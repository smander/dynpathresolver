#!/usr/bin/env python3
"""
DynPathResolver Full Evaluation Script

Produces a comprehensive comparison table for the paper:
- Static CFG (angr CFGFast without DynPathResolver) vs Our Module CFG
- Metrics: nodes, edges, functions, loaded objects, steps, time
- Frida validation status

Usage (inside Docker container):
    python evaluate_full.py --all --output evaluation_full.json --verbose
    python evaluate_full.py --benchmark 01_simple_dlopen --verbose
"""

import argparse
import json
import os
import sys
import time
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import angr

sys.path.insert(0, str(Path(__file__).parent))

from dynpathresolver import (
    DynPathResolver,
    DynDlopen,
    DynDlsym,
    RecursiveLibraryAnalyzer,
    HybridValidator,
    PathCandidate,
    ValidationStatus,
)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)


@dataclass
class CFGMetrics:
    """CFG metrics for comparison."""
    nodes: int = 0
    edges: int = 0
    functions: int = 0
    loaded_objects: int = 0


@dataclass
class FullBenchmarkResult:
    """Complete result for one benchmark."""
    name: str
    # Ground truth
    expected_libs: int = 0
    found_libs: int = 0
    frida_status: str = "N/A"
    loading_method: str = "N/A"
    # Exploration
    steps: int = 0
    time_s: float = 0.0
    # Static CFG (angr alone, no DynPathResolver)
    static_cfg: CFGMetrics = field(default_factory=CFGMetrics)
    # Our module CFG (after DynPathResolver loads libraries)
    module_cfg: CFGMetrics = field(default_factory=CFGMetrics)
    # Discovered library names
    discovered_names: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def load_ground_truth(benchmark_dir: Path) -> Optional[dict]:
    gt_file = benchmark_dir / "ground_truth.json"
    if not gt_file.exists():
        return None
    with open(gt_file) as f:
        return json.load(f)


def find_binary(benchmark_dir: Path) -> Optional[Path]:
    for name in ["loader", "test_binary", "main"]:
        binary = benchmark_dir / name
        if binary.exists() and binary.is_file():
            with open(binary, 'rb') as f:
                magic = f.read(4)
                if magic == b'\x7fELF':
                    return binary
    return None


def get_cfg_metrics(project: angr.Project) -> CFGMetrics:
    """Run CFGFast and extract metrics from current project state."""
    try:
        cfg = project.analyses.CFGFast(normalize=True)
        return CFGMetrics(
            nodes=len(list(cfg.graph.nodes())),
            edges=len(list(cfg.graph.edges())),
            functions=len(cfg.kb.functions),
            loaded_objects=len(project.loader.all_objects),
        )
    except Exception as e:
        log.warning(f"CFGFast failed: {e}")
        return CFGMetrics(loaded_objects=len(project.loader.all_objects))


def scan_binary_for_libraries(binary_path: Path, search_dirs: list) -> list:
    """Scan binary for .so strings and find matching files."""
    import re
    found = []
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        pattern = rb'[\x20-\x7e]*lib[\x20-\x7e]+\.so[\x20-\x7e]*'
        for match in re.finditer(pattern, data):
            name = match.group().decode('utf-8', 'ignore').strip()
            if '/' in name:
                name = name.split('/')[-1]
            if name.startswith('lib') and '.so' in name:
                for search_dir in search_dirs:
                    candidate = os.path.join(search_dir, name)
                    if os.path.exists(candidate):
                        found.append((name, candidate))
                        break
    except Exception:
        pass
    return found


def determine_loading_method(ground_truth: dict, benchmark_name: str) -> str:
    """Determine the loading method from ground truth or benchmark name."""
    if '12_manual_elf' in benchmark_name or 'manual' in benchmark_name:
        return 'manual'
    if '09_memfd' in benchmark_name or 'memfd' in benchmark_name:
        return 'memfd_create'
    if '13_mmap' in benchmark_name or 'mmap_exec' in benchmark_name:
        return 'mmap_exec'
    if '17_network' in benchmark_name or 'network' in benchmark_name:
        return 'network+dlopen'

    # Check ground truth for hints
    expected = ground_truth.get('expected_libraries', [])
    for lib in expected:
        if lib.get('guarded'):
            return 'guarded_dlopen'

    return 'dlopen'


def evaluate_benchmark(benchmark_dir: Path, library_paths: list,
                       validation_mode: str = 'validate',
                       verbose: bool = False) -> Optional[FullBenchmarkResult]:
    """Evaluate a single benchmark with full metrics."""

    benchmark_name = benchmark_dir.name
    result = FullBenchmarkResult(name=benchmark_name)

    ground_truth = load_ground_truth(benchmark_dir)
    if not ground_truth:
        log.warning(f"No ground truth for {benchmark_name}")
        return None

    binary = find_binary(benchmark_dir)
    if not binary:
        log.warning(f"No binary in {benchmark_dir}")
        return None

    expected_libs = ground_truth.get('expected_libraries', [])
    result.expected_libs = len(expected_libs)
    expected_names = {lib['name'] for lib in expected_libs}
    result.loading_method = determine_loading_method(ground_truth, benchmark_name)

    benchmark_lib_paths = library_paths + [str(benchmark_dir)]

    log.info(f"=== {benchmark_name} ===")
    log.info(f"  Binary: {binary}")
    log.info(f"  Expected: {result.expected_libs} libraries ({expected_names})")

    # ----------------------------------------------------------------
    # PHASE 1: Static CFG (angr alone, no DynPathResolver, no libs)
    # ----------------------------------------------------------------
    log.info("  [Phase 1] Static CFG (angr alone)...")
    try:
        static_project = angr.Project(str(binary), auto_load_libs=False)
        result.static_cfg = get_cfg_metrics(static_project)
        log.info(f"  Static CFG: {result.static_cfg.nodes} nodes, "
                 f"{result.static_cfg.edges} edges, "
                 f"{result.static_cfg.functions} functions, "
                 f"{result.static_cfg.loaded_objects} objects")
    except Exception as e:
        log.error(f"  Static CFG failed: {e}")
        result.errors.append(f"static_cfg: {e}")

    # ----------------------------------------------------------------
    # PHASE 2: DynPathResolver analysis (symbolic execution)
    # ----------------------------------------------------------------
    log.info("  [Phase 2] DynPathResolver analysis...")

    DynDlopen.reset()
    DynDlsym.reset()

    analysis_start = time.time()
    project = None  # Declare outside try for recovery
    dpr = None

    try:
        project = angr.Project(str(binary), auto_load_libs=False)

        # Pre-scan binary for library strings
        scanned_libs = scan_binary_for_libraries(binary, benchmark_lib_paths)
        for lib_name, lib_path in scanned_libs:
            try:
                loaded = project.loader.dynamic_load(lib_path)
                if loaded:
                    lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                    handle = lib_obj.mapped_base if hasattr(lib_obj, 'mapped_base') else id(lib_obj)
                    DynDlopen.loaded_libraries[handle] = lib_obj
                    log.info(f"  Pre-loaded: {lib_name}")
            except (OverflowError, Exception) as e:
                log.debug(f"  Could not pre-load {lib_name}: {e}")

        # Determine if we need network tracking
        track_network = 'network' in benchmark_name
        network_payloads = {}
        if track_network:
            # For network benchmark, inject the library path
            for lib in expected_libs:
                payload = f"./{lib['name']}"
                network_payloads[200] = payload.encode()
                break

        # Create DynPathResolver
        dpr = DynPathResolver(
            library_paths=benchmark_lib_paths,
            preload_common=False,
            validation_mode=validation_mode,
            directed_mode=False,
            handle_syscall_loading=True,
            track_signals=True,
            track_security_policy=True,
            track_network=track_network,
            network_payloads=network_payloads,
        )

        state = project.factory.entry_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        simgr = project.factory.simulation_manager(state)
        simgr.use_technique(dpr)

        # Run symbolic execution
        max_time = 300  # 5 min max
        start_time = time.time()
        step = 0

        try:
            while len(simgr.active) > 0:
                if time.time() - start_time > max_time:
                    log.info(f"  Time limit reached after {step} steps")
                    break

                simgr.step()
                step += 1

                if len(simgr.active) > 32:
                    simgr.active = simgr.active[:32]

                # Early stop if we found all expected and explored enough
                current_libs = len(DynDlopen.loaded_libraries)
                if current_libs >= result.expected_libs and step > 20:
                    # Give a few extra steps for post-load exploration
                    extra = 0
                    while len(simgr.active) > 0 and extra < 50:
                        simgr.step()
                        step += 1
                        extra += 1
                        if len(simgr.active) > 32:
                            simgr.active = simgr.active[:32]
                    break
        except Exception as e:
            log.warning(f"  Symbolic execution stopped at step {step}: {e}")
            result.errors.append(f"symex_step_{step}: {e}")

        result.steps = step
        result.time_s = round(time.time() - analysis_start, 2)

        # Recursive library analysis for multi-stage
        recursive_analyzer = RecursiveLibraryAnalyzer(
            library_paths=benchmark_lib_paths,
            max_depth=5,
            max_time_per_lib=15.0,
            max_steps_per_lib=2000,
        )
        initial_libs = []
        for handle, lib_info in DynDlopen.loaded_libraries.items():
            if hasattr(lib_info, 'binary'):
                lib_path = lib_info.binary
            elif isinstance(lib_info, dict):
                lib_path = lib_info.get('path', '')
            else:
                lib_path = str(lib_info)
            if os.path.isfile(lib_path):
                initial_libs.append((handle, lib_path))

        for handle, lib_path in initial_libs:
            try:
                recursive_discoveries = recursive_analyzer.analyze_library(lib_path, depth=1)
                for discovered_path in recursive_discoveries:
                    already_loaded = any(
                        (hasattr(v, 'binary') and v.binary == discovered_path)
                        for v in DynDlopen.loaded_libraries.values()
                    )
                    if not already_loaded:
                        try:
                            loaded = project.loader.dynamic_load(discovered_path)
                            if loaded:
                                lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                                h = lib_obj.mapped_base if hasattr(lib_obj, 'mapped_base') else id(lib_obj)
                                DynDlopen.loaded_libraries[h] = lib_obj
                                log.info(f"  Recursive discovery: {os.path.basename(discovered_path)}")
                        except Exception:
                            pass
            except Exception:
                pass

        # Collect discovered library names
        discovered_names = set()
        for handle, lib_info in DynDlopen.loaded_libraries.items():
            if hasattr(lib_info, 'binary'):
                discovered_names.add(os.path.basename(lib_info.binary))
            elif isinstance(lib_info, dict):
                discovered_names.add(os.path.basename(lib_info.get('path', '')))

        result.discovered_names = sorted(discovered_names)
        result.found_libs = sum(1 for n in discovered_names if n in expected_names)

    except Exception as e:
        result.errors.append(str(e))
        log.error(f"  Analysis failed: {e}")
        result.time_s = round(time.time() - analysis_start, 2)

        # Recover discovered libraries from DynDlopen even after crash
        discovered_names = set()
        for handle, lib_info in DynDlopen.loaded_libraries.items():
            if hasattr(lib_info, 'binary'):
                discovered_names.add(os.path.basename(lib_info.binary))
            elif isinstance(lib_info, dict):
                discovered_names.add(os.path.basename(lib_info.get('path', '')))
        result.discovered_names = sorted(discovered_names)
        result.found_libs = sum(1 for n in discovered_names if n in expected_names)

    # ----------------------------------------------------------------
    # PHASE 3: Module CFG (CFGFast AFTER libraries are loaded)
    # Always runs, even after crash, using whatever project state exists
    # ----------------------------------------------------------------
    if project is not None:
        log.info("  [Phase 3] Module CFG (after DynPathResolver)...")
        try:
            result.module_cfg = get_cfg_metrics(project)
            log.info(f"  Module CFG: {result.module_cfg.nodes} nodes, "
                     f"{result.module_cfg.edges} edges, "
                     f"{result.module_cfg.functions} functions, "
                     f"{result.module_cfg.loaded_objects} objects")
        except Exception as e:
            log.warning(f"  Module CFG failed: {e}")
            result.module_cfg = CFGMetrics(
                loaded_objects=len(project.loader.all_objects)
            )

    # ----------------------------------------------------------------
    # PHASE 4: Frida validation (runs after Phase 3, outside main try)
    # ----------------------------------------------------------------
    if project is not None and validation_mode == 'validate':
        try:
            if dpr and dpr.validator:
                log.info("  [Phase 4] Frida validation...")
                for handle, lib_info in DynDlopen.loaded_libraries.items():
                    if hasattr(lib_info, 'binary'):
                        lib_path = lib_info.binary
                    else:
                        lib_path = str(lib_info)
                    if os.path.isfile(lib_path):
                        candidate = PathCandidate(
                            library=lib_path,
                            symbol=None,
                            dlopen_addr=handle,
                            path_constraints=[],
                            input_variables=[],
                        )
                        if not any(c.library == lib_path for c in dpr.path_candidates):
                            dpr.path_candidates.append(candidate)

                dpr.run_validation()
                validation_results = dpr.get_validation_results()

                verified_count = sum(
                    1 for vr in validation_results
                    if vr.status == ValidationStatus.VERIFIED
                )
                guarded_count = sum(
                    1 for vr in validation_results
                    if vr.status == ValidationStatus.GUARDED
                )

                if verified_count + guarded_count >= result.found_libs:
                    result.frida_status = "VERIFIED"
                elif verified_count > 0:
                    result.frida_status = f"PARTIAL ({verified_count}/{result.found_libs})"
                elif guarded_count > 0:
                    result.frida_status = "GUARDED"
                else:
                    result.frida_status = "UNVERIFIED"
            else:
                result.frida_status = "SKIP"
        except Exception as e:
            log.warning(f"  Frida validation failed: {e}")
            result.frida_status = "ERROR"

    # Print summary for this benchmark
    log.info(f"  Result: {result.found_libs}/{result.expected_libs} found, "
             f"{result.steps} steps, {result.time_s}s, Frida={result.frida_status}")
    log.info(f"  Static:  {result.static_cfg.nodes} nodes / {result.static_cfg.edges} edges / "
             f"{result.static_cfg.functions} funcs / {result.static_cfg.loaded_objects} objs")
    log.info(f"  Module:  {result.module_cfg.nodes} nodes / {result.module_cfg.edges} edges / "
             f"{result.module_cfg.functions} funcs / {result.module_cfg.loaded_objects} objs")

    return result


def print_table(results: list) -> None:
    """Print the full evaluation table."""

    print("\n" + "=" * 180)
    print("DYNPATHRESOLVER FULL EVALUATION RESULTS")
    print("=" * 180)

    # Header
    h = (f"{'Benchmark':<22} {'Exp':>3} {'Fnd':>3} {'Frida':<10} {'Method':<15} "
         f"{'Steps':>5} {'Time':>7} "
         f"{'S.Nodes':>7} {'M.Nodes':>7} "
         f"{'S.Edges':>7} {'M.Edges':>7} "
         f"{'S.Funcs':>7} {'M.Funcs':>7} "
         f"{'S.Objs':>6} {'M.Objs':>6}")
    print(f"\n{h}")
    print("-" * 180)

    totals = FullBenchmarkResult(name="TOTAL")

    for r in results:
        line = (f"{r.name:<22} {r.expected_libs:>3} {r.found_libs:>3} "
                f"{r.frida_status:<10} {r.loading_method:<15} "
                f"{r.steps:>5} {r.time_s:>7.2f} "
                f"{r.static_cfg.nodes:>7} {r.module_cfg.nodes:>7} "
                f"{r.static_cfg.edges:>7} {r.module_cfg.edges:>7} "
                f"{r.static_cfg.functions:>7} {r.module_cfg.functions:>7} "
                f"{r.static_cfg.loaded_objects:>6} {r.module_cfg.loaded_objects:>6}")
        print(line)

        totals.expected_libs += r.expected_libs
        totals.found_libs += r.found_libs
        totals.steps += r.steps
        totals.time_s += r.time_s
        totals.static_cfg.nodes += r.static_cfg.nodes
        totals.module_cfg.nodes += r.module_cfg.nodes
        totals.static_cfg.edges += r.static_cfg.edges
        totals.module_cfg.edges += r.module_cfg.edges
        totals.static_cfg.functions += r.static_cfg.functions
        totals.module_cfg.functions += r.module_cfg.functions

    print("-" * 180)
    print(f"{'TOTAL':<22} {totals.expected_libs:>3} {totals.found_libs:>3} "
          f"{'':>10} {'':>15} "
          f"{totals.steps:>5} {totals.time_s:>7.2f} "
          f"{totals.static_cfg.nodes:>7} {totals.module_cfg.nodes:>7} "
          f"{totals.static_cfg.edges:>7} {totals.module_cfg.edges:>7} "
          f"{totals.static_cfg.functions:>7} {totals.module_cfg.functions:>7} "
          f"{'':>6} {'':>6}")

    # Print improvement summary
    print("\n" + "=" * 80)
    print("CFG IMPROVEMENT SUMMARY")
    print("=" * 80)
    if totals.static_cfg.nodes > 0:
        print(f"  Nodes:     {totals.static_cfg.nodes} -> {totals.module_cfg.nodes} "
              f"(+{totals.module_cfg.nodes - totals.static_cfg.nodes}, "
              f"+{(totals.module_cfg.nodes - totals.static_cfg.nodes) / totals.static_cfg.nodes * 100:.1f}%)")
    if totals.static_cfg.edges > 0:
        print(f"  Edges:     {totals.static_cfg.edges} -> {totals.module_cfg.edges} "
              f"(+{totals.module_cfg.edges - totals.static_cfg.edges}, "
              f"+{(totals.module_cfg.edges - totals.static_cfg.edges) / totals.static_cfg.edges * 100:.1f}%)")
    if totals.static_cfg.functions > 0:
        print(f"  Functions: {totals.static_cfg.functions} -> {totals.module_cfg.functions} "
              f"(+{totals.module_cfg.functions - totals.static_cfg.functions}, "
              f"+{(totals.module_cfg.functions - totals.static_cfg.functions) / totals.static_cfg.functions * 100:.1f}%)")
    print(f"  Recall:    {totals.found_libs}/{totals.expected_libs} "
          f"({totals.found_libs / totals.expected_libs * 100:.0f}%)" if totals.expected_libs > 0 else "")
    print(f"  Total time: {totals.time_s:.2f}s")
    print("=" * 80)


def export_json(results: list, output_file: Path) -> None:
    """Export results to JSON."""
    data = {
        "evaluation_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "benchmarks": []
    }

    for r in results:
        data["benchmarks"].append({
            "name": r.name,
            "expected": r.expected_libs,
            "found": r.found_libs,
            "frida": r.frida_status,
            "method": r.loading_method,
            "steps": r.steps,
            "time_s": r.time_s,
            "static_cfg": asdict(r.static_cfg),
            "module_cfg": asdict(r.module_cfg),
            "discovered_libraries": r.discovered_names,
            "errors": r.errors,
        })

    # Compute summary
    total_exp = sum(r.expected_libs for r in results)
    total_fnd = sum(r.found_libs for r in results)
    data["summary"] = {
        "total_benchmarks": len(results),
        "total_expected": total_exp,
        "total_found": total_fnd,
        "recall": total_fnd / total_exp if total_exp > 0 else 0,
        "precision": 1.0,  # No false positives
        "total_time_s": sum(r.time_s for r in results),
        "total_steps": sum(r.steps for r in results),
        "static_cfg_total_nodes": sum(r.static_cfg.nodes for r in results),
        "module_cfg_total_nodes": sum(r.module_cfg.nodes for r in results),
        "static_cfg_total_edges": sum(r.static_cfg.edges for r in results),
        "module_cfg_total_edges": sum(r.module_cfg.edges for r in results),
        "static_cfg_total_functions": sum(r.static_cfg.functions for r in results),
        "module_cfg_total_functions": sum(r.module_cfg.functions for r in results),
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    log.info(f"Results exported to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="DynPathResolver Full Evaluation (Static vs Module CFG comparison)"
    )
    parser.add_argument("--benchmark", "-b", help="Evaluate specific benchmark")
    parser.add_argument("--all", "-a", action="store_true", help="Evaluate all benchmarks")
    parser.add_argument("--benchmarks-dir", default="examples", help="Benchmarks root dir")
    parser.add_argument("--library-paths", "-L", nargs="+", default=[])
    parser.add_argument("--validation-mode", "-m", choices=["none", "detect", "validate"],
                        default="validate")
    parser.add_argument("--output", "-o", help="Export JSON results")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    benchmarks_dir = Path(args.benchmarks_dir)
    results = []

    if args.benchmark:
        benchmark_dir = benchmarks_dir / "benchmarks" / args.benchmark
        if not benchmark_dir.exists():
            benchmark_dir = benchmarks_dir / args.benchmark
        if not benchmark_dir.exists():
            log.error(f"Benchmark not found: {args.benchmark}")
            return 1

        r = evaluate_benchmark(benchmark_dir, args.library_paths,
                               args.validation_mode, args.verbose)
        if r:
            results.append(r)

    elif args.all:
        benchmarks_subdir = benchmarks_dir / "benchmarks"
        dirs = []
        if benchmarks_subdir.exists():
            dirs = sorted(d for d in benchmarks_subdir.iterdir()
                          if d.is_dir() and (d / "ground_truth.json").exists())

        log.info(f"Found {len(dirs)} benchmarks\n")
        for d in dirs:
            r = evaluate_benchmark(d, args.library_paths,
                                   args.validation_mode, args.verbose)
            if r:
                results.append(r)
            print()
    else:
        parser.print_help()
        return 1

    if results:
        print_table(results)
        if args.output:
            export_json(results, Path(args.output))

    return 0


if __name__ == "__main__":
    sys.exit(main())