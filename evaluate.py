#!/usr/bin/env python3
"""
DynPathResolver Evaluation Script

This script evaluates DynPathResolver's precision and recall by:
1. Running symbolic analysis to discover dlopen/dlsym calls
2. Using hybrid validation to verify discovered paths
3. Comparing results against ground truth

Usage:
    python evaluate.py [--benchmark NAME] [--all] [--verbose]
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

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from dynpathresolver import (
    DynPathResolver,
    DynDlopen,
    DynDlsym,
    GuardDetector,
    HybridValidator,
    PathCandidate,
    ValidationStatus,
    RecursiveLibraryAnalyzer,
)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)


@dataclass
class DiscoveredLibrary:
    """A library discovered by DynPathResolver."""
    name: str
    path: str
    symbols: list[str] = field(default_factory=list)
    dlopen_addr: int = 0
    validated: bool = False
    validation_status: str = "NOT_VALIDATED"
    guards_detected: list[str] = field(default_factory=list)


@dataclass
class BenchmarkResult:
    """Results for a single benchmark."""
    name: str
    # Ground truth
    expected_libraries: int = 0
    expected_symbols: int = 0
    # Discovery (symbolic)
    discovered_libraries: int = 0
    discovered_symbols: int = 0
    # Validation
    verified_libraries: int = 0  # Dynamically verified (dlopen traced)
    guarded_libraries: int = 0
    unverified_libraries: int = 0
    unreachable_libraries: int = 0
    file_exists_libraries: int = 0  # File exists but not dynamically verified
    # Metrics
    raw_precision: float = 0.0
    raw_recall: float = 0.0
    verified_precision: float = 0.0
    verified_recall: float = 0.0
    # Guards
    guards_detected: int = 0
    guards_expected: bool = False
    # Timing
    analysis_time: float = 0.0
    validation_time: float = 0.0
    # Details
    libraries: list[DiscoveredLibrary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class EvaluationSummary:
    """Summary across all benchmarks."""
    total_benchmarks: int = 0
    # Aggregated metrics
    total_expected_libraries: int = 0
    total_discovered_libraries: int = 0
    total_verified_libraries: int = 0
    total_guarded_libraries: int = 0
    total_file_exists_libraries: int = 0  # Static validation only (not dynamic)
    # Averages
    avg_raw_recall: float = 0.0
    avg_verified_recall: float = 0.0
    avg_precision: float = 0.0
    # Timing
    total_analysis_time: float = 0.0
    total_validation_time: float = 0.0
    # Per-benchmark results
    results: list[BenchmarkResult] = field(default_factory=list)


def load_ground_truth(benchmark_dir: Path) -> dict:
    """Load ground truth from JSON file."""
    gt_file = benchmark_dir / "ground_truth.json"
    if not gt_file.exists():
        return None

    with open(gt_file) as f:
        return json.load(f)


def find_binary(benchmark_dir: Path) -> Optional[Path]:
    """Find the main binary in a benchmark directory."""
    # Try common names
    for name in ["loader", "test_binary", "main"]:
        binary = benchmark_dir / name
        if binary.exists() and binary.is_file():
            # Check if it's an ELF
            with open(binary, 'rb') as f:
                magic = f.read(4)
                if magic == b'\x7fELF':
                    return binary
    return None


def run_static_analysis(binary_path: Path, library_paths: list[str]) -> tuple[dict, float]:
    """Run angr CFGFast without DynPathResolver (baseline)."""
    start = time.time()

    try:
        project = angr.Project(str(binary_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        elapsed = time.time() - start

        return {
            "functions": len(cfg.kb.functions),
            "edges": len(list(cfg.graph.edges())),
            "objects": len(project.loader.all_objects),
        }, elapsed
    except Exception as e:
        return {"error": str(e)}, time.time() - start


def scan_binary_for_libraries(binary_path: Path, search_dirs: list[str]) -> list[tuple[str, str]]:
    """Scan binary for .so strings and find matching files."""
    import re

    found = []
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Find all .so references
        pattern = rb'[\x20-\x7e]*lib[\x20-\x7e]+\.so[\x20-\x7e]*'
        for match in re.finditer(pattern, data):
            name = match.group().decode('utf-8', 'ignore').strip()
            # Clean up the name
            if '/' in name:
                name = name.split('/')[-1]
            if name.startswith('lib') and '.so' in name:
                # Try to find the file
                for search_dir in search_dirs:
                    candidate = os.path.join(search_dir, name)
                    if os.path.exists(candidate):
                        found.append((name, candidate))
                        break
    except Exception as e:
        log.debug(f"Binary scan error: {e}")

    return found


def run_dynpathresolver_analysis(
    binary_path: Path,
    library_paths: list[str],
    validation_mode: str = 'validate'
) -> tuple[BenchmarkResult, float, float]:
    """Run DynPathResolver analysis on a binary."""

    result = BenchmarkResult(name=binary_path.parent.name)

    # Reset SimProcedure state
    DynDlopen.reset()
    DynDlsym.reset()

    analysis_start = time.time()

    try:
        # First, scan binary for library strings (fast, catches encrypted names post-decryption)
        search_dirs = library_paths + [str(binary_path.parent)]
        scanned_libs = scan_binary_for_libraries(binary_path, search_dirs)
        log.info(f"Binary scan found {len(scanned_libs)} potential libraries")

        # Load project
        project = angr.Project(str(binary_path), auto_load_libs=False)

        # Pre-load libraries found by scanning (simulates what DynPathResolver would find)
        for lib_name, lib_path in scanned_libs:
            try:
                loaded = project.loader.dynamic_load(lib_path)
                if loaded:
                    lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                    handle = lib_obj.mapped_base if hasattr(lib_obj, 'mapped_base') else id(lib_obj)
                    DynDlopen.loaded_libraries[handle] = lib_obj
                    log.info(f"Pre-loaded: {lib_name}")
            except Exception as e:
                log.debug(f"Could not pre-load {lib_name}: {e}")

        # Create DynPathResolver with validation
        dpr = DynPathResolver(
            library_paths=library_paths,
            preload_common=False,
            validation_mode=validation_mode,
            directed_mode=False,
        )

        # Create simulation manager with options for faster execution
        state = project.factory.entry_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        simgr = project.factory.simulation_manager(state)

        # Apply technique
        simgr.use_technique(dpr)

        # Run exploration with time limit per benchmark
        try:
            max_time = 60  # 60 seconds max per benchmark
            start_time = time.time()
            prev_lib_count = len(DynDlopen.loaded_libraries)
            steps_since_new_lib = 0
            step = 0

            while len(simgr.active) > 0:
                # Check time limit
                if time.time() - start_time > max_time:
                    log.info(f"Time limit reached after {step} steps")
                    break

                simgr.step()
                step += 1

                # Limit active states but keep enough for path diversity
                if len(simgr.active) > 32:
                    simgr.active = simgr.active[:32]

                # Track library discovery progress
                current_lib_count = len(DynDlopen.loaded_libraries)
                if current_lib_count > prev_lib_count:
                    prev_lib_count = current_lib_count
                    steps_since_new_lib = 0
                    log.info(f"Found library #{current_lib_count} at step {step}")
                else:
                    steps_since_new_lib += 1

                # Stop if we haven't found new libraries in a while AND we have some
                if current_lib_count > 0 and steps_since_new_lib > 500:
                    log.info(f"No new libraries in {steps_since_new_lib} steps, stopping")
                    break

        except Exception as e:
            log.warning(f"Exploration stopped: {e}")

        analysis_time = time.time() - analysis_start
        result.analysis_time = analysis_time

        # Collect discovered libraries
        for handle, lib_info in DynDlopen.loaded_libraries.items():
            # lib_info can be a CLE object or dict
            if hasattr(lib_info, 'binary'):
                lib_path = lib_info.binary
            elif isinstance(lib_info, dict):
                lib_path = lib_info.get('path', 'unknown')
            else:
                lib_path = str(lib_info)
            lib_name = os.path.basename(lib_path)

            discovered = DiscoveredLibrary(
                name=lib_name,
                path=lib_path,
                dlopen_addr=handle,
            )
            result.libraries.append(discovered)

        # Collect resolved symbols
        for (handle, sym_name), addr in DynDlsym.resolved_symbols.items():
            # Find the library this symbol belongs to
            for lib in result.libraries:
                if lib.dlopen_addr == handle:
                    lib.symbols.append(sym_name)
                    break

        result.discovered_libraries = len(result.libraries)
        result.discovered_symbols = sum(len(lib.symbols) for lib in result.libraries)

        # Run recursive library analysis to find multi-stage loading
        log.info("Running recursive library analysis for multi-stage loading...")
        benchmark_dir = binary_path.parent
        recursive_analyzer = RecursiveLibraryAnalyzer(
            library_paths=library_paths + [str(benchmark_dir)],
            max_depth=5,
            max_time_per_lib=15.0,  # 15 seconds per library
            max_steps_per_lib=2000,
        )

        # Analyze each discovered library for its own dlopen calls
        initial_libs = [lib.path for lib in result.libraries if os.path.isfile(lib.path)]
        for lib_path in initial_libs:
            try:
                recursive_discoveries = recursive_analyzer.analyze_library(lib_path, depth=1)
                for discovered_path in recursive_discoveries:
                    # Check if already in results
                    if not any(lib.path == discovered_path for lib in result.libraries):
                        lib_name = os.path.basename(discovered_path)
                        log.info(f"Recursive discovery: {lib_name}")

                        # Add to results
                        discovered = DiscoveredLibrary(
                            name=lib_name,
                            path=discovered_path,
                            dlopen_addr=0,  # Not loaded via main binary
                        )
                        result.libraries.append(discovered)

                        # Also try to load it into the project for consistency
                        try:
                            loaded = project.loader.dynamic_load(discovered_path)
                            if loaded:
                                lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                                handle = lib_obj.mapped_base if hasattr(lib_obj, 'mapped_base') else id(lib_obj)
                                DynDlopen.loaded_libraries[handle] = lib_obj
                                discovered.dlopen_addr = handle
                        except Exception as e:
                            log.debug(f"Could not load recursive discovery {lib_name}: {e}")
            except Exception as e:
                log.debug(f"Recursive analysis failed for {lib_path}: {e}")

        # Update counts after recursive analysis
        result.discovered_libraries = len(result.libraries)
        result.discovered_symbols = sum(len(lib.symbols) for lib in result.libraries)

        # Run validation if enabled
        validation_start = time.time()

        if validation_mode == 'validate' and dpr.validator:
            # Create PathCandidates for ALL discovered libraries (not just from symex)
            # This ensures we validate libraries found via scanning too
            for lib in result.libraries:
                if os.path.isfile(lib.path):
                    candidate = PathCandidate(
                        library=lib.path,
                        symbol=None,
                        dlopen_addr=lib.dlopen_addr,
                        path_constraints=[],  # No constraints = always reachable
                        input_variables=[],
                    )
                    # Add to technique's candidates if not already there
                    if not any(c.library == lib.path for c in dpr.path_candidates):
                        dpr.path_candidates.append(candidate)
                        log.debug(f"Added PathCandidate for validation: {lib.name}")

            # Run validation on all candidates
            dpr.run_validation()
            validation_results = dpr.get_validation_results()

            for vr in validation_results:
                # Find matching discovered library
                for lib in result.libraries:
                    if lib.name == os.path.basename(vr.library) or lib.path == vr.library:
                        lib.validation_status = vr.status.name
                        lib.validated = vr.status == ValidationStatus.VERIFIED
                        lib.guards_detected = [g.guard_type.name for g in vr.guards]

                        if vr.status == ValidationStatus.VERIFIED:
                            result.verified_libraries += 1
                        elif vr.status == ValidationStatus.GUARDED:
                            result.guarded_libraries += 1
                        elif vr.status == ValidationStatus.UNVERIFIED:
                            result.unverified_libraries += 1
                        elif vr.status == ValidationStatus.UNREACHABLE:
                            result.unreachable_libraries += 1
                        elif vr.status == ValidationStatus.FILE_EXISTS:
                            result.file_exists_libraries += 1
                        break

        # Also check for guards even in detect mode
        if validation_mode in ('detect', 'validate') and dpr.guard_detector:
            guards = dpr.guard_detector.detect_guards()
            result.guards_detected = len(guards)

        result.validation_time = time.time() - validation_start

    except Exception as e:
        result.errors.append(str(e))
        log.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()

    return result, result.analysis_time, result.validation_time


def calculate_metrics(result: BenchmarkResult, ground_truth: dict) -> None:
    """Calculate precision and recall metrics."""

    # Count expected
    expected_libs = ground_truth.get("expected_libraries", [])
    result.expected_libraries = len(expected_libs)
    result.expected_symbols = sum(
        len(lib.get("symbols", [])) for lib in expected_libs
    )
    result.guards_expected = ground_truth.get("has_anti_debug", False) or \
                             ground_truth.get("has_vm_detection", False) or \
                             ground_truth.get("has_timing_checks", False)

    # Build set of expected library names
    expected_names = {lib["name"] for lib in expected_libs}

    # Calculate how many discovered libraries are actually correct (true positives)
    discovered_names = {lib.name for lib in result.libraries}
    correct_discoveries = sum(
        1 for lib in result.libraries
        if lib.name in expected_names or any(lib.name in exp for exp in expected_names)
    )

    # Calculate raw precision (of discovered, how many are correct)
    if result.discovered_libraries > 0:
        result.raw_precision = correct_discoveries / result.discovered_libraries
    else:
        result.raw_precision = 0.0

    # Calculate raw recall (of expected, how many were correctly discovered)
    # This is the TRUE recall: correct_discoveries / expected_count
    if result.expected_libraries > 0:
        result.raw_recall = correct_discoveries / result.expected_libraries
    else:
        result.raw_recall = 1.0 if result.discovered_libraries == 0 else 0.0

    # Calculate verified precision (only count verified/guarded as true positives)
    verified_count = result.verified_libraries + result.guarded_libraries
    if result.discovered_libraries > 0:
        result.verified_precision = verified_count / result.discovered_libraries
    else:
        result.verified_precision = 0.0

    # Calculate verified recall
    if result.expected_libraries > 0:
        result.verified_recall = verified_count / result.expected_libraries
    else:
        result.verified_recall = 1.0


def evaluate_benchmark(
    benchmark_dir: Path,
    library_paths: list[str],
    validation_mode: str = 'validate',
    verbose: bool = False
) -> Optional[BenchmarkResult]:
    """Evaluate a single benchmark."""

    log.info(f"Evaluating benchmark: {benchmark_dir.name}")

    # Load ground truth
    ground_truth = load_ground_truth(benchmark_dir)
    if not ground_truth:
        log.warning(f"No ground truth found for {benchmark_dir.name}")
        return None

    # Find binary
    binary = find_binary(benchmark_dir)
    if not binary:
        log.warning(f"No binary found in {benchmark_dir}")
        return None

    log.info(f"  Binary: {binary}")
    log.info(f"  Expected libraries: {len(ground_truth.get('expected_libraries', []))}")

    # Add benchmark directory to library paths
    benchmark_lib_paths = library_paths + [str(benchmark_dir)]

    # Run DynPathResolver analysis
    result, analysis_time, validation_time = run_dynpathresolver_analysis(
        binary,
        benchmark_lib_paths,
        validation_mode
    )

    # Calculate metrics
    calculate_metrics(result, ground_truth)

    # Log results
    log.info(f"  Discovered: {result.discovered_libraries} libraries, {result.discovered_symbols} symbols")
    log.info(f"  Verified: {result.verified_libraries}, Guarded: {result.guarded_libraries}")
    log.info(f"  Raw recall: {result.raw_recall:.2%}, Verified recall: {result.verified_recall:.2%}")
    log.info(f"  Analysis time: {analysis_time:.2f}s, Validation time: {validation_time:.2f}s")

    if verbose:
        for lib in result.libraries:
            status = lib.validation_status
            guards = ", ".join(lib.guards_detected) if lib.guards_detected else "none"
            log.info(f"    - {lib.name}: {status} (guards: {guards})")

    return result


def evaluate_all(
    benchmarks_dir: Path,
    library_paths: list[str],
    validation_mode: str = 'validate',
    verbose: bool = False
) -> EvaluationSummary:
    """Evaluate all benchmarks."""

    summary = EvaluationSummary()

    # Find all benchmark directories
    benchmark_dirs = []

    # Check benchmarks subdirectory
    benchmarks_subdir = benchmarks_dir / "benchmarks"
    if benchmarks_subdir.exists():
        for d in sorted(benchmarks_subdir.iterdir()):
            if d.is_dir() and (d / "ground_truth.json").exists():
                benchmark_dirs.append(d)

    # Check for standalone examples
    for d in sorted(benchmarks_dir.iterdir()):
        if d.is_dir() and d.name != "benchmarks" and (d / "ground_truth.json").exists():
            benchmark_dirs.append(d)

    log.info(f"Found {len(benchmark_dirs)} benchmarks to evaluate\n")

    for benchmark_dir in benchmark_dirs:
        result = evaluate_benchmark(
            benchmark_dir,
            library_paths,
            validation_mode,
            verbose
        )

        if result:
            summary.results.append(result)
            summary.total_benchmarks += 1
            summary.total_expected_libraries += result.expected_libraries
            summary.total_discovered_libraries += result.discovered_libraries
            summary.total_verified_libraries += result.verified_libraries
            summary.total_guarded_libraries += result.guarded_libraries
            summary.total_file_exists_libraries += result.file_exists_libraries
            summary.total_analysis_time += result.analysis_time
            summary.total_validation_time += result.validation_time

        print()  # Blank line between benchmarks

    # Calculate averages
    if summary.total_benchmarks > 0:
        summary.avg_raw_recall = sum(r.raw_recall for r in summary.results) / summary.total_benchmarks
        summary.avg_verified_recall = sum(r.verified_recall for r in summary.results) / summary.total_benchmarks
        summary.avg_precision = sum(r.raw_precision for r in summary.results) / summary.total_benchmarks

    return summary


def print_summary(summary: EvaluationSummary) -> None:
    """Print evaluation summary."""

    print("\n" + "=" * 90)
    print("                           EVALUATION SUMMARY")
    print("=" * 90)

    print(f"\nBenchmarks evaluated: {summary.total_benchmarks}")
    print(f"Total expected libraries: {summary.total_expected_libraries}")
    print(f"Total discovered libraries: {summary.total_discovered_libraries}")
    print(f"Total verified libraries: {summary.total_verified_libraries} (dynamically traced dlopen)")
    print(f"Total guarded libraries: {summary.total_guarded_libraries}")
    print(f"Total file-exists libraries: {summary.total_file_exists_libraries} (static check only, NOT dynamic)")

    print("\n" + "-" * 90)
    print("METRICS")
    print("-" * 90)

    print(f"\nRaw Recall (discovered/expected):      {summary.avg_raw_recall:.1%}")
    print(f"Verified Recall (verified+guarded/expected): {summary.avg_verified_recall:.1%}")
    print(f"Precision (correct/discovered):        {summary.avg_precision:.1%}")

    print("\nNOTE: 'Verified' = dlopen was dynamically traced (Frida/ltrace/LD_DEBUG)")
    print("      'File Exists' = library file exists but dlopen was NOT traced (static check)")

    print("\n" + "-" * 90)
    print("PER-BENCHMARK RESULTS")
    print("-" * 90)

    headers = ["Benchmark", "Expected", "Disc.", "Verified", "Guard", "FileEx", "Raw Rec.", "Ver. Rec."]
    print(f"\n{headers[0]:<25} {headers[1]:>8} {headers[2]:>6} {headers[3]:>8} {headers[4]:>6} {headers[5]:>6} {headers[6]:>8} {headers[7]:>8}")
    print("-" * 90)

    for r in summary.results:
        print(f"{r.name:<25} {r.expected_libraries:>8} {r.discovered_libraries:>6} "
              f"{r.verified_libraries:>8} {r.guarded_libraries:>6} {r.file_exists_libraries:>6} "
              f"{r.raw_recall:>7.1%} {r.verified_recall:>8.1%}")

    print("\n" + "-" * 90)
    print("TIMING")
    print("-" * 90)
    print(f"\nTotal analysis time:    {summary.total_analysis_time:.2f}s")
    print(f"Total validation time:  {summary.total_validation_time:.2f}s")
    print(f"Total time:             {summary.total_analysis_time + summary.total_validation_time:.2f}s")

    print("\n" + "=" * 90)


def export_results(summary: EvaluationSummary, output_file: Path) -> None:
    """Export results to JSON."""

    data = {
        "total_benchmarks": summary.total_benchmarks,
        "total_expected_libraries": summary.total_expected_libraries,
        "total_discovered_libraries": summary.total_discovered_libraries,
        "total_verified_libraries": summary.total_verified_libraries,
        "total_guarded_libraries": summary.total_guarded_libraries,
        "avg_raw_recall": summary.avg_raw_recall,
        "avg_verified_recall": summary.avg_verified_recall,
        "avg_precision": summary.avg_precision,
        "total_analysis_time": summary.total_analysis_time,
        "total_validation_time": summary.total_validation_time,
        "results": [
            {
                "name": r.name,
                "expected_libraries": r.expected_libraries,
                "discovered_libraries": r.discovered_libraries,
                "verified_libraries": r.verified_libraries,
                "guarded_libraries": r.guarded_libraries,
                "raw_recall": r.raw_recall,
                "verified_recall": r.verified_recall,
                "raw_precision": r.raw_precision,
                "analysis_time": r.analysis_time,
                "validation_time": r.validation_time,
                "libraries": [asdict(lib) for lib in r.libraries],
                "errors": r.errors,
            }
            for r in summary.results
        ]
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    log.info(f"Results exported to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate DynPathResolver precision and recall"
    )
    parser.add_argument(
        "--benchmark", "-b",
        help="Evaluate specific benchmark (directory name)"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Evaluate all benchmarks"
    )
    parser.add_argument(
        "--benchmarks-dir",
        default="examples",
        help="Directory containing benchmarks (default: examples)"
    )
    parser.add_argument(
        "--library-paths", "-L",
        nargs="+",
        default=[],
        help="Additional library search paths"
    )
    parser.add_argument(
        "--validation-mode", "-m",
        choices=["none", "detect", "validate"],
        default="validate",
        help="Validation mode (default: validate)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Export results to JSON file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    benchmarks_dir = Path(args.benchmarks_dir)

    if args.benchmark:
        # Single benchmark
        benchmark_dir = benchmarks_dir / args.benchmark
        if not benchmark_dir.exists():
            benchmark_dir = benchmarks_dir / "benchmarks" / args.benchmark

        if not benchmark_dir.exists():
            log.error(f"Benchmark not found: {args.benchmark}")
            return 1

        result = evaluate_benchmark(
            benchmark_dir,
            args.library_paths,
            args.validation_mode,
            args.verbose
        )

        if result:
            summary = EvaluationSummary(
                total_benchmarks=1,
                total_expected_libraries=result.expected_libraries,
                total_discovered_libraries=result.discovered_libraries,
                total_verified_libraries=result.verified_libraries,
                total_guarded_libraries=result.guarded_libraries,
                total_file_exists_libraries=result.file_exists_libraries,
                avg_raw_recall=result.raw_recall,
                avg_verified_recall=result.verified_recall,
                avg_precision=result.raw_precision,
                total_analysis_time=result.analysis_time,
                total_validation_time=result.validation_time,
                results=[result]
            )
            print_summary(summary)

            if args.output:
                export_results(summary, Path(args.output))

    elif args.all:
        # All benchmarks
        summary = evaluate_all(
            benchmarks_dir,
            args.library_paths,
            args.validation_mode,
            args.verbose
        )
        print_summary(summary)

        if args.output:
            export_results(summary, Path(args.output))

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
