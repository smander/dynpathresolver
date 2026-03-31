#!/usr/bin/env python3
"""
Run DynPathResolver analysis on benchmark binaries.

This script analyzes the compiled benchmarks using the new syscall-level
and control flow detection features.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import angr
from dynpathresolver import DynPathResolver

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def analyze_benchmark(benchmark_dir: Path, timeout_steps: int = 1000) -> dict:
    """
    Analyze a single benchmark binary.

    Returns:
        dict with analysis results
    """
    binary_path = benchmark_dir / "test_binary"
    ground_truth_path = benchmark_dir / "ground_truth.json"

    if not binary_path.exists():
        return {"error": f"Binary not found: {binary_path}"}

    # Load ground truth
    ground_truth = {}
    if ground_truth_path.exists():
        with open(ground_truth_path) as f:
            ground_truth = json.load(f)

    log.info(f"Analyzing: {benchmark_dir.name}")

    try:
        # Create angr project
        project = angr.Project(
            str(binary_path),
            auto_load_libs=False,
            load_options={'main_opts': {'base_addr': 0x400000}}
        )

        # Create DynPathResolver with new features enabled
        technique = DynPathResolver(
            library_paths=[str(benchmark_dir)],
            handle_syscall_loading=True,
            track_indirect_flow=True,
            detect_rop=True,
            track_signals=True,
            path_predictor='heuristic',
        )

        # Create simulation manager
        state = project.factory.entry_state()
        simgr = project.factory.simgr(state)
        simgr.use_technique(technique)

        # Run symbolic execution
        steps = 0
        while len(simgr.active) > 0 and steps < timeout_steps:
            simgr.step()
            steps += 1

        # Gather results
        results = {
            "benchmark": benchmark_dir.name,
            "steps": steps,
            "active_states": len(simgr.active),
            "deadended_states": len(simgr.deadended) if hasattr(simgr, 'deadended') else 0,
        }

        # Get syscall-level detection results
        if technique.memory_tracker:
            stats = technique.memory_tracker.get_statistics()
            results["memory_tracking"] = stats
            results["executable_regions"] = len(technique.get_executable_regions())
            results["manual_library_loads"] = len(technique.get_manual_library_loads())
            results["wx_transitions"] = len(technique.memory_tracker.get_wx_transitions())

        # Get control flow results
        if technique.indirect_flow_tracker:
            stats = technique.indirect_flow_tracker.get_statistics()
            results["indirect_flow"] = stats
            results["dynamic_calls"] = len(technique.get_dynamic_calls())

        # Get ROP/JOP results
        results["rop_chains"] = len(technique.get_rop_chains())
        results["jop_chains"] = len(technique.get_jop_chains())

        # Get signal results
        if technique.signal_tracker:
            stats = technique.signal_tracker.get_statistics()
            results["signal_tracking"] = stats
            results["signal_handlers"] = len(technique.get_signal_handlers())

        # Compare with ground truth
        if ground_truth:
            expected_libs = [lib["name"] for lib in ground_truth.get("expected_libraries", [])]
            results["expected_libraries"] = expected_libs
            results["ground_truth_technique"] = ground_truth.get("technique", "unknown")

        return results

    except Exception as e:
        log.error(f"Analysis failed for {benchmark_dir.name}: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e), "benchmark": benchmark_dir.name}


def main():
    """Run analysis on all benchmarks."""
    benchmarks_dir = Path(__file__).parent

    # Find all benchmark directories
    benchmarks = sorted([
        d for d in benchmarks_dir.iterdir()
        if d.is_dir() and d.name[0].isdigit()
    ])

    print("=" * 60)
    print("DynPathResolver Benchmark Analysis")
    print("=" * 60)

    all_results = []

    for benchmark_dir in benchmarks:
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {benchmark_dir.name}")
        print("=" * 60)

        results = analyze_benchmark(benchmark_dir)
        all_results.append(results)

        if "error" in results:
            print(f"  ERROR: {results['error']}")
            continue

        print(f"  Steps: {results['steps']}")
        print(f"  Active states: {results['active_states']}")

        if "memory_tracking" in results:
            print(f"  Memory tracking:")
            print(f"    - Total mmaps: {results['memory_tracking'].get('total_mmaps', 0)}")
            print(f"    - Executable regions: {results['executable_regions']}")
            print(f"    - Manual library loads: {results['manual_library_loads']}")
            print(f"    - W->X transitions: {results['wx_transitions']}")

        if "indirect_flow" in results:
            print(f"  Indirect control flow:")
            print(f"    - Total calls: {results['indirect_flow'].get('total_indirect_calls', 0)}")
            print(f"    - Dynamic calls: {results['dynamic_calls']}")

        print(f"  ROP chains detected: {results['rop_chains']}")
        print(f"  JOP chains detected: {results['jop_chains']}")

        if "signal_tracking" in results:
            print(f"  Signal tracking:")
            print(f"    - Handlers registered: {results['signal_handlers']}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    successful = [r for r in all_results if "error" not in r]
    failed = [r for r in all_results if "error" in r]

    print(f"Total benchmarks: {len(all_results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if failed:
        print("\nFailed benchmarks:")
        for r in failed:
            print(f"  - {r.get('benchmark', 'unknown')}: {r.get('error', 'unknown error')}")

    # Save results to JSON
    output_path = benchmarks_dir / "analysis_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
