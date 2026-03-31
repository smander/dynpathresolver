#!/usr/bin/env python3
"""
Lightweight DynPathResolver analysis for benchmarks.

This script performs a quick analysis of benchmark binaries using reduced
step limits to avoid memory issues in constrained environments.
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

logging.basicConfig(level=logging.WARNING)  # Reduce log verbosity
log = logging.getLogger(__name__)


def analyze_benchmark(benchmark_dir: Path, timeout_steps: int = 100) -> dict:
    """
    Analyze a single benchmark binary with reduced steps.

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

    print(f"  Analyzing: {benchmark_dir.name}...", end=" ", flush=True)

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

        # Run symbolic execution with limited steps
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
            "status": "OK",
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

        print("OK")
        return results

    except Exception as e:
        print(f"ERROR: {e}")
        return {"error": str(e), "benchmark": benchmark_dir.name, "status": "ERROR"}


def main():
    """Run analysis on all benchmarks."""
    benchmarks_dir = Path(__file__).parent

    # Find all benchmark directories
    benchmarks = sorted([
        d for d in benchmarks_dir.iterdir()
        if d.is_dir() and d.name[0].isdigit()
    ])

    print("=" * 60)
    print("DynPathResolver Benchmark Analysis (Lite)")
    print("=" * 60)
    print(f"Found {len(benchmarks)} benchmarks")
    print()

    all_results = []

    for benchmark_dir in benchmarks:
        results = analyze_benchmark(benchmark_dir, timeout_steps=100)
        all_results.append(results)

    # Summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    successful = [r for r in all_results if r.get("status") == "OK"]
    failed = [r for r in all_results if r.get("status") != "OK"]

    print(f"Total benchmarks: {len(all_results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    # Print detailed results for new benchmarks
    print()
    print("New Feature Detection Results:")
    print("-" * 40)

    for r in successful:
        name = r.get("benchmark", "unknown")
        if any(x in name for x in ["13_", "14_", "16_"]):
            print(f"\n{name}:")
            print(f"  Steps: {r.get('steps', 0)}")
            if "memory_tracking" in r:
                mt = r["memory_tracking"]
                print(f"  Memory: mmaps={mt.get('total_mmaps', 0)}, "
                      f"mprotects={mt.get('total_mprotects', 0)}, "
                      f"exec_regions={r.get('executable_regions', 0)}")
            if "indirect_flow" in r:
                ifl = r["indirect_flow"]
                print(f"  Indirect flow: calls={ifl.get('total_indirect_calls', 0)}, "
                      f"dynamic={r.get('dynamic_calls', 0)}")
            print(f"  ROP chains: {r.get('rop_chains', 0)}")
            print(f"  JOP chains: {r.get('jop_chains', 0)}")
            if "signal_tracking" in r:
                st = r["signal_tracking"]
                print(f"  Signals: handlers={r.get('signal_handlers', 0)}")

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
