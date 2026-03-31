#!/usr/bin/env python3
"""
DynPathResolver benchmark analysis - runs all benchmarks with appropriate timeouts.
"""

import gc
import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import angr
from dynpathresolver import DynPathResolver

# No benchmarks skipped - all work correctly
SKIP_BENCHMARKS = set()

# Benchmarks that need more steps due to complex analysis
# NOTE: 08_anti_debug takes ~60s+ due to symbolic /proc/self/status exploration
EXTENDED_STEP_BENCHMARKS = {
    '08_anti_debug': 100,       # Limited steps (full analysis takes 60s+)
    '12_manual_elf_load': 200,  # Manual ELF parsing
    '13_mmap_exec': 200,        # mmap + exec shellcode
}


def analyze_benchmark(benchmark_dir: Path, timeout_steps: int = 100) -> dict:
    """Analyze a single benchmark."""
    binary_path = benchmark_dir / "test_binary"

    if not binary_path.exists():
        return {"benchmark": benchmark_dir.name, "status": "SKIP", "error": "No binary"}

    print(f"  {benchmark_dir.name}...", end=" ", flush=True)

    try:
        project = angr.Project(
            str(binary_path),
            auto_load_libs=False,
            load_options={'main_opts': {'base_addr': 0x400000}}
        )

        technique = DynPathResolver(
            library_paths=[str(benchmark_dir)],
            handle_syscall_loading=True,
            track_indirect_flow=True,
            detect_rop=True,
            track_signals=True,
            path_predictor='heuristic',
        )

        state = project.factory.entry_state(
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
        )
        simgr = project.factory.simgr(state)
        simgr.use_technique(technique)

        steps = 0
        while len(simgr.active) > 0 and steps < timeout_steps:
            simgr.step()
            steps += 1

        results = {
            "benchmark": benchmark_dir.name,
            "status": "OK",
            "steps": steps,
            "active_states": len(simgr.active),
        }

        if technique.memory_tracker:
            stats = technique.memory_tracker.get_statistics()
            results["memory"] = {
                "mmaps": stats.get('total_mmaps', 0),
                "mprotects": stats.get('total_mprotects', 0),
                "exec_regions": len(technique.get_executable_regions()),
                "wx_transitions": len(technique.memory_tracker.get_wx_transitions()),
            }

        if technique.indirect_flow_tracker:
            stats = technique.indirect_flow_tracker.get_statistics()
            results["control_flow"] = {
                "indirect_calls": stats.get('total_indirect_calls', 0),
                "dynamic_calls": len(technique.get_dynamic_calls()),
            }

        results["rop_chains"] = len(technique.get_rop_chains())
        results["jop_chains"] = len(technique.get_jop_chains())

        if technique.signal_tracker:
            results["signal_handlers"] = len(technique.get_signal_handlers())

        print("OK")

        # Force garbage collection between benchmarks
        del simgr, state, project, technique
        gc.collect()

        return results

    except Exception as e:
        print(f"ERROR: {e}")
        gc.collect()
        return {"benchmark": benchmark_dir.name, "status": "ERROR", "error": str(e)}


def main():
    benchmarks_dir = Path(__file__).parent

    benchmarks = sorted([
        d for d in benchmarks_dir.iterdir()
        if d.is_dir() and d.name[0].isdigit() and d.name not in SKIP_BENCHMARKS
    ])

    print("=" * 60)
    print("DynPathResolver Benchmark Analysis")
    print("=" * 60)
    print(f"Running {len(benchmarks)} benchmarks\n")

    all_results = []
    for benchmark_dir in benchmarks:
        # Use extended steps for complex benchmarks
        steps = EXTENDED_STEP_BENCHMARKS.get(benchmark_dir.name, 100)
        results = analyze_benchmark(benchmark_dir, timeout_steps=steps)
        all_results.append(results)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    successful = [r for r in all_results if r.get("status") == "OK"]
    print(f"Successful: {len(successful)}/{len(all_results)}")

    # Save results
    output_path = benchmarks_dir / "analysis_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
