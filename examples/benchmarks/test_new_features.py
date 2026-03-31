#!/usr/bin/env python3
"""
Quick test of new DynPathResolver features (syscall tracking, control flow, signals).
Only tests the new benchmarks: 13_mmap_exec, 14_rop_chain, 16_signal_handler
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import angr
from dynpathresolver import DynPathResolver


def test_benchmark(name: str, benchmark_dir: Path) -> dict:
    """Test a single benchmark with 50 steps max."""
    binary_path = benchmark_dir / "test_binary"

    if not binary_path.exists():
        return {"name": name, "status": "SKIP", "error": "Binary not found"}

    print(f"\n{'=' * 50}")
    print(f"Testing: {name}")
    print('=' * 50)

    try:
        # Create angr project
        project = angr.Project(
            str(binary_path),
            auto_load_libs=False,
            load_options={'main_opts': {'base_addr': 0x400000}}
        )
        print(f"  Loaded: {project.arch.name}")

        # Create DynPathResolver with all new features
        technique = DynPathResolver(
            library_paths=[str(benchmark_dir)],
            handle_syscall_loading=True,
            track_indirect_flow=True,
            detect_rop=True,
            detect_jop=True,
            track_signals=True,
            path_predictor='heuristic',
        )

        # Create simulation manager
        state = project.factory.entry_state(
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        )
        simgr = project.factory.simgr(state)
        simgr.use_technique(technique)

        # Run with limited steps
        steps = 0
        while len(simgr.active) > 0 and steps < 50:
            simgr.step()
            steps += 1

        print(f"  Executed {steps} steps")
        print(f"  Active states: {len(simgr.active)}")

        # Memory tracker results
        if technique.memory_tracker:
            stats = technique.memory_tracker.get_statistics()
            print(f"  Memory Tracking:")
            print(f"    - mmaps: {stats.get('total_mmaps', 0)}")
            print(f"    - mprotects: {stats.get('total_mprotects', 0)}")
            print(f"    - executable regions: {len(technique.get_executable_regions())}")
            print(f"    - W->X transitions: {len(technique.memory_tracker.get_wx_transitions())}")

        # Control flow results
        if technique.indirect_flow_tracker:
            stats = technique.indirect_flow_tracker.get_statistics()
            print(f"  Indirect Flow:")
            print(f"    - total calls: {stats.get('total_indirect_calls', 0)}")
            print(f"    - dynamic calls: {len(technique.get_dynamic_calls())}")
            print(f"    - returns: {stats.get('total_returns', 0)}")

        # ROP/JOP results
        rop = technique.get_rop_chains()
        jop = technique.get_jop_chains()
        print(f"  ROP Detection:")
        print(f"    - chains found: {len(rop)}")
        print(f"  JOP Detection:")
        print(f"    - chains found: {len(jop)}")

        # Signal results
        if technique.signal_tracker:
            stats = technique.signal_tracker.get_statistics()
            handlers = technique.get_signal_handlers()
            print(f"  Signal Tracking:")
            print(f"    - handlers: {len(handlers)}")
            for h in handlers:
                print(f"      - signal {h.signum} -> 0x{h.handler_addr:x}")

        return {
            "name": name,
            "status": "OK",
            "steps": steps,
            "memory_stats": technique.memory_tracker.get_statistics() if technique.memory_tracker else {},
            "flow_stats": technique.indirect_flow_tracker.get_statistics() if technique.indirect_flow_tracker else {},
            "rop_chains": len(rop),
            "jop_chains": len(jop),
            "signal_handlers": len(technique.get_signal_handlers()) if technique.signal_tracker else 0,
        }

    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()
        return {"name": name, "status": "ERROR", "error": str(e)}


def main():
    benchmarks_dir = Path(__file__).parent

    print("=" * 60)
    print("DynPathResolver New Feature Tests")
    print("=" * 60)

    # Test only the new benchmarks
    new_benchmarks = [
        ("13_mmap_exec", benchmarks_dir / "13_mmap_exec"),
        ("14_rop_chain", benchmarks_dir / "14_rop_chain"),
        ("16_signal_handler", benchmarks_dir / "16_signal_handler"),
    ]

    results = []
    for name, path in new_benchmarks:
        if path.exists():
            result = test_benchmark(name, path)
            results.append(result)
        else:
            print(f"\nSkipping {name} - directory not found")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for r in results:
        status = r.get("status", "UNKNOWN")
        name = r.get("name", "?")
        if status == "OK":
            print(f"  {name}: OK ({r.get('steps', 0)} steps)")
        else:
            print(f"  {name}: {status} - {r.get('error', '')}")


if __name__ == "__main__":
    main()
