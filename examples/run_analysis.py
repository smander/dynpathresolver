#!/usr/bin/env python3
"""
DynPathResolver Analysis Script

This script demonstrates how to use DynPathResolver to analyze binaries
with complex dynamic loading patterns that static analysis would miss.

Usage:
    python examples/run_analysis.py <binary> [options]

Example:
    python examples/run_analysis.py examples/complex_loader/loader

    # With custom library path
    python examples/run_analysis.py examples/complex_loader/loader \
        --lib-path examples/complex_loader
"""

import argparse
import json
import os
import sys
from pathlib import Path

import angr

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dynpathresolver import DynPathResolver


def analyze_static(project: angr.Project) -> dict:
    """Run static CFG analysis for comparison."""
    print("[*] Running static CFG analysis (CFGFast)...")

    cfg = project.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=False,  # Disable built-in resolution
    )

    # Count nodes and edges
    static_results = {
        'nodes': len(cfg.graph.nodes()),
        'edges': len(cfg.graph.edges()),
        'functions': len(cfg.functions),
        'function_names': [f.name for f in cfg.functions.values() if f.name],
    }

    print(f"    Nodes: {static_results['nodes']}")
    print(f"    Edges: {static_results['edges']}")
    print(f"    Functions: {static_results['functions']}")

    return static_results


def analyze_dynamic(
    project: angr.Project,
    library_paths: list[str],
    output_dir: str,
    max_steps: int = 1000,
    max_forks: int = 8,
) -> dict:
    """Run DynPathResolver analysis."""
    print("\n[*] Running DynPathResolver analysis...")

    # Create initial state
    state = project.factory.entry_state(
        add_options={
            angr.options.LAZY_SOLVES,
        }
    )

    # Create simulation manager
    simgr = project.factory.simgr(state)

    # Apply DynPathResolver technique
    dpr = DynPathResolver(
        max_forks=max_forks,
        preload_common=True,
        library_paths=library_paths,
        output_dir=output_dir,
    )
    simgr.use_technique(dpr)

    print(f"    Library paths: {library_paths}")
    print(f"    Max forks: {max_forks}")
    print(f"    Max steps: {max_steps}")

    # Run exploration
    step_count = 0
    for _ in range(max_steps):
        if not simgr.active:
            print(f"    Exploration complete at step {step_count}")
            break
        simgr.step()
        step_count += 1

        # Progress indicator
        if step_count % 100 == 0:
            print(f"    Step {step_count}: {len(simgr.active)} active states")

    # Export results
    dpr.complete(simgr)

    # Collect statistics
    dynamic_results = {
        'steps': step_count,
        'final_active_states': len(simgr.active),
        'deadended_states': len(simgr.deadended),
        'discoveries': len(dpr.cfg_patcher.discovery_log.entries),
        'preloaded_libs': len(dpr.preloader.pending_libs),
    }

    print(f"\n    Steps executed: {dynamic_results['steps']}")
    print(f"    Active states: {dynamic_results['final_active_states']}")
    print(f"    Deadended: {dynamic_results['deadended_states']}")
    print(f"    Discoveries: {dynamic_results['discoveries']}")

    return dynamic_results


def print_discoveries(output_dir: str):
    """Print discovered dynamic paths."""
    json_path = os.path.join(output_dir, 'discoveries.json')

    if not os.path.exists(json_path):
        print("\n[!] No discoveries file found")
        return

    with open(json_path) as f:
        discoveries = json.load(f)

    if not discoveries:
        print("\n[*] No dynamic paths discovered")
        return

    print(f"\n[*] Discovered {len(discoveries)} dynamic path(s):")
    print("-" * 60)

    for i, d in enumerate(discoveries, 1):
        print(f"\n  [{i}] {d['type']}")
        print(f"      Source: 0x{d['source']:x}")
        print(f"      Target: 0x{d['target']:x}")
        print(f"      Confidence: {d.get('confidence', 1.0)}")

        if d.get('solver_solutions'):
            solutions = d['solver_solutions']
            if len(solutions) > 1:
                print(f"      All solutions: {[hex(s) for s in solutions]}")

        if d.get('library_loaded'):
            print(f"      Library: {d['library_loaded']}")


def compare_results(static_results: dict, dynamic_results: dict):
    """Compare static vs dynamic analysis results."""
    print("\n" + "=" * 60)
    print("COMPARISON: Static vs Dynamic Analysis")
    print("=" * 60)

    print(f"\n  Static Analysis:")
    print(f"    - Functions found: {static_results['functions']}")
    print(f"    - CFG nodes: {static_results['nodes']}")
    print(f"    - CFG edges: {static_results['edges']}")

    print(f"\n  Dynamic Analysis (DynPathResolver):")
    print(f"    - New paths discovered: {dynamic_results['discoveries']}")
    print(f"    - Libraries preloaded: {dynamic_results['preloaded_libs']}")
    print(f"    - Exploration depth: {dynamic_results['steps']} steps")

    if dynamic_results['discoveries'] > 0:
        print("\n  [+] DynPathResolver found paths missed by static analysis!")
    else:
        print("\n  [!] No additional paths found (may need more exploration)")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze binary with DynPathResolver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python examples/run_analysis.py ./binary

  # With library path
  python examples/run_analysis.py ./binary --lib-path ./libs

  # With custom output directory
  python examples/run_analysis.py ./binary -o ./results

  # Complex loader example
  python examples/run_analysis.py examples/complex_loader/loader \\
      --lib-path examples/complex_loader -o output/complex
        """
    )

    parser.add_argument('binary', help='Path to binary to analyze')
    parser.add_argument(
        '--lib-path', '-l',
        action='append',
        default=[],
        help='Additional library search paths (can be repeated)'
    )
    parser.add_argument(
        '--output', '-o',
        default='./output',
        help='Output directory for results (default: ./output)'
    )
    parser.add_argument(
        '--max-steps', '-s',
        type=int,
        default=1000,
        help='Maximum exploration steps (default: 1000)'
    )
    parser.add_argument(
        '--max-forks', '-f',
        type=int,
        default=8,
        help='Maximum state forks per indirect jump (default: 8)'
    )
    parser.add_argument(
        '--no-static',
        action='store_true',
        help='Skip static CFG analysis comparison'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Validate binary exists
    if not os.path.exists(args.binary):
        print(f"Error: Binary not found: {args.binary}")
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    print("=" * 60)
    print("DynPathResolver Analysis")
    print("=" * 60)
    print(f"\n  Binary: {args.binary}")
    print(f"  Output: {args.output}")

    # Load binary
    print("\n[*] Loading binary...")
    project = angr.Project(
        args.binary,
        auto_load_libs=False,  # We'll handle library loading
        load_options={
            'main_opts': {'base_addr': 0x400000},
        }
    )

    print(f"    Architecture: {project.arch.name}")
    print(f"    Entry point: 0x{project.entry:x}")

    # Run static analysis for comparison
    static_results = None
    if not args.no_static:
        static_results = analyze_static(project)

    # Run dynamic analysis
    dynamic_results = analyze_dynamic(
        project,
        library_paths=args.lib_path,
        output_dir=args.output,
        max_steps=args.max_steps,
        max_forks=args.max_forks,
    )

    # Print discoveries
    print_discoveries(args.output)

    # Compare results
    if static_results:
        compare_results(static_results, dynamic_results)

    print(f"\n[*] Results saved to: {args.output}/")
    print("    - discoveries.json")
    print("    - discoveries.db")


if __name__ == '__main__':
    main()
