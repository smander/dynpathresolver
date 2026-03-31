#!/usr/bin/env python3
"""
Example: Using CompleteCFGBuilder to get complete CFG with state information.

This example shows how to build a complete CFG that includes:
- Full register states at each basic block
- CPU flags (ZF, CF, SF, OF, etc.)
- Path constraints
- Both static and dynamically-discovered edges
- Discovered libraries and resolved symbols
"""

import sys
import logging
import angr

from dynpathresolver import CompleteCFGBuilder, CompleteCFG

# Enable logging to see what's happening
logging.basicConfig(level=logging.INFO)


def analyze_binary(binary_path: str) -> CompleteCFG:
    """
    Build a complete CFG for the given binary.

    Args:
        binary_path: Path to the binary to analyze

    Returns:
        CompleteCFG with full state information
    """
    print(f"\n{'='*60}")
    print(f"Analyzing: {binary_path}")
    print(f"{'='*60}\n")

    # Load the binary
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create the CFG builder
    builder = CompleteCFGBuilder(
        project=project,
        context_sensitivity_level=1,  # 0=fastest, 3=most precise
        keep_state=True,              # Keep full state at each node
        library_paths=['.', '/lib', '/usr/lib'],
    )

    # Build the CFG (Option 1: CFGEmulated-based)
    print("Building CFG with CFGEmulated + DynPathResolver hooks...")
    cfg = builder.build(call_depth=3)

    return cfg


def print_cfg_summary(cfg: CompleteCFG) -> None:
    """Print a summary of the CFG."""
    print(f"\n{'='*60}")
    print("CFG Summary")
    print(f"{'='*60}")
    print(f"Total basic blocks: {cfg.total_basic_blocks}")
    print(f"Total instructions: {cfg.total_instructions}")
    print(f"Total edges: {len(cfg.edges)}")
    print(f"  - Static edges: {cfg.static_edges}")
    print(f"  - Dynamic edges: {cfg.dynamic_edges}")
    print(f"Functions discovered: {len(cfg.functions)}")

    if cfg.discovered_libraries:
        print(f"\nDiscovered libraries:")
        for lib in cfg.discovered_libraries:
            print(f"  - {lib}")

    if cfg.resolved_symbols:
        print(f"\nResolved symbols:")
        for sym, addr in cfg.resolved_symbols.items():
            print(f"  - {sym} @ 0x{addr:x}")


def print_node_details(cfg: CompleteCFG, addr: int) -> None:
    """Print detailed information about a specific node."""
    node = cfg.get_node(addr)
    if not node:
        print(f"No node at 0x{addr:x}")
        return

    print(f"\n{'='*60}")
    print(f"Node at 0x{addr:x}")
    print(f"{'='*60}")
    print(f"Size: {node.size} bytes")
    print(f"Function: {node.function_name or 'unknown'}")

    if node.instructions:
        print(f"\nInstructions ({len(node.instructions)}):")
        for instr in node.instructions[:10]:  # Limit to first 10
            print(f"  {instr}")
        if len(node.instructions) > 10:
            print(f"  ... and {len(node.instructions) - 10} more")

    if node.exit_states:
        print(f"\nExit states ({len(node.exit_states)}):")
        for i, state in enumerate(node.exit_states[:3]):  # Limit to first 3
            print(f"  State {i}:")
            print(f"    RAX=0x{state.rax:x}" if state.rax else "    RAX=symbolic")
            print(f"    RBX=0x{state.rbx:x}" if state.rbx else "    RBX=symbolic")
            print(f"    RSP=0x{state.rsp:x}" if state.rsp else "    RSP=symbolic")
            print(f"    Flags: ZF={state.zf}, CF={state.cf}, SF={state.sf}, OF={state.of}")
            if state.symbolic_regs:
                print(f"    Symbolic registers: {', '.join(state.symbolic_regs)}")

    if node.constraints:
        print(f"\nPath constraints ({len(node.constraints)}):")
        for c in node.constraints[:5]:  # Limit to first 5
            print(f"  {c[:80]}..." if len(c) > 80 else f"  {c}")

    # Show successors
    succs = cfg.get_successors(addr)
    if succs:
        print(f"\nSuccessors: {[hex(s) for s in succs]}")

    # Show predecessors
    preds = cfg.get_predecessors(addr)
    if preds:
        print(f"Predecessors: {[hex(p) for p in preds]}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python cfg_builder_example.py <binary>")
        print("\nExample:")
        print("  python cfg_builder_example.py ./examples/benchmarks/01_simple_dlopen/main")
        sys.exit(1)

    binary_path = sys.argv[1]

    # Build the CFG
    cfg = analyze_binary(binary_path)

    # Print summary
    print_cfg_summary(cfg)

    # Print details for entry point
    if cfg.nodes:
        # Find entry node
        entry_nodes = [n for n in cfg.nodes.values() if n.is_entry]
        if entry_nodes:
            print_node_details(cfg, entry_nodes[0].addr)
        else:
            # Just show the first node
            first_addr = min(cfg.nodes.keys())
            print_node_details(cfg, first_addr)

    # Export to files
    output_base = binary_path.replace('/', '_')

    json_path = f"{output_base}_cfg.json"
    cfg.export_json(json_path)
    print(f"\nExported CFG to: {json_path}")

    dot_path = f"{output_base}_cfg.dot"
    cfg.export_dot(dot_path)
    print(f"Exported DOT to: {dot_path}")
    print(f"\nTo visualize: dot -Tpng {dot_path} -o {output_base}_cfg.png")


if __name__ == '__main__':
    main()
