#!/usr/bin/env python3
"""
Full example: Using CompleteCFGBuilder with exploration for complete CFG.

This uses the exploration-based approach which runs full symbolic execution
with DynPathResolver to get more complete coverage.
"""

import sys
import logging
import angr

from dynpathresolver import CompleteCFGBuilder, CompleteCFG

# Enable logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(message)s')
log = logging.getLogger(__name__)


def analyze_binary(binary_path: str, use_exploration: bool = False) -> CompleteCFG:
    """Build a complete CFG for the given binary."""
    print(f"\n{'='*70}")
    print(f"Analyzing: {binary_path}")
    print(f"Method: {'Exploration-based' if use_exploration else 'CFGEmulated'}")
    print(f"{'='*70}\n")

    # Load the binary with libraries for better analysis
    project = angr.Project(
        binary_path,
        auto_load_libs=True,  # Load libc etc for better CFG
        load_options={'auto_load_libs': True}
    )

    print(f"Loaded binary: {project.filename}")
    print(f"Architecture: {project.arch.name}")
    print(f"Entry point: 0x{project.entry:x}")

    # Create the CFG builder
    builder = CompleteCFGBuilder(
        project=project,
        context_sensitivity_level=1,
        keep_state=True,
        max_iterations=50000,
        max_steps=50000,
        library_paths=['.', '/lib', '/usr/lib', '/lib/aarch64-linux-gnu'],
        resolve_indirect=True,
        track_memory=True,
    )

    if use_exploration:
        # Use exploration-based method (slower but more complete)
        print("\nRunning exploration-based CFG building...")
        cfg = builder.build_with_exploration(max_steps=5000)
    else:
        # Use CFGEmulated method (faster)
        print("\nRunning CFGEmulated-based CFG building...")
        cfg = builder.build(call_depth=5)

    return cfg


def print_cfg_summary(cfg: CompleteCFG) -> None:
    """Print a summary of the CFG."""
    print(f"\n{'='*70}")
    print("CFG Summary")
    print(f"{'='*70}")
    print(f"Total basic blocks: {cfg.total_basic_blocks}")
    print(f"Total instructions: {cfg.total_instructions}")
    print(f"Total edges: {len(cfg.edges)}")
    print(f"  - Static edges: {cfg.static_edges}")
    print(f"  - Dynamic edges: {cfg.dynamic_edges}")
    print(f"Functions discovered: {len(cfg.functions)}")

    # Show some functions
    if cfg.functions:
        print(f"\nFunctions (first 20):")
        for i, (addr, name) in enumerate(sorted(cfg.functions.items())[:20]):
            print(f"  0x{addr:x}: {name}")
        if len(cfg.functions) > 20:
            print(f"  ... and {len(cfg.functions) - 20} more")

    if cfg.discovered_libraries:
        print(f"\nDiscovered libraries:")
        for lib in cfg.discovered_libraries:
            print(f"  - {lib}")

    if cfg.resolved_symbols:
        print(f"\nResolved symbols:")
        for sym, addr in cfg.resolved_symbols.items():
            print(f"  - {sym} @ 0x{addr:x}")


def print_node_with_state(cfg: CompleteCFG, addr: int) -> None:
    """Print detailed information about a node including register states."""
    node = cfg.get_node(addr)
    if not node:
        print(f"No node at 0x{addr:x}")
        return

    print(f"\n{'='*70}")
    print(f"Node Details: 0x{addr:x}")
    print(f"{'='*70}")
    print(f"Size: {node.size} bytes")
    print(f"Function: {node.function_name or 'unknown'} @ 0x{node.function_addr:x}" if node.function_addr else "Function: unknown")
    print(f"Is entry: {node.is_entry}")
    print(f"Is dynamic target: {node.is_dynamic_target}")

    if node.loads_library:
        print(f"Loads library: {node.loads_library}")

    if node.instructions:
        print(f"\nInstructions ({len(node.instructions)}):")
        for instr in node.instructions:
            print(f"  {instr}")

    if node.exit_states:
        print(f"\nExit states ({len(node.exit_states)}):")
        for i, state in enumerate(node.exit_states[:3]):
            print(f"\n  State {i}:")
            # Print registers that have concrete values
            regs = state.to_dict()['registers']
            concrete_regs = {k: v for k, v in regs.items() if v is not None}
            if concrete_regs:
                print(f"    Concrete registers:")
                for reg, val in concrete_regs.items():
                    print(f"      {reg.upper()} = 0x{val:x}")

            # Print flags
            flags = state.to_dict()['flags']
            flag_str = ", ".join(f"{k.upper()}={v}" for k, v in flags.items() if v is not None)
            if flag_str:
                print(f"    Flags: {flag_str}")

            # Print symbolic registers
            if state.symbolic_regs:
                print(f"    Symbolic: {', '.join(state.symbolic_regs)}")

    if node.constraints:
        print(f"\nPath constraints ({len(node.constraints)}):")
        for c in node.constraints[:5]:
            c_str = str(c)
            print(f"  {c_str[:100]}..." if len(c_str) > 100 else f"  {c_str}")
        if len(node.constraints) > 5:
            print(f"  ... and {len(node.constraints) - 5} more")

    # Show successors
    succs = cfg.get_successors(addr)
    if succs:
        print(f"\nSuccessors ({len(succs)}):")
        for s in succs[:10]:
            succ_node = cfg.get_node(s)
            name = succ_node.function_name if succ_node else "?"
            print(f"  -> 0x{s:x} ({name})")

    # Show predecessors
    preds = cfg.get_predecessors(addr)
    if preds:
        print(f"\nPredecessors ({len(preds)}):")
        for p in preds[:10]:
            pred_node = cfg.get_node(p)
            name = pred_node.function_name if pred_node else "?"
            print(f"  <- 0x{p:x} ({name})")


def main():
    if len(sys.argv) < 2:
        print("Usage: python cfg_builder_full_example.py <binary> [--explore]")
        print("\nOptions:")
        print("  --explore  Use exploration-based method (slower but more complete)")
        print("\nExample:")
        print("  python cfg_builder_full_example.py ./test_binary")
        print("  python cfg_builder_full_example.py ./test_binary --explore")
        sys.exit(1)

    binary_path = sys.argv[1]
    use_exploration = '--explore' in sys.argv

    # Build the CFG
    cfg = analyze_binary(binary_path, use_exploration)

    # Print summary
    print_cfg_summary(cfg)

    # Find and print interesting nodes
    if cfg.nodes:
        # Find entry node
        entry_nodes = [n for n in cfg.nodes.values() if n.is_entry]
        if entry_nodes:
            print_node_with_state(cfg, entry_nodes[0].addr)

        # Find main function if exists
        main_nodes = [n for n in cfg.nodes.values() if n.function_name == 'main']
        if main_nodes:
            print_node_with_state(cfg, main_nodes[0].addr)

        # Find any dynamic targets
        dynamic_nodes = [n for n in cfg.nodes.values() if n.is_dynamic_target]
        if dynamic_nodes:
            print(f"\n{'='*70}")
            print(f"Found {len(dynamic_nodes)} dynamic targets")
            print(f"{'='*70}")
            for node in dynamic_nodes[:3]:
                print_node_with_state(cfg, node.addr)

    # Export
    import os
    output_dir = os.path.dirname(binary_path) or '.'
    base_name = os.path.basename(binary_path)

    json_path = os.path.join(output_dir, f"{base_name}_complete_cfg.json")
    cfg.export_json(json_path)
    print(f"\n\nExported CFG to: {json_path}")

    dot_path = os.path.join(output_dir, f"{base_name}_complete_cfg.dot")
    cfg.export_dot(dot_path)
    print(f"Exported DOT to: {dot_path}")
    print(f"\nTo visualize: dot -Tpng {dot_path} -o {base_name}_cfg.png")


if __name__ == '__main__':
    main()
