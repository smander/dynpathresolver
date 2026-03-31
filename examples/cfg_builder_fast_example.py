#!/usr/bin/env python3
"""
Fast example: Using CompleteCFGBuilder with CFGFast fallback.

This is a faster version that uses CFGFast for initial CFG building,
then augments with state information from limited symbolic execution.
"""

import sys
import logging
import angr

logging.basicConfig(level=logging.WARNING)

from dynpathresolver.core.cfg_builder import (
    CompleteCFGBuilder, CompleteCFG, CompleteCFGNode,
    CompleteCFGEdge, EdgeType, RegisterState, Instruction
)


def build_fast_cfg(binary_path: str) -> CompleteCFG:
    """Build CFG using CFGFast (fast) and augment with limited state info."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {binary_path}")
    print(f"{'='*60}\n")

    # Load binary without libs for speed
    project = angr.Project(binary_path, auto_load_libs=False)

    print(f"Architecture: {project.arch.name}")
    print(f"Entry point: 0x{project.entry:x}")

    # Build CFGFast
    print("\nBuilding CFGFast...")
    angr_cfg = project.analyses.CFGFast(normalize=True)
    print(f"CFGFast: {len(angr_cfg.graph.nodes())} nodes, {len(angr_cfg.graph.edges())} edges")

    # Convert to CompleteCFG
    complete_cfg = CompleteCFG()

    # Process nodes
    for angr_node in angr_cfg.graph.nodes():
        if angr_node.addr is None:
            continue

        node = CompleteCFGNode(
            addr=angr_node.addr,
            size=angr_node.size if angr_node.size else 0,
        )

        # Extract instructions
        if angr_node.block:
            try:
                for insn in angr_node.block.capstone.insns:
                    node.instructions.append(Instruction(
                        addr=insn.address,
                        size=insn.size,
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                        bytes=bytes(insn.bytes),
                    ))
            except Exception:
                pass

        # Get function info
        if angr_node.function_address:
            node.function_addr = angr_node.function_address
            func = angr_cfg.kb.functions.get(angr_node.function_address)
            if func:
                node.function_name = func.name
                complete_cfg.functions[angr_node.function_address] = func.name

        if angr_node.addr == project.entry:
            node.is_entry = True

        complete_cfg.add_node(node)

    # Process edges
    for src_node, dst_node, edge_data in angr_cfg.graph.edges(data=True):
        if src_node.addr is None or dst_node.addr is None:
            continue

        jumpkind = edge_data.get('jumpkind', 'Ijk_Boring')

        edge_type = {
            'Ijk_Boring': EdgeType.FALLTHROUGH,
            'Ijk_Call': EdgeType.DIRECT_CALL,
            'Ijk_Ret': EdgeType.RETURN,
            'Ijk_Sys_syscall': EdgeType.SYSCALL,
        }.get(jumpkind, EdgeType.DIRECT_JUMP)

        edge = CompleteCFGEdge(
            src_addr=src_node.addr,
            dst_addr=dst_node.addr,
            edge_type=edge_type,
        )
        complete_cfg.add_edge(edge)

    # Now run limited symbolic execution to get state at key points
    print("\nRunning limited symbolic execution for state capture...")

    # Create initial state
    state = project.factory.entry_state(
        add_options={angr.sim_options.LAZY_SOLVES}
    )
    simgr = project.factory.simgr(state)

    # Run for limited steps
    states_captured = {}
    step = 0
    max_steps = 500

    while simgr.active and step < max_steps:
        for s in simgr.active:
            addr = s.addr
            if addr in complete_cfg.nodes and addr not in states_captured:
                # Capture state
                reg_state = RegisterState.from_state(s)
                complete_cfg.nodes[addr].exit_states.append(reg_state)
                states_captured[addr] = True

        simgr.step()
        step += 1

    print(f"Captured states at {len(states_captured)} nodes")

    return complete_cfg


def print_summary(cfg: CompleteCFG) -> None:
    """Print CFG summary."""
    print(f"\n{'='*60}")
    print("CFG Summary")
    print(f"{'='*60}")
    print(f"Basic blocks: {cfg.total_basic_blocks}")
    print(f"Instructions: {cfg.total_instructions}")
    print(f"Edges: {len(cfg.edges)}")
    print(f"Functions: {len(cfg.functions)}")

    # Show functions
    if cfg.functions:
        print(f"\nFunctions:")
        for addr, name in sorted(cfg.functions.items())[:15]:
            print(f"  0x{addr:x}: {name}")
        if len(cfg.functions) > 15:
            print(f"  ... and {len(cfg.functions) - 15} more")

    # Find nodes with captured states
    nodes_with_states = [n for n in cfg.nodes.values() if n.exit_states]
    print(f"\nNodes with state info: {len(nodes_with_states)}")

    # Show one node with state
    if nodes_with_states:
        node = nodes_with_states[0]
        print(f"\nExample node with state: 0x{node.addr:x}")
        if node.function_name:
            print(f"  Function: {node.function_name}")
        if node.instructions:
            print(f"  Instructions: {len(node.instructions)}")
            for i in node.instructions[:3]:
                print(f"    {i}")
        if node.exit_states:
            state = node.exit_states[0]
            print(f"  Register state (arch={state.arch}):")
            # Show architecture-appropriate registers
            if 'AARCH64' in state.arch or 'ARM' in state.arch:
                if state.sp is not None:
                    print(f"    SP = 0x{state.sp:x}" if isinstance(state.sp, int) else f"    SP = {state.sp}")
                if state.pc is not None:
                    print(f"    PC = 0x{state.pc:x}" if isinstance(state.pc, int) else f"    PC = {state.pc}")
                # Show a few general registers
                for reg_name in ['x0', 'x1', 'x2', 'x29', 'x30']:
                    val = state.registers.get(reg_name)
                    if val is not None:
                        print(f"    {reg_name.upper()} = 0x{val:x}" if isinstance(val, int) else f"    {reg_name.upper()} = {val}")
            else:
                # x86_64
                if state.sp is not None:
                    print(f"    RSP = 0x{state.sp:x}" if isinstance(state.sp, int) else f"    RSP = {state.sp}")
                if state.pc is not None:
                    print(f"    RIP = 0x{state.pc:x}" if isinstance(state.pc, int) else f"    RIP = {state.pc}")
            if state.symbolic_regs:
                print(f"    Symbolic: {', '.join(state.symbolic_regs[:5])}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python cfg_builder_fast_example.py <binary>")
        sys.exit(1)

    binary_path = sys.argv[1]

    cfg = build_fast_cfg(binary_path)
    print_summary(cfg)

    # Export
    import os
    base = os.path.basename(binary_path)
    dir_path = os.path.dirname(binary_path) or '.'

    json_path = os.path.join(dir_path, f"{base}_fast_cfg.json")
    cfg.export_json(json_path)
    print(f"\nExported to: {json_path}")


if __name__ == '__main__':
    main()
