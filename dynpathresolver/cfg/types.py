"""
CFG type definitions: dataclasses and enums for CFG representation.

This module provides the data types used to represent a complete CFG:
- EdgeType: Types of CFG edges
- RegisterState: Snapshot of register values at a CFG node
- Instruction: A single instruction
- CompleteCFGNode: A CFG node with complete state information
- CompleteCFGEdge: A CFG edge with metadata
- CompleteCFG: Complete CFG with all nodes, edges, and state information
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.enums import EdgeType

log = logging.getLogger(__name__)


@dataclass
class RegisterState:
    """
    Snapshot of register values at a CFG node.

    Supports both x86_64 and ARM64 architectures.
    Values can be:
    - Concrete integer (for non-symbolic registers)
    - Evaluated integer (one possible value for symbolic registers)
    - Symbolic expression string (when evaluation fails)
    """
    # Architecture-independent register storage
    registers: dict[str, int | str] = field(default_factory=dict)

    # Flags (architecture-dependent)
    flags: dict[str, bool | None] = field(default_factory=dict)

    # Track which registers are symbolic
    symbolic_regs: list[str] = field(default_factory=list)

    # Architecture name
    arch: str = "unknown"

    # Program counter
    pc: int | str | None = None

    # Stack pointer
    sp: int | str | None = None

    @classmethod
    def from_state(cls, state: "angr.SimState") -> "RegisterState":
        """Extract register values from an angr state."""
        reg_state = cls()
        reg_state.arch = state.arch.name

        def get_reg_value(reg_name: str) -> tuple[int | str | None, bool]:
            """
            Get register value and whether it's symbolic.
            Returns (value, is_symbolic).
            Value is int if concrete/evaluable, str if symbolic expression, None on error.
            """
            try:
                reg = getattr(state.regs, reg_name)
                is_symbolic = state.solver.symbolic(reg)

                # Always try to get a concrete value (eval gives one solution even for symbolic)
                try:
                    value = state.solver.eval(reg)
                    return (value, is_symbolic)
                except Exception:
                    # Can't evaluate - return symbolic expression as string
                    return (str(reg), is_symbolic)
            except AttributeError:
                # Register doesn't exist for this architecture
                return (None, False)
            except Exception as e:
                return (None, False)

        # Detect architecture and extract appropriate registers
        arch_name = state.arch.name.upper()

        if 'AMD64' in arch_name or 'X86' in arch_name:
            # x86_64 / x86 registers
            x86_regs = [
                'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'
            ]
            if 'AMD64' not in arch_name:  # 32-bit
                x86_regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']

            for reg_name in x86_regs:
                value, is_symbolic = get_reg_value(reg_name)
                if value is not None:
                    reg_state.registers[reg_name] = value
                    if is_symbolic:
                        reg_state.symbolic_regs.append(reg_name)

            # Get PC and SP
            pc_reg = 'rip' if 'AMD64' in arch_name else 'eip'
            sp_reg = 'rsp' if 'AMD64' in arch_name else 'esp'
            reg_state.pc = reg_state.registers.get(pc_reg)
            reg_state.sp = reg_state.registers.get(sp_reg)

            # Extract x86 flags from eflags/rflags
            try:
                eflags = state.regs.eflags if 'AMD64' not in arch_name else state.regs.rflags
                if state.solver.symbolic(eflags):
                    # Try to evaluate anyway
                    try:
                        flags_val = state.solver.eval(eflags)
                    except Exception:
                        flags_val = None
                else:
                    flags_val = state.solver.eval(eflags)

                if flags_val is not None:
                    reg_state.flags = {
                        'cf': bool(flags_val & 0x0001),
                        'pf': bool(flags_val & 0x0004),
                        'af': bool(flags_val & 0x0010),
                        'zf': bool(flags_val & 0x0040),
                        'sf': bool(flags_val & 0x0080),
                        'tf': bool(flags_val & 0x0100),
                        'df': bool(flags_val & 0x0400),
                        'of': bool(flags_val & 0x0800),
                    }
            except Exception:
                pass

        elif 'AARCH64' in arch_name or 'ARM' in arch_name:
            # ARM64 / ARM32 registers
            if 'AARCH64' in arch_name:
                # ARM64: x0-x30, sp, pc
                arm_regs = [f'x{i}' for i in range(31)] + ['sp', 'pc', 'lr']
            else:
                # ARM32: r0-r15
                arm_regs = [f'r{i}' for i in range(16)] + ['sp', 'pc', 'lr']

            for reg_name in arm_regs:
                value, is_symbolic = get_reg_value(reg_name)
                if value is not None:
                    reg_state.registers[reg_name] = value
                    if is_symbolic:
                        reg_state.symbolic_regs.append(reg_name)

            # Get PC and SP
            reg_state.pc = reg_state.registers.get('pc')
            reg_state.sp = reg_state.registers.get('sp')

            # ARM condition flags (NZCV)
            try:
                # Try to get CPSR/PSTATE
                for flag_reg in ['cpsr', 'pstate', 'nzcv']:
                    try:
                        flags_reg = getattr(state.regs, flag_reg)
                        if state.solver.symbolic(flags_reg):
                            try:
                                flags_val = state.solver.eval(flags_reg)
                            except Exception:
                                flags_val = None
                        else:
                            flags_val = state.solver.eval(flags_reg)

                        if flags_val is not None:
                            reg_state.flags = {
                                'n': bool(flags_val & (1 << 31)),  # Negative
                                'z': bool(flags_val & (1 << 30)),  # Zero
                                'c': bool(flags_val & (1 << 29)),  # Carry
                                'v': bool(flags_val & (1 << 28)),  # Overflow
                            }
                            break
                    except AttributeError:
                        continue
            except Exception:
                pass

        else:
            # Generic: try common register names
            for reg_name in ['pc', 'sp', 'ra', 'gp', 'fp']:
                value, is_symbolic = get_reg_value(reg_name)
                if value is not None:
                    reg_state.registers[reg_name] = value
                    if is_symbolic:
                        reg_state.symbolic_regs.append(reg_name)

            reg_state.pc = reg_state.registers.get('pc')
            reg_state.sp = reg_state.registers.get('sp')

        return reg_state

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        # Convert int values to hex strings for readability
        def format_value(v):
            if isinstance(v, int):
                return f"0x{v:x}"
            return v

        return {
            'arch': self.arch,
            'pc': format_value(self.pc),
            'sp': format_value(self.sp),
            'registers': {k: format_value(v) for k, v in self.registers.items()},
            'flags': self.flags,
            'symbolic_regs': self.symbolic_regs,
        }


@dataclass
class Instruction:
    """Represents a single instruction."""
    addr: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes

    def __str__(self) -> str:
        return f"0x{self.addr:x}: {self.mnemonic} {self.op_str}"


@dataclass
class CompleteCFGNode:
    """A CFG node with complete state information."""
    addr: int
    size: int

    # Instructions in this basic block
    instructions: list[Instruction] = field(default_factory=list)

    # Function this node belongs to (if known)
    function_addr: int | None = None
    function_name: str | None = None

    # Register states at entry and exit
    entry_state: RegisterState | None = None
    exit_states: list[RegisterState] = field(default_factory=list)

    # Path constraints to reach this node
    constraints: list[str] = field(default_factory=list)

    # Memory accesses in this block
    memory_reads: list[tuple[int, int]] = field(default_factory=list)   # (addr, size)
    memory_writes: list[tuple[int, int]] = field(default_factory=list)  # (addr, size)

    # Dynamic loading info
    loads_library: str | None = None
    resolves_symbol: str | None = None

    # Node metadata
    is_entry: bool = False
    is_exit: bool = False
    is_call_target: bool = False
    is_dynamic_target: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'addr': self.addr,
            'size': self.size,
            'instructions': [str(i) for i in self.instructions],
            'function_addr': self.function_addr,
            'function_name': self.function_name,
            'entry_state': self.entry_state.to_dict() if self.entry_state else None,
            'exit_states': [s.to_dict() for s in self.exit_states],
            'constraints': self.constraints,
            'memory_reads': self.memory_reads,
            'memory_writes': self.memory_writes,
            'loads_library': self.loads_library,
            'resolves_symbol': self.resolves_symbol,
            'is_entry': self.is_entry,
            'is_exit': self.is_exit,
            'is_call_target': self.is_call_target,
            'is_dynamic_target': self.is_dynamic_target,
        }


@dataclass
class CompleteCFGEdge:
    """A CFG edge with metadata."""
    src_addr: int
    dst_addr: int
    edge_type: EdgeType

    # Condition for conditional branches
    condition: str | None = None

    # For indirect edges, the resolution method
    resolution_method: str | None = None

    # Confidence (1.0 = certain, <1.0 = speculative)
    confidence: float = 1.0

    # For dynamic edges
    library_loaded: str | None = None
    symbol_resolved: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'src_addr': self.src_addr,
            'dst_addr': self.dst_addr,
            'edge_type': self.edge_type.name,
            'condition': self.condition,
            'resolution_method': self.resolution_method,
            'confidence': self.confidence,
            'library_loaded': self.library_loaded,
            'symbol_resolved': self.symbol_resolved,
        }


@dataclass
class CompleteCFG:
    """Complete CFG with all nodes, edges, and state information."""
    nodes: dict[int, CompleteCFGNode] = field(default_factory=dict)  # addr -> node
    edges: list[CompleteCFGEdge] = field(default_factory=list)

    # Function information
    functions: dict[int, str] = field(default_factory=dict)  # addr -> name

    # Dynamic discoveries
    discovered_libraries: list[str] = field(default_factory=list)
    resolved_symbols: dict[str, int] = field(default_factory=dict)  # symbol -> addr

    # Statistics
    total_instructions: int = 0
    total_basic_blocks: int = 0
    static_edges: int = 0
    dynamic_edges: int = 0

    def add_node(self, node: CompleteCFGNode) -> None:
        """Add a node to the CFG."""
        self.nodes[node.addr] = node
        self.total_basic_blocks += 1
        self.total_instructions += len(node.instructions)

    def add_edge(self, edge: CompleteCFGEdge) -> None:
        """Add an edge to the CFG."""
        self.edges.append(edge)
        if edge.edge_type in (EdgeType.DYNAMIC_LOAD, EdgeType.INDIRECT_JUMP,
                              EdgeType.INDIRECT_CALL, EdgeType.VTABLE_CALL):
            self.dynamic_edges += 1
        else:
            self.static_edges += 1

    def get_successors(self, addr: int) -> list[int]:
        """Get successor addresses for a node."""
        return [e.dst_addr for e in self.edges if e.src_addr == addr]

    def get_predecessors(self, addr: int) -> list[int]:
        """Get predecessor addresses for a node."""
        return [e.src_addr for e in self.edges if e.dst_addr == addr]

    def get_node(self, addr: int) -> CompleteCFGNode | None:
        """Get node at address."""
        return self.nodes.get(addr)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'nodes': {hex(addr): node.to_dict() for addr, node in self.nodes.items()},
            'edges': [e.to_dict() for e in self.edges],
            'functions': {hex(addr): name for addr, name in self.functions.items()},
            'discovered_libraries': self.discovered_libraries,
            'resolved_symbols': self.resolved_symbols,
            'statistics': {
                'total_instructions': self.total_instructions,
                'total_basic_blocks': self.total_basic_blocks,
                'static_edges': self.static_edges,
                'dynamic_edges': self.dynamic_edges,
            }
        }

    def export_json(self, path: str) -> None:
        """Export CFG to JSON file."""
        import json
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def export_dot(self, path: str) -> None:
        """Export CFG to DOT format for visualization."""
        with open(path, 'w') as f:
            f.write("digraph CFG {\n")
            f.write("  node [shape=box, fontname=monospace, fontsize=10];\n")
            f.write("  edge [fontname=monospace, fontsize=8];\n\n")

            # Write nodes
            for addr, node in self.nodes.items():
                label = f"0x{addr:x}"
                if node.function_name:
                    label = f"{node.function_name}\\n{label}"
                if node.instructions:
                    # Show first few instructions
                    for instr in node.instructions[:3]:
                        label += f"\\n{instr.mnemonic} {instr.op_str}"
                    if len(node.instructions) > 3:
                        label += f"\\n... ({len(node.instructions) - 3} more)"

                color = "black"
                if node.is_entry:
                    color = "green"
                elif node.is_dynamic_target:
                    color = "blue"
                elif node.loads_library:
                    color = "red"

                f.write(f'  node_{addr:x} [label="{label}", color={color}];\n')

            # Write edges
            for edge in self.edges:
                style = "solid"
                color = "black"
                label = ""

                if edge.edge_type == EdgeType.CONDITIONAL_TRUE:
                    color = "green"
                    label = "T"
                elif edge.edge_type == EdgeType.CONDITIONAL_FALSE:
                    color = "red"
                    label = "F"
                elif edge.edge_type in (EdgeType.INDIRECT_JUMP, EdgeType.INDIRECT_CALL):
                    style = "dashed"
                    color = "blue"
                elif edge.edge_type == EdgeType.DYNAMIC_LOAD:
                    style = "dotted"
                    color = "purple"
                    if edge.library_loaded:
                        label = edge.library_loaded
                elif edge.edge_type == EdgeType.RETURN:
                    style = "dashed"
                    color = "gray"

                f.write(f'  node_{edge.src_addr:x} -> node_{edge.dst_addr:x} '
                       f'[style={style}, color={color}')
                if label:
                    f.write(f', label="{label}"')
                f.write('];\n')

            f.write("}\n")
