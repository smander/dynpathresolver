"""
LibraryLoadEvent - Captures complete state at dynamic library load points.

This module provides detailed snapshots of:
- Register values (all general-purpose registers)
- CPU flags (ZF, CF, SF, OF, etc.)
- Stack state
- Memory regions
- Path constraints
- Call context
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dynpathresolver.config.enums import LoadingMethod

if TYPE_CHECKING:
    import angr
    import claripy

log = logging.getLogger(__name__)


@dataclass
class RegisterSnapshot:
    """
    Complete register snapshot at a specific point.

    Captures all registers with both concrete values (when available)
    and symbolic information.
    """
    # Architecture name (AMD64, AARCH64, etc.)
    arch: str = "unknown"

    # All register values: register_name -> (concrete_value, is_symbolic)
    registers: dict[str, tuple[int | str, bool]] = field(default_factory=dict)

    # CPU flags
    flags: dict[str, bool | None] = field(default_factory=dict)

    # Program counter
    pc: int | None = None

    # Stack pointer
    sp: int | None = None

    # Base pointer / frame pointer
    bp: int | None = None

    @classmethod
    def from_state(cls, state: "angr.SimState") -> "RegisterSnapshot":
        """Extract complete register snapshot from angr state."""
        snapshot = cls()
        snapshot.arch = state.arch.name

        def get_reg(reg_name: str) -> tuple[int | str, bool] | None:
            """Get register value and symbolic status."""
            try:
                reg = getattr(state.regs, reg_name)
                is_symbolic = state.solver.symbolic(reg)
                try:
                    value = state.solver.eval(reg)
                    return (value, is_symbolic)
                except Exception:
                    return (str(reg), is_symbolic)
            except (AttributeError, Exception):
                return None

        arch_name = state.arch.name.upper()

        if 'AMD64' in arch_name or 'X86_64' in arch_name:
            # x86_64 registers
            for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']:
                val = get_reg(reg)
                if val:
                    snapshot.registers[reg] = val

            snapshot.pc = snapshot.registers.get('rip', (None, False))[0] if 'rip' in snapshot.registers else None
            snapshot.sp = snapshot.registers.get('rsp', (None, False))[0] if 'rsp' in snapshot.registers else None
            snapshot.bp = snapshot.registers.get('rbp', (None, False))[0] if 'rbp' in snapshot.registers else None

            # x86_64 flags
            try:
                rflags = state.regs.rflags
                flags_val = state.solver.eval(rflags)
                snapshot.flags = {
                    'CF': bool(flags_val & 0x0001),
                    'PF': bool(flags_val & 0x0004),
                    'AF': bool(flags_val & 0x0010),
                    'ZF': bool(flags_val & 0x0040),
                    'SF': bool(flags_val & 0x0080),
                    'TF': bool(flags_val & 0x0100),
                    'IF': bool(flags_val & 0x0200),
                    'DF': bool(flags_val & 0x0400),
                    'OF': bool(flags_val & 0x0800),
                }
            except Exception:
                pass

        elif 'X86' in arch_name:
            # 32-bit x86
            for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']:
                val = get_reg(reg)
                if val:
                    snapshot.registers[reg] = val

            snapshot.pc = snapshot.registers.get('eip', (None, False))[0] if 'eip' in snapshot.registers else None
            snapshot.sp = snapshot.registers.get('esp', (None, False))[0] if 'esp' in snapshot.registers else None
            snapshot.bp = snapshot.registers.get('ebp', (None, False))[0] if 'ebp' in snapshot.registers else None

        elif 'AARCH64' in arch_name:
            # ARM64 registers
            for i in range(31):
                val = get_reg(f'x{i}')
                if val:
                    snapshot.registers[f'x{i}'] = val

            for reg in ['sp', 'pc', 'lr']:
                val = get_reg(reg)
                if val:
                    snapshot.registers[reg] = val

            snapshot.pc = snapshot.registers.get('pc', (None, False))[0] if 'pc' in snapshot.registers else None
            snapshot.sp = snapshot.registers.get('sp', (None, False))[0] if 'sp' in snapshot.registers else None
            snapshot.bp = snapshot.registers.get('x29', (None, False))[0] if 'x29' in snapshot.registers else None  # FP

            # ARM64 NZCV flags
            try:
                # NZCV is in PSTATE, often accessed via special register
                for flag_reg in ['n', 'z', 'c', 'v']:
                    try:
                        flag = getattr(state.regs, flag_reg)
                        snapshot.flags[flag_reg.upper()] = bool(state.solver.eval(flag))
                    except Exception:
                        pass
            except Exception:
                pass

        return snapshot

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'arch': self.arch,
            'pc': f'0x{self.pc:x}' if isinstance(self.pc, int) else self.pc,
            'sp': f'0x{self.sp:x}' if isinstance(self.sp, int) else self.sp,
            'bp': f'0x{self.bp:x}' if isinstance(self.bp, int) else self.bp,
            'registers': {
                k: {'value': f'0x{v[0]:x}' if isinstance(v[0], int) else str(v[0]),
                    'symbolic': v[1]}
                for k, v in self.registers.items()
            },
            'flags': self.flags,
        }


@dataclass
class MemoryRegion:
    """Memory region information."""
    start: int
    end: int
    permissions: str  # e.g., "rwx", "r-x"
    name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            'start': f'0x{self.start:x}',
            'end': f'0x{self.end:x}',
            'size': self.end - self.start,
            'permissions': self.permissions,
            'name': self.name,
        }


@dataclass
class LibraryLoadEvent:
    """
    Complete snapshot of state when a dynamic library is loaded.

    Captures everything needed to understand the loading context:
    - What library was loaded and how
    - Complete register state at the moment of loading
    - Memory layout
    - Symbolic constraints that led to this path
    - Call stack
    """

    # Library information
    library_path: str
    library_name: str = ""
    loading_method: LoadingMethod = LoadingMethod.DLOPEN
    handle: int | None = None
    base_address: int | None = None

    # Address where loading was initiated (e.g., dlopen call site)
    call_site: int | None = None

    # Complete register state at load time
    register_snapshot: RegisterSnapshot | None = None

    # Function arguments (for dlopen: path, flags)
    arguments: dict[str, Any] = field(default_factory=dict)

    # Symbols resolved from this library
    resolved_symbols: dict[str, int] = field(default_factory=dict)

    # Memory regions after load
    memory_regions: list[MemoryRegion] = field(default_factory=list)

    # Path constraints (serialized)
    constraints: list[str] = field(default_factory=list)

    # Call stack (list of return addresses)
    call_stack: list[int] = field(default_factory=list)

    # Timestamp (step number in symbolic execution)
    step_number: int = 0

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dlopen(
        cls,
        state: "angr.SimState",
        library_path: str,
        handle: int | None = None,
        flags: int = 0,
    ) -> "LibraryLoadEvent":
        """Create event from dlopen() call."""
        import os

        event = cls(
            library_path=library_path,
            library_name=os.path.basename(library_path),
            loading_method=LoadingMethod.DLOPEN,
            handle=handle,
            call_site=state.addr,
            register_snapshot=RegisterSnapshot.from_state(state),
            arguments={'path': library_path, 'flags': flags},
        )

        # Extract constraints
        try:
            for c in state.solver.constraints[:20]:  # Limit to 20
                event.constraints.append(str(c)[:200])  # Truncate long constraints
        except Exception:
            pass

        # Extract call stack
        try:
            if hasattr(state, 'callstack'):
                for frame in state.callstack:
                    if hasattr(frame, 'ret_addr'):
                        event.call_stack.append(frame.ret_addr)
        except Exception:
            pass

        return event

    @classmethod
    def from_mmap(
        cls,
        state: "angr.SimState",
        addr: int,
        length: int,
        prot: int,
        flags: int,
        fd: int = -1,
    ) -> "LibraryLoadEvent":
        """Create event from mmap() with PROT_EXEC."""
        event = cls(
            library_path=f"mmap@0x{addr:x}",
            library_name=f"mmap_region_{addr:x}",
            loading_method=LoadingMethod.MMAP_EXEC,
            base_address=addr,
            call_site=state.addr,
            register_snapshot=RegisterSnapshot.from_state(state),
            arguments={
                'addr': f'0x{addr:x}',
                'length': length,
                'prot': prot,
                'flags': flags,
                'fd': fd,
            },
        )
        return event

    @classmethod
    def from_memfd(
        cls,
        state: "angr.SimState",
        name: str,
        fd: int,
    ) -> "LibraryLoadEvent":
        """Create event from memfd_create()."""
        event = cls(
            library_path=f"/proc/self/fd/{fd}",
            library_name=name,
            loading_method=LoadingMethod.MEMFD_CREATE,
            call_site=state.addr,
            register_snapshot=RegisterSnapshot.from_state(state),
            arguments={'name': name, 'fd': fd},
        )
        return event

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            'library': {
                'path': self.library_path,
                'name': self.library_name,
                'loading_method': self.loading_method.name,
                'handle': f'0x{self.handle:x}' if self.handle else None,
                'base_address': f'0x{self.base_address:x}' if self.base_address else None,
            },
            'call_site': f'0x{self.call_site:x}' if self.call_site else None,
            'registers': self.register_snapshot.to_dict() if self.register_snapshot else None,
            'arguments': self.arguments,
            'resolved_symbols': {k: f'0x{v:x}' for k, v in self.resolved_symbols.items()},
            'memory_regions': [r.to_dict() for r in self.memory_regions],
            'constraints': self.constraints,
            'call_stack': [f'0x{addr:x}' for addr in self.call_stack],
            'step_number': self.step_number,
            'metadata': self.metadata,
        }


@dataclass
class LibraryLoadLog:
    """Collection of all library load events during analysis."""

    events: list[LibraryLoadEvent] = field(default_factory=list)

    # Summary statistics
    total_libraries: int = 0
    unique_libraries: set[str] = field(default_factory=set)

    def add_event(self, event: LibraryLoadEvent) -> None:
        """Add a load event to the log."""
        self.events.append(event)
        self.total_libraries += 1
        self.unique_libraries.add(event.library_path)

    def get_events_for_library(self, library_name: str) -> list[LibraryLoadEvent]:
        """Get all events for a specific library."""
        return [e for e in self.events if library_name in e.library_path]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'summary': {
                'total_load_events': self.total_libraries,
                'unique_libraries': len(self.unique_libraries),
                'libraries': list(self.unique_libraries),
            },
            'events': [e.to_dict() for e in self.events],
        }

    def export_json(self, path: str) -> None:
        """Export to JSON file."""
        import json
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
