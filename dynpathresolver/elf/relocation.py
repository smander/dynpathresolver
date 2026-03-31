"""
Relocation processing for dynamically loaded libraries.

This module handles ELF relocations (REL/RELA) that occur during
dynamic library loading, including:
- R_X86_64_JUMP_SLOT: PLT lazy binding
- R_X86_64_GLOB_DAT: Global data references
- R_X86_64_RELATIVE: ASLR-relative relocations
- R_X86_64_64: Direct 64-bit relocations

For x86 (32-bit):
- R_386_JMP_SLOT
- R_386_GLOB_DAT
- R_386_RELATIVE
- R_386_32
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.enums import X86_64_Reloc, X86_Reloc

log = logging.getLogger(__name__)


@dataclass
class GOTEntry:
    """Represents an entry in the Global Offset Table."""
    address: int           # Address of GOT entry
    symbol_name: str       # Symbol this entry refers to
    resolved_addr: int     # Resolved symbol address (0 if unresolved)
    is_lazy: bool = True   # Whether this is a lazy-binding entry


@dataclass
class PLTEntry:
    """Represents an entry in the Procedure Linkage Table."""
    address: int           # Address of PLT stub
    got_entry: int         # Address of corresponding GOT entry
    symbol_name: str       # Symbol this entry calls
    is_bound: bool = False # Whether the symbol has been resolved


@dataclass
class RelocationEntry:
    """Represents a relocation entry."""
    offset: int            # Where to apply the relocation
    type: int              # Relocation type
    symbol_name: str       # Symbol name (empty for R_*_RELATIVE)
    addend: int = 0        # Addend for RELA relocations
    resolved: bool = False # Whether relocation has been applied


class GOTTracker:
    """
    Tracks Global Offset Table entries during analysis.

    The GOT contains addresses that are resolved at runtime by the
    dynamic linker. This class tracks GOT modifications to understand
    which symbols are being resolved.
    """

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.got_entries: dict[int, GOTEntry] = {}
        self.plt_entries: dict[int, PLTEntry] = {}
        self._initialized = False

    def initialize(self) -> None:
        """Scan the binary to find GOT and PLT entries."""
        if self._initialized:
            return

        for obj in self.project.loader.all_objects:
            self._scan_object(obj)

        self._initialized = True
        log.info(f"GOT Tracker: Found {len(self.got_entries)} GOT entries, "
                 f"{len(self.plt_entries)} PLT entries")

    def _scan_object(self, obj) -> None:
        """Scan a loaded object for GOT/PLT entries."""
        # Find .got and .got.plt sections
        got_section = None
        got_plt_section = None
        plt_section = None

        if hasattr(obj, 'sections'):
            for section in obj.sections:
                name = getattr(section, 'name', '')
                if name == '.got':
                    got_section = section
                elif name == '.got.plt':
                    got_plt_section = section
                elif name == '.plt':
                    plt_section = section

        # Get relocations
        if hasattr(obj, 'relocs'):
            for reloc in obj.relocs:
                self._process_relocation(obj, reloc)

    def _process_relocation(self, obj, reloc) -> None:
        """Process a relocation entry to track GOT/PLT."""
        if not hasattr(reloc, 'rebased_addr'):
            return

        addr = reloc.rebased_addr
        reloc_type = getattr(reloc, 'type', 0)
        symbol_name = ''

        if hasattr(reloc, 'symbol') and reloc.symbol:
            symbol_name = getattr(reloc.symbol, 'name', '')

        # Check if this is a JUMP_SLOT (PLT) relocation
        is_jump_slot = (
            reloc_type == X86_64_Reloc.R_X86_64_JUMP_SLOT or
            reloc_type == X86_Reloc.R_386_JMP_SLOT
        )

        # Check if this is a GLOB_DAT relocation
        is_glob_dat = (
            reloc_type == X86_64_Reloc.R_X86_64_GLOB_DAT or
            reloc_type == X86_Reloc.R_386_GLOB_DAT
        )

        if is_jump_slot or is_glob_dat:
            self.got_entries[addr] = GOTEntry(
                address=addr,
                symbol_name=symbol_name,
                resolved_addr=0,
                is_lazy=is_jump_slot
            )
            log.debug(f"GOT: Found entry at 0x{addr:x} for {symbol_name}")

    def update_got_entry(self, addr: int, resolved_addr: int) -> None:
        """Update a GOT entry with a resolved address."""
        if addr in self.got_entries:
            self.got_entries[addr].resolved_addr = resolved_addr
            log.debug(f"GOT: Updated 0x{addr:x} -> 0x{resolved_addr:x}")

    def get_got_entry(self, addr: int) -> GOTEntry | None:
        """Get the GOT entry at the given address."""
        return self.got_entries.get(addr)

    def is_got_address(self, addr: int) -> bool:
        """Check if an address is in the GOT."""
        return addr in self.got_entries


class RelocationProcessor:
    """
    Processes ELF relocations for dynamically loaded libraries.

    When a library is loaded via dlopen, its relocations need to be
    processed to resolve symbol references. This class handles that
    processing in the context of symbolic execution.
    """

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.got_tracker = GOTTracker(project)
        self.pending_relocations: list[RelocationEntry] = []
        self.processed_relocations: list[RelocationEntry] = []

    def initialize(self) -> None:
        """Initialize the relocation processor."""
        self.got_tracker.initialize()

    def process_library(self, lib, state: "angr.SimState") -> int:
        """
        Process all relocations for a newly loaded library.

        Args:
            lib: The loaded library object
            state: The current symbolic state

        Returns:
            Number of relocations processed
        """
        count = 0
        base_addr = getattr(lib, 'mapped_base', 0) or getattr(lib, 'min_addr', 0)

        if not hasattr(lib, 'relocs'):
            log.debug(f"Relocation: No relocs found for {lib}")
            return 0

        for reloc in lib.relocs:
            if self._process_relocation(lib, reloc, state, base_addr):
                count += 1

        log.info(f"Relocation: Processed {count} relocations for {lib}")
        return count

    def _process_relocation(
        self,
        lib,
        reloc,
        state: "angr.SimState",
        base_addr: int
    ) -> bool:
        """Process a single relocation."""
        import claripy

        if not hasattr(reloc, 'rebased_addr'):
            return False

        addr = reloc.rebased_addr
        reloc_type = getattr(reloc, 'type', 0)
        addend = getattr(reloc, 'addend', 0)

        symbol_name = ''
        symbol_addr = 0

        if hasattr(reloc, 'symbol') and reloc.symbol:
            symbol_name = getattr(reloc.symbol, 'name', '')
            # Try to resolve symbol
            symbol_addr = self._resolve_symbol(symbol_name)

        # Handle different relocation types
        arch_bits = self.project.arch.bits

        if reloc_type == X86_64_Reloc.R_X86_64_RELATIVE or reloc_type == X86_Reloc.R_386_RELATIVE:
            # R_*_RELATIVE: B + A (base + addend)
            value = base_addr + addend
            self._write_value(state, addr, value, arch_bits)
            log.debug(f"Relocation: RELATIVE at 0x{addr:x} = 0x{value:x}")
            return True

        elif reloc_type == X86_64_Reloc.R_X86_64_GLOB_DAT or reloc_type == X86_Reloc.R_386_GLOB_DAT:
            # R_*_GLOB_DAT: S (symbol address)
            if symbol_addr:
                self._write_value(state, addr, symbol_addr, arch_bits)
                self.got_tracker.update_got_entry(addr, symbol_addr)
                log.debug(f"Relocation: GLOB_DAT at 0x{addr:x} = {symbol_name}@0x{symbol_addr:x}")
                return True

        elif reloc_type == X86_64_Reloc.R_X86_64_JUMP_SLOT or reloc_type == X86_Reloc.R_386_JMP_SLOT:
            # R_*_JUMP_SLOT: S (symbol address) - for lazy binding
            if symbol_addr:
                self._write_value(state, addr, symbol_addr, arch_bits)
                self.got_tracker.update_got_entry(addr, symbol_addr)
                log.debug(f"Relocation: JUMP_SLOT at 0x{addr:x} = {symbol_name}@0x{symbol_addr:x}")
                return True

        elif reloc_type == X86_64_Reloc.R_X86_64_64:
            # R_X86_64_64: S + A
            if symbol_addr:
                value = symbol_addr + addend
                self._write_value(state, addr, value, 64)
                return True

        elif reloc_type == X86_Reloc.R_386_32:
            # R_386_32: S + A
            if symbol_addr:
                value = symbol_addr + addend
                self._write_value(state, addr, value, 32)
                return True

        # Record as pending if symbol not resolved
        if symbol_name and not symbol_addr:
            self.pending_relocations.append(RelocationEntry(
                offset=addr,
                type=reloc_type,
                symbol_name=symbol_name,
                addend=addend,
                resolved=False
            ))

        return False

    def _resolve_symbol(self, name: str) -> int | None:
        """Resolve a symbol to its address."""
        # Check dynamically loaded libraries
        from .simprocedures.dlopen import DynDlopen

        for lib in DynDlopen.loaded_libraries.values():
            if hasattr(lib, 'get_symbol'):
                sym = lib.get_symbol(name)
                if sym and hasattr(sym, 'rebased_addr'):
                    return sym.rebased_addr

        # Check project's statically loaded objects
        for obj in self.project.loader.all_objects:
            if hasattr(obj, 'get_symbol'):
                sym = obj.get_symbol(name)
                if sym and hasattr(sym, 'rebased_addr'):
                    return sym.rebased_addr

        # Check for hooked symbols
        sym = self.project.loader.find_symbol(name)
        if sym:
            return sym.rebased_addr

        return None

    def _write_value(
        self,
        state: "angr.SimState",
        addr: int,
        value: int,
        bits: int
    ) -> None:
        """Write a value to memory during relocation processing."""
        import claripy

        state.memory.store(
            addr,
            claripy.BVV(value, bits),
            endness=state.arch.memory_endness
        )

    def resolve_pending(self, state: "angr.SimState") -> int:
        """
        Try to resolve pending relocations.

        Called after new libraries are loaded to resolve previously
        unresolved symbol references.

        Returns:
            Number of newly resolved relocations
        """
        count = 0
        still_pending = []

        for reloc in self.pending_relocations:
            symbol_addr = self._resolve_symbol(reloc.symbol_name)

            if symbol_addr:
                # Determine value based on relocation type
                if reloc.type in (X86_64_Reloc.R_X86_64_64, X86_Reloc.R_386_32):
                    value = symbol_addr + reloc.addend
                else:
                    value = symbol_addr

                self._write_value(state, reloc.offset, value, self.project.arch.bits)
                reloc.resolved = True
                self.processed_relocations.append(reloc)
                count += 1
                log.debug(f"Relocation: Resolved pending {reloc.symbol_name}@0x{symbol_addr:x}")
            else:
                still_pending.append(reloc)

        self.pending_relocations = still_pending
        return count


class LazyBindingSimulator:
    """
    Simulates lazy binding (PLT/GOT) behavior.

    When a PLT entry is called for the first time, the dynamic linker
    resolves the symbol and updates the GOT entry. This class simulates
    that behavior.
    """

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.got_tracker = GOTTracker(project)
        self._first_call: set[int] = set()

    def initialize(self) -> None:
        """Initialize the lazy binding simulator."""
        self.got_tracker.initialize()

    def handle_plt_call(self, state: "angr.SimState", plt_addr: int) -> int | None:
        """
        Handle a call through PLT.

        Args:
            state: Current symbolic state
            plt_addr: Address of PLT entry being called

        Returns:
            Resolved function address, or None if not a PLT call
        """
        # Find the corresponding GOT entry
        got_entry = self._find_got_for_plt(plt_addr)
        if got_entry is None:
            return None

        # If first call, simulate resolution
        if plt_addr not in self._first_call:
            self._first_call.add(plt_addr)
            resolved = self._resolve_symbol(got_entry.symbol_name)

            if resolved:
                got_entry.resolved_addr = resolved
                # Update GOT in memory
                import claripy
                state.memory.store(
                    got_entry.address,
                    claripy.BVV(resolved, state.arch.bits),
                    endness=state.arch.memory_endness
                )
                log.info(f"Lazy binding: Resolved {got_entry.symbol_name} -> 0x{resolved:x}")

        return got_entry.resolved_addr if got_entry.resolved_addr else None

    def _find_got_for_plt(self, plt_addr: int) -> GOTEntry | None:
        """
        Find the GOT entry corresponding to a PLT entry by parsing the PLT stub.

        PLT stubs typically look like:
        - x86_64: jmp QWORD PTR [rip+offset]  -> GOT entry
        - x86:    jmp DWORD PTR [offset]      -> GOT entry
        """
        try:
            # Read PLT stub bytes
            plt_bytes = self.project.loader.memory.load(plt_addr, 16)

            # x86_64 PLT stub: ff 25 XX XX XX XX (jmp [rip+offset])
            if len(plt_bytes) >= 6 and plt_bytes[0:2] == b'\xff\x25':
                # RIP-relative addressing: offset is relative to next instruction
                import struct
                offset = struct.unpack('<i', plt_bytes[2:6])[0]
                got_addr = plt_addr + 6 + offset  # 6 = size of jmp instruction

                # Look up this GOT entry
                if got_addr in self.got_tracker.got_entries:
                    return self.got_tracker.got_entries[got_addr]

            # x86 PLT stub: ff 25 XX XX XX XX (jmp [absolute])
            if len(plt_bytes) >= 6 and plt_bytes[0:2] == b'\xff\x25':
                if self.project.arch.bits == 32:
                    import struct
                    got_addr = struct.unpack('<I', plt_bytes[2:6])[0]
                    if got_addr in self.got_tracker.got_entries:
                        return self.got_tracker.got_entries[got_addr]

            # Alternative: PLT with push + jmp pattern
            # ff 35 XX XX XX XX (push [got])
            # ff 25 XX XX XX XX (jmp [got])
            if len(plt_bytes) >= 6 and plt_bytes[0:2] == b'\xff\x35':
                # Skip to the jmp instruction
                if len(plt_bytes) >= 12 and plt_bytes[6:8] == b'\xff\x25':
                    import struct
                    if self.project.arch.bits == 64:
                        offset = struct.unpack('<i', plt_bytes[8:12])[0]
                        got_addr = plt_addr + 12 + offset
                    else:
                        got_addr = struct.unpack('<I', plt_bytes[8:12])[0]
                    if got_addr in self.got_tracker.got_entries:
                        return self.got_tracker.got_entries[got_addr]

        except Exception as e:
            log.debug(f"Could not parse PLT stub at 0x{plt_addr:x}: {e}")

        # Fallback: no entry found
        return None

    def _resolve_symbol(self, name: str) -> int | None:
        """Resolve a symbol to its address."""
        sym = self.project.loader.find_symbol(name)
        if sym:
            return sym.rebased_addr
        return None
