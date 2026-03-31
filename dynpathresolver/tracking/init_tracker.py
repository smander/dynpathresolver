"""
Constructor/Destructor (.init/.fini) tracking.

This module tracks library initialization and finalization functions
(.init, .fini, .init_array, .fini_array) which can be used for
code execution during library loading/unloading.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import (
    DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ,
    DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
)

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class InitFunction:
    """Represents an initialization/finalization function."""

    addr: int
    section: str  # '.init', '.init_array', '.fini', '.fini_array', '.preinit_array'
    library: str
    index: int = 0  # Index in array (for *_array sections)
    executed: bool = False
    executed_at_step: int | None = None


@dataclass
class InitExecution:
    """Represents an init/fini function execution event."""

    function_addr: int
    section: str
    library: str
    state_addr: int
    step: int


class InitFiniTracker:
    """
    Tracks constructor/destructor functions in ELF binaries.

    This class:
    1. Scans loaded objects for .init, .fini, .init_array, .fini_array
    2. Tracks execution of these functions
    3. Detects suspicious initialization patterns
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Discovered functions
        self.init_functions: list[InitFunction] = []
        self.fini_functions: list[InitFunction] = []

        # Execution tracking
        self.executions: list[InitExecution] = []

        # Address lookup
        self._addr_to_init: dict[int, InitFunction] = {}

    def scan_all_objects(self) -> tuple[list[InitFunction], list[InitFunction]]:
        """
        Scan all loaded objects for init/fini functions.

        Returns:
            Tuple of (init_functions, fini_functions)
        """
        self.init_functions.clear()
        self.fini_functions.clear()
        self._addr_to_init.clear()

        for obj in self.project.loader.all_objects:
            self._scan_object(obj)

        log.info(f"Found {len(self.init_functions)} init functions, "
                f"{len(self.fini_functions)} fini functions")

        return self.init_functions.copy(), self.fini_functions.copy()

    def _scan_object(self, obj) -> None:
        """Scan a single loaded object for init/fini functions."""
        obj_name = obj.provides if hasattr(obj, 'provides') else str(obj)

        # Skip objects without ELF info
        if not hasattr(obj, 'reader'):
            return

        try:
            self._scan_init_fini_sections(obj, obj_name)
            self._scan_init_fini_arrays(obj, obj_name)
        except Exception as e:
            log.debug(f"Error scanning {obj_name}: {e}")

    def _scan_init_fini_sections(self, obj, obj_name: str) -> None:
        """Scan for .init and .fini sections."""
        # Check for .init section
        if hasattr(obj, 'sections'):
            for section in obj.sections:
                if section.name == '.init':
                    func = InitFunction(
                        addr=section.vaddr + obj.mapped_base,
                        section='.init',
                        library=obj_name,
                    )
                    self.init_functions.append(func)
                    self._addr_to_init[func.addr] = func
                    log.debug(f".init at 0x{func.addr:x} in {obj_name}")

                elif section.name == '.fini':
                    func = InitFunction(
                        addr=section.vaddr + obj.mapped_base,
                        section='.fini',
                        library=obj_name,
                    )
                    self.fini_functions.append(func)
                    self._addr_to_init[func.addr] = func
                    log.debug(f".fini at 0x{func.addr:x} in {obj_name}")

    def _scan_init_fini_arrays(self, obj, obj_name: str) -> None:
        """Scan for .init_array and .fini_array entries."""
        # Look for dynamic entries
        if not hasattr(obj, 'reader') or not hasattr(obj.reader, 'iter_sections'):
            return

        try:
            # Find dynamic segment
            for segment in obj.reader.iter_segments():
                if segment.header.p_type != 'PT_DYNAMIC':
                    continue

                dynamic = segment
                base_addr = obj.mapped_base

                init_array_addr = None
                init_array_size = None
                fini_array_addr = None
                fini_array_size = None
                preinit_array_addr = None
                preinit_array_size = None

                # Parse dynamic entries
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_INIT_ARRAY':
                        init_array_addr = tag.entry.d_val
                    elif tag.entry.d_tag == 'DT_INIT_ARRAYSZ':
                        init_array_size = tag.entry.d_val
                    elif tag.entry.d_tag == 'DT_FINI_ARRAY':
                        fini_array_addr = tag.entry.d_val
                    elif tag.entry.d_tag == 'DT_FINI_ARRAYSZ':
                        fini_array_size = tag.entry.d_val
                    elif tag.entry.d_tag == 'DT_PREINIT_ARRAY':
                        preinit_array_addr = tag.entry.d_val
                    elif tag.entry.d_tag == 'DT_PREINIT_ARRAYSZ':
                        preinit_array_size = tag.entry.d_val

                ptr_size = 8 if obj.arch.bits == 64 else 4

                # Parse init_array
                if init_array_addr and init_array_size:
                    self._parse_function_array(
                        obj, obj_name, init_array_addr + base_addr,
                        init_array_size, ptr_size, '.init_array', is_init=True
                    )

                # Parse fini_array
                if fini_array_addr and fini_array_size:
                    self._parse_function_array(
                        obj, obj_name, fini_array_addr + base_addr,
                        fini_array_size, ptr_size, '.fini_array', is_init=False
                    )

                # Parse preinit_array
                if preinit_array_addr and preinit_array_size:
                    self._parse_function_array(
                        obj, obj_name, preinit_array_addr + base_addr,
                        preinit_array_size, ptr_size, '.preinit_array', is_init=True
                    )

        except Exception as e:
            log.debug(f"Error parsing dynamic arrays for {obj_name}: {e}")

    def _parse_function_array(self, obj, obj_name: str, array_addr: int,
                              array_size: int, ptr_size: int,
                              section: str, is_init: bool) -> None:
        """Parse a function pointer array (.init_array, .fini_array, etc.)."""
        num_entries = array_size // ptr_size

        for i in range(num_entries):
            entry_addr = array_addr + (i * ptr_size)

            # Read function pointer from binary
            try:
                # Read from the backend storage
                func_addr = obj.memory.unpack_word(
                    entry_addr - obj.mapped_base,
                    size=ptr_size
                )

                if func_addr == 0 or func_addr == 0xffffffffffffffff:
                    continue

                # Adjust for PIE if needed
                if obj.pic and func_addr < obj.mapped_base:
                    func_addr += obj.mapped_base

                func = InitFunction(
                    addr=func_addr,
                    section=section,
                    library=obj_name,
                    index=i,
                )

                if is_init:
                    self.init_functions.append(func)
                else:
                    self.fini_functions.append(func)

                self._addr_to_init[func_addr] = func
                log.debug(f"{section}[{i}] at 0x{func_addr:x} in {obj_name}")

            except Exception as e:
                log.debug(f"Error reading {section} entry {i}: {e}")

    def is_init_function(self, addr: int) -> bool:
        """Check if an address is a known init/fini function."""
        return addr in self._addr_to_init

    def get_init_function(self, addr: int) -> InitFunction | None:
        """Get the InitFunction for an address."""
        return self._addr_to_init.get(addr)

    def record_execution(self, state: "angr.SimState", addr: int) -> InitExecution | None:
        """
        Record execution of an init/fini function.

        Args:
            state: Current symbolic state
            addr: Address being executed

        Returns:
            The recorded InitExecution, or None if not a known init/fini
        """
        func = self._addr_to_init.get(addr)
        if not func:
            return None

        step = state.history.depth if state.history else 0

        # Mark as executed
        func.executed = True
        func.executed_at_step = step

        execution = InitExecution(
            function_addr=addr,
            section=func.section,
            library=func.library,
            state_addr=state.addr,
            step=step,
        )
        self.executions.append(execution)

        log.info(f"Executed {func.section} function at 0x{addr:x} from {func.library}")

        return execution

    # === Query Methods ===

    def get_init_functions(self, library: str | None = None) -> list[InitFunction]:
        """Get init functions, optionally filtered by library."""
        if library:
            return [f for f in self.init_functions if f.library == library]
        return self.init_functions.copy()

    def get_fini_functions(self, library: str | None = None) -> list[InitFunction]:
        """Get fini functions, optionally filtered by library."""
        if library:
            return [f for f in self.fini_functions if f.library == library]
        return self.fini_functions.copy()

    def get_unexecuted_inits(self) -> list[InitFunction]:
        """Get init functions that haven't been executed."""
        return [f for f in self.init_functions if not f.executed]

    def get_executions(self) -> list[InitExecution]:
        """Get all execution events."""
        return self.executions.copy()

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        executed_inits = sum(1 for f in self.init_functions if f.executed)
        executed_finis = sum(1 for f in self.fini_functions if f.executed)

        return {
            'total_init_functions': len(self.init_functions),
            'total_fini_functions': len(self.fini_functions),
            'executed_inits': executed_inits,
            'executed_finis': executed_finis,
            'total_executions': len(self.executions),
        }

    def reset(self) -> None:
        """Reset execution tracking (keeps discovered functions)."""
        for func in self.init_functions:
            func.executed = False
            func.executed_at_step = None
        for func in self.fini_functions:
            func.executed = False
            func.executed_at_step = None
        self.executions.clear()
