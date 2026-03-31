"""
SimProcedure for dlsym() that resolves symbols in dynamically loaded libraries.

This replaces angr's default dlsym SimProcedure to:
1. Look up the library from the handle
2. Find the symbol in that library
3. Return the actual address of the symbol
"""

import logging

import angr
import claripy

from dynpathresolver.config.constants import RTLD_DEFAULT, RTLD_NEXT

log = logging.getLogger(__name__)


class DynDlsym(angr.SimProcedure):
    """
    SimProcedure for dlsym that resolves symbols to actual addresses.

    This procedure:
    1. Gets the library handle and symbol name
    2. Looks up the library in our loaded libraries
    3. Finds the symbol in the library's symbol table
    4. Returns the symbol's actual address
    """

    # Class-level tracking of resolved symbols: (handle, name) -> address
    resolved_symbols: dict[tuple[int, str], int] = {}

    # Class-level reference to technique (set by DynPathResolver)
    technique: "object | None" = None

    @classmethod
    def reset(cls):
        """Reset class-level state between analyses."""
        cls.resolved_symbols = {}

    def _get_technique(self):
        """Get technique from state globals (falls back to class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    @property
    def loaded_libraries(self):
        """Get loaded libraries from state globals (falls back to DynDlopen class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_loaded_libraries', {})
        from .dlopen import DynDlopen
        return DynDlopen.loaded_libraries

    def run(self, handle, symbol_ptr):
        """
        Simulate dlsym(handle, symbol).

        Args:
            handle: Library handle from dlopen (or RTLD_DEFAULT/RTLD_NEXT)
            symbol: Pointer to symbol name string

        Returns:
            Address of the symbol, or NULL (0) if not found
        """
        # Get symbol name
        symbol_name = self._get_symbol_name(symbol_ptr)

        if symbol_name is None:
            log.warning("dlsym: Could not resolve symbol name (symbolic)")
            return claripy.BVS("dlsym_result", self.state.arch.bits)

        log.info(f"dlsym: Looking up symbol '{symbol_name}'")

        # Concretize handle if possible
        if self.state.solver.symbolic(handle):
            if self.state.solver.satisfiable():
                handle_val = self.state.solver.eval(handle)
            else:
                log.warning("dlsym: Symbolic handle, cannot resolve")
                return claripy.BVS("dlsym_result", self.state.arch.bits)
        else:
            handle_val = self.state.solver.eval(handle)

        # Look up the symbol
        symbol_addr = self._find_symbol(handle_val, symbol_name)

        if symbol_addr is None:
            log.warning(f"dlsym: Symbol not found: {symbol_name}")
            return claripy.BVV(0, self.state.arch.bits)  # NULL

        log.info(f"dlsym: Resolved '{symbol_name}' to 0x{symbol_addr:x}")

        # Track the resolution in state.globals
        resolved = self.state.globals.get('dpr_resolved_symbols', {})
        resolved[(handle_val, symbol_name)] = symbol_addr
        self.state.globals['dpr_resolved_symbols'] = resolved

        return claripy.BVV(symbol_addr, self.state.arch.bits)

    def _get_symbol_name(self, symbol_ptr) -> str | None:
        """Extract symbol name string from memory."""
        if self.state.solver.symbolic(symbol_ptr):
            if self.state.solver.satisfiable():
                symbol_ptr = self.state.solver.eval(symbol_ptr)
            else:
                return None

        try:
            symbol_bytes = self.state.mem[symbol_ptr].string.concrete
            if isinstance(symbol_bytes, bytes):
                return symbol_bytes.decode('utf-8', errors='ignore')
            return str(symbol_bytes)
        except Exception as e:
            log.debug(f"dlsym: Error reading symbol string: {e}")
            return None

    def _find_symbol(self, handle: int, symbol_name: str) -> int | None:
        """Find a symbol in the specified library or all libraries."""
        # Handle special values
        if handle == 0:  # RTLD_DEFAULT - search all
            return self._search_all_libraries(symbol_name)

        # Handle might be negative for RTLD_NEXT
        if handle > 0x7FFFFFFF:  # Treat as RTLD_NEXT on 32-bit or signed
            return self._search_all_libraries(symbol_name)

        # Look up specific library
        lib = self.loaded_libraries.get(handle)

        if lib is None:
            # Handle might be the base address directly
            for h, loaded_lib in self.loaded_libraries.items():
                if hasattr(loaded_lib, 'mapped_base') and loaded_lib.mapped_base == handle:
                    lib = loaded_lib
                    break

        if lib is None:
            log.debug(f"dlsym: Unknown handle 0x{handle:x}, searching all libraries")
            return self._search_all_libraries(symbol_name)

        # Search in the specific library
        return self._find_symbol_in_lib(lib, symbol_name)

    def _search_all_libraries(self, symbol_name: str) -> int | None:
        """Search for symbol in all loaded libraries."""
        # First check dynamically loaded libraries
        for lib in self.loaded_libraries.values():
            addr = self._find_symbol_in_lib(lib, symbol_name)
            if addr is not None:
                return addr

        # Then check project's statically loaded objects
        project = self.state.project
        for obj in project.loader.all_objects:
            addr = self._find_symbol_in_lib(obj, symbol_name)
            if addr is not None:
                return addr

        # Check if it's a hooked function (e.g. dlopen, dlsym, dlclose)
        # These are hooked by DynPathResolver but not present as real symbols.
        # When a binary resolves dl* via dlsym(RTLD_DEFAULT, "dlopen"), the
        # symbol may not exist in any CLE object. We allocate a synthetic
        # address and hook it with our SimProcedure.
        HOOKED_FUNCTIONS = {
            'dlopen', 'dlsym', 'dlclose', 'dlmopen', 'dlvsym',
            'dladdr', 'dlinfo', 'dlerror',
        }
        if symbol_name in HOOKED_FUNCTIONS:
            # First check if it's already a known symbol
            sym = project.loader.find_symbol(symbol_name)
            if sym:
                return sym.rebased_addr
            # Check angr's hooked procedures directly
            for addr, hook in project._sim_procedures.items():
                hook_name = getattr(hook, 'display_name', type(hook).__name__)
                if hook_name == symbol_name or hook_name == f'Dyn{symbol_name.capitalize()}':
                    return addr
            # Symbol not found anywhere — create a synthetic hook
            return self._create_synthetic_hook(project, symbol_name)

        return None

    def _create_synthetic_hook(self, project, symbol_name: str) -> int | None:
        """Create a synthetic hook for a dl* function that isn't in any CLE object."""
        from dynpathresolver.simprocedures import (
            DynDlopen, DynDlclose,
            DynDlmopen, DynDlvsym, DynDladdr, DynDlinfo, DynDlerror,
        )

        SIMPROC_MAP = {
            'dlopen': DynDlopen,
            'dlsym': DynDlsym,
            'dlclose': DynDlclose,
            'dlmopen': DynDlmopen,
            'dlvsym': DynDlvsym,
            'dladdr': DynDladdr,
            'dlinfo': DynDlinfo,
            'dlerror': DynDlerror,
        }

        simproc_class = SIMPROC_MAP.get(symbol_name)
        if simproc_class is None:
            return None

        # Allocate a synthetic address in the extern region
        try:
            extern = project.loader.extern_object
            if extern:
                addr = extern.allocate()
                project.hook(addr, simproc_class(), replace=True)
                log.info(f"dlsym: Created synthetic hook for {symbol_name} at 0x{addr:x}")
                return addr
        except Exception as e:
            log.debug(f"dlsym: Failed to create synthetic hook for {symbol_name}: {e}")

        return None

    def _find_symbol_in_lib(self, lib, symbol_name: str) -> int | None:
        """Find a symbol in a specific library."""
        try:
            # Try to get symbol from the library
            if hasattr(lib, 'get_symbol'):
                sym = lib.get_symbol(symbol_name)
                if sym is not None:
                    # Return rebased address
                    if hasattr(sym, 'rebased_addr'):
                        return sym.rebased_addr
                    elif hasattr(sym, 'linked_addr'):
                        base = getattr(lib, 'mapped_base', 0)
                        return base + sym.linked_addr

            # Try symbols dict
            if hasattr(lib, 'symbols'):
                if symbol_name in lib.symbols:
                    sym = lib.symbols[symbol_name]
                    if hasattr(sym, 'rebased_addr'):
                        return sym.rebased_addr

            # Try exported symbols
            if hasattr(lib, '_symbol_cache'):
                if symbol_name in lib._symbol_cache:
                    sym = lib._symbol_cache[symbol_name]
                    if hasattr(sym, 'rebased_addr'):
                        return sym.rebased_addr

        except Exception as e:
            log.debug(f"dlsym: Error searching {lib}: {e}")

        return None
