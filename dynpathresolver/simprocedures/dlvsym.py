"""
SimProcedure for dlvsym() - version-specific symbol resolution.

dlvsym is like dlsym but allows specifying a symbol version,
useful for resolving symbols that have multiple versions (symbol versioning).
"""

import logging

import angr
import claripy

from .dlsym import DynDlsym
from .dlerror import DlError

log = logging.getLogger(__name__)


class DynDlvsym(angr.SimProcedure):
    """
    SimProcedure for dlvsym that resolves versioned symbols.

    Signature: void* dlvsym(void *handle, const char *symbol, const char *version)

    This procedure:
    1. Gets the library handle and symbol name
    2. Attempts to find the symbol with the specified version
    3. Falls back to unversioned symbol if version not found
    4. Returns the symbol's actual address

    Note: Most ELF binaries don't use explicit versioning, so this
    typically falls back to regular dlsym behavior.
    """

    # Track versioned symbol resolutions
    resolved_versioned_symbols: dict[tuple[int, str, str], int] = {}

    @property
    def loaded_libraries(self):
        """Get loaded libraries from state globals (falls back to DynDlopen class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_loaded_libraries', {})
        from .dlopen import DynDlopen
        return DynDlopen.loaded_libraries

    def run(self, handle, symbol_ptr, version_ptr):
        """
        Simulate dlvsym(handle, symbol, version).

        Args:
            handle: Library handle from dlopen (or RTLD_DEFAULT/RTLD_NEXT)
            symbol_ptr: Pointer to symbol name string
            version_ptr: Pointer to version string

        Returns:
            Address of the symbol, or NULL (0) if not found
        """
        # Get symbol name
        symbol_name = self._get_string(symbol_ptr)
        if symbol_name is None:
            log.warning("dlvsym: Could not resolve symbol name (symbolic)")
            return claripy.BVS("dlvsym_result", self.state.arch.bits)

        # Get version string
        version = self._get_string(version_ptr)
        if version is None:
            log.debug("dlvsym: No version specified, falling back to dlsym")
            version = ""

        log.info(f"dlvsym: Looking up symbol '{symbol_name}' version '{version}'")

        # Concretize handle
        if self.state.solver.symbolic(handle):
            if self.state.solver.satisfiable():
                handle_val = self.state.solver.eval(handle)
            else:
                log.warning("dlvsym: Symbolic handle, cannot resolve")
                return claripy.BVS("dlvsym_result", self.state.arch.bits)
        else:
            handle_val = self.state.solver.eval(handle)

        # Try to find versioned symbol first
        symbol_addr = self._find_versioned_symbol(handle_val, symbol_name, version)

        if symbol_addr is None:
            # Fall back to unversioned symbol
            symbol_addr = self._find_symbol(handle_val, symbol_name)

        if symbol_addr is None:
            log.warning(f"dlvsym: Symbol not found: {symbol_name}@{version}")
            DlError.set_error(f"dlvsym: undefined symbol: {symbol_name}", self.state)
            return claripy.BVV(0, self.state.arch.bits)

        log.info(f"dlvsym: Resolved '{symbol_name}@{version}' to 0x{symbol_addr:x}")

        # Track resolution in state.globals
        resolved = self.state.globals.get('dpr_resolved_versioned_symbols', {})
        resolved[(handle_val, symbol_name, version)] = symbol_addr
        self.state.globals['dpr_resolved_versioned_symbols'] = resolved

        return claripy.BVV(symbol_addr, self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract null-terminated string from memory."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"dlvsym: Error reading string: {e}")
            return None

    def _find_versioned_symbol(self, handle: int, symbol_name: str, version: str) -> int | None:
        """
        Find a symbol with a specific version.

        ELF symbol versioning uses the .gnu.version and .gnu.version_r sections.
        This implementation checks for versioned symbols in the ELF structure.
        """
        if not version:
            return None

        # Get the library
        lib = self.loaded_libraries.get(handle)
        if lib is None:
            # Try to find by base address
            for h, loaded_lib in self.loaded_libraries.items():
                if hasattr(loaded_lib, 'mapped_base') and loaded_lib.mapped_base == handle:
                    lib = loaded_lib
                    break

        if lib is None:
            # Search all libraries
            return self._search_all_versioned(symbol_name, version)

        return self._find_versioned_in_lib(lib, symbol_name, version)

    def _find_versioned_in_lib(self, lib, symbol_name: str, version: str) -> int | None:
        """Find a versioned symbol in a specific library."""
        try:
            # Check if library has versioned symbols
            if hasattr(lib, 'symbols'):
                for name, sym in lib.symbols.items():
                    # Check for versioned symbol name (symbol@version or symbol@@version)
                    if name == f"{symbol_name}@{version}" or name == f"{symbol_name}@@{version}":
                        if hasattr(sym, 'rebased_addr'):
                            return sym.rebased_addr

            # Check symbol version information if available
            if hasattr(lib, '_symbol_cache'):
                for name, sym in lib._symbol_cache.items():
                    if name == f"{symbol_name}@{version}" or name == f"{symbol_name}@@{version}":
                        if hasattr(sym, 'rebased_addr'):
                            return sym.rebased_addr

        except Exception as e:
            log.debug(f"dlvsym: Error searching versioned symbols in {lib}: {e}")

        return None

    def _search_all_versioned(self, symbol_name: str, version: str) -> int | None:
        """Search for versioned symbol in all loaded libraries."""
        for lib in self.loaded_libraries.values():
            addr = self._find_versioned_in_lib(lib, symbol_name, version)
            if addr is not None:
                return addr

        # Also check project's statically loaded objects
        for obj in self.state.project.loader.all_objects:
            addr = self._find_versioned_in_lib(obj, symbol_name, version)
            if addr is not None:
                return addr

        return None

    def _find_symbol(self, handle: int, symbol_name: str) -> int | None:
        """Find unversioned symbol using DynDlsym logic."""
        dlsym = DynDlsym(
            project=self.state.project,
            cc=self.cc,
            prototype=self.prototype,
        )
        dlsym.state = self.state
        return dlsym._find_symbol(handle, symbol_name)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.resolved_versioned_symbols = {}
