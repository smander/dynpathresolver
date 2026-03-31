"""
SimProcedure for dladdr() - reverse address lookup.

dladdr takes an address and returns information about the shared object
and symbol that contains that address.
"""

import logging

import angr
import claripy

from dynpathresolver.config.constants import DLADDR_STRING_BASE

log = logging.getLogger(__name__)


# Dl_info structure offsets (x86_64)
# struct Dl_info {
#     const char *dli_fname;  /* Pathname of shared object */
#     void       *dli_fbase;  /* Base address of shared object */
#     const char *dli_sname;  /* Name of nearest symbol */
#     void       *dli_saddr;  /* Address of nearest symbol */
# };

class DlInfoOffsets:
    """Offsets for Dl_info structure fields."""

    @staticmethod
    def get_offsets(arch_bits: int) -> dict:
        """Get field offsets based on architecture."""
        ptr_size = arch_bits // 8
        return {
            'dli_fname': 0,
            'dli_fbase': ptr_size,
            'dli_sname': ptr_size * 2,
            'dli_saddr': ptr_size * 3,
        }


class DynDladdr(angr.SimProcedure):
    """
    SimProcedure for dladdr.

    Signature: int dladdr(const void *addr, Dl_info *info)

    This procedure:
    1. Takes an address in a loaded shared object
    2. Finds which shared object contains the address
    3. Finds the nearest symbol at or before the address
    4. Populates the Dl_info structure with the information
    5. Returns non-zero on success, 0 on failure

    The Dl_info structure contains:
    - dli_fname: pathname of the shared object
    - dli_fbase: base address of the shared object
    - dli_sname: name of the nearest symbol
    - dli_saddr: address of the nearest symbol
    """

    # Cache for allocated strings (to avoid repeated allocation)
    _string_cache: dict[str, int] = {}
    _next_string_addr: int = DLADDR_STRING_BASE

    @property
    def loaded_libraries(self):
        """Get loaded libraries from state globals (falls back to DynDlopen class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_loaded_libraries', {})
        from .dlopen import DynDlopen
        return DynDlopen.loaded_libraries

    def run(self, addr, info_ptr):
        """
        Simulate dladdr(addr, info).

        Args:
            addr: Address to look up
            info_ptr: Pointer to Dl_info structure to fill

        Returns:
            Non-zero on success, 0 if address not in any shared object
        """
        # Concretize address
        if self.state.solver.symbolic(addr):
            if self.state.solver.satisfiable():
                addr_val = self.state.solver.eval(addr)
            else:
                log.warning("dladdr: Symbolic address, cannot resolve")
                return claripy.BVV(0, self.state.arch.bits)
        else:
            addr_val = self.state.solver.eval(addr)

        # Concretize info pointer
        if self.state.solver.symbolic(info_ptr):
            if self.state.solver.satisfiable():
                info_ptr_val = self.state.solver.eval(info_ptr)
            else:
                log.warning("dladdr: Symbolic info pointer")
                return claripy.BVV(0, self.state.arch.bits)
        else:
            info_ptr_val = self.state.solver.eval(info_ptr)

        log.debug(f"dladdr: Looking up address 0x{addr_val:x}")

        # Find the shared object containing this address
        obj, obj_name = self._find_object(addr_val)

        if obj is None:
            log.debug(f"dladdr: Address 0x{addr_val:x} not found in any shared object")
            return claripy.BVV(0, self.state.arch.bits)

        # Find the nearest symbol
        sym_name, sym_addr = self._find_nearest_symbol(obj, addr_val)

        # Get object base address
        base_addr = getattr(obj, 'mapped_base', 0) or getattr(obj, 'min_addr', 0)

        # Populate Dl_info structure
        self._populate_dl_info(
            info_ptr_val,
            obj_name,
            base_addr,
            sym_name,
            sym_addr
        )

        log.info(f"dladdr: 0x{addr_val:x} -> {obj_name} + {sym_name}@0x{sym_addr:x}")
        return claripy.BVV(1, self.state.arch.bits)  # Success

    def _find_object(self, addr: int) -> tuple:
        """Find the shared object containing the given address."""
        # Check dynamically loaded libraries first
        for handle, lib in self.loaded_libraries.items():
            min_addr = getattr(lib, 'min_addr', 0) or getattr(lib, 'mapped_base', 0)
            max_addr = getattr(lib, 'max_addr', 0)

            if min_addr <= addr <= max_addr:
                name = getattr(lib, 'binary', None) or f"lib@0x{handle:x}"
                return lib, name

        # Check project's statically loaded objects
        for obj in self.state.project.loader.all_objects:
            min_addr = getattr(obj, 'min_addr', 0)
            max_addr = getattr(obj, 'max_addr', 0)

            if min_addr <= addr <= max_addr:
                name = getattr(obj, 'binary', None) or str(obj)
                return obj, name

        return None, None

    def _find_nearest_symbol(self, obj, addr: int) -> tuple[str | None, int]:
        """Find the nearest symbol at or before the given address."""
        nearest_name = None
        nearest_addr = 0

        try:
            # Iterate through symbols
            symbols = None
            if hasattr(obj, 'symbols'):
                symbols = obj.symbols
            elif hasattr(obj, '_symbol_cache'):
                symbols = obj._symbol_cache

            if symbols:
                for name, sym in symbols.items():
                    sym_addr = 0
                    if hasattr(sym, 'rebased_addr'):
                        sym_addr = sym.rebased_addr
                    elif hasattr(sym, 'linked_addr'):
                        base = getattr(obj, 'mapped_base', 0)
                        sym_addr = base + sym.linked_addr

                    # Symbol must be at or before our address
                    if sym_addr <= addr and sym_addr > nearest_addr:
                        # Skip internal/empty names
                        if name and not name.startswith('_'):
                            nearest_name = name
                            nearest_addr = sym_addr

        except Exception as e:
            log.debug(f"dladdr: Error finding symbol: {e}")

        return nearest_name, nearest_addr

    def _populate_dl_info(
        self,
        info_ptr: int,
        fname: str | None,
        fbase: int,
        sname: str | None,
        saddr: int
    ) -> None:
        """Populate the Dl_info structure at the given address."""
        offsets = DlInfoOffsets.get_offsets(self.state.arch.bits)
        ptr_size = self.state.arch.bits // 8

        # Allocate strings
        fname_ptr = self._allocate_string(fname) if fname else 0
        sname_ptr = self._allocate_string(sname) if sname else 0

        # Write dli_fname
        self.state.memory.store(
            info_ptr + offsets['dli_fname'],
            claripy.BVV(fname_ptr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        # Write dli_fbase
        self.state.memory.store(
            info_ptr + offsets['dli_fbase'],
            claripy.BVV(fbase, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        # Write dli_sname
        self.state.memory.store(
            info_ptr + offsets['dli_sname'],
            claripy.BVV(sname_ptr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        # Write dli_saddr
        self.state.memory.store(
            info_ptr + offsets['dli_saddr'],
            claripy.BVV(saddr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

    def _allocate_string(self, s: str) -> int:
        """Allocate a string in memory and return its address."""
        if s in self._string_cache:
            return self._string_cache[s]

        addr = self._next_string_addr
        DynDladdr._next_string_addr += len(s) + 1 + 8  # Align to 8 bytes

        # Write string with null terminator
        string_bytes = s.encode('utf-8') + b'\x00'
        for i, byte in enumerate(string_bytes):
            self.state.memory.store(
                addr + i,
                claripy.BVV(byte, 8),
                endness=self.state.arch.memory_endness
            )

        self._string_cache[s] = addr
        return addr

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls._string_cache = {}
        cls._next_string_addr = DLADDR_STRING_BASE
