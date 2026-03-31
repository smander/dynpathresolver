"""
SimProcedure for dlinfo() - get information about a dynamically loaded object.

dlinfo allows querying various pieces of information about a loaded
shared object using different request codes.
"""

import logging

import angr
import claripy

from dynpathresolver.config.constants import (
    RTLD_DI_LMID, RTLD_DI_LINKMAP, RTLD_DI_ORIGIN,
    RTLD_DI_SERINFO, RTLD_DI_SERINFOSIZE,
    RTLD_DI_TLS_MODID, RTLD_DI_TLS_DATA,
    LM_ID_BASE, DLINFO_LINKMAP_BASE,
)
from .dlerror import DlError
from .dlmopen import DynDlmopen

log = logging.getLogger(__name__)


class DynDlinfo(angr.SimProcedure):
    """
    SimProcedure for dlinfo.

    Signature: int dlinfo(void *handle, int request, void *info)

    This procedure supports the following requests:
    - RTLD_DI_LMID: Get the link-map namespace ID
    - RTLD_DI_LINKMAP: Get pointer to link_map structure
    - RTLD_DI_ORIGIN: Get the origin directory

    Returns 0 on success, -1 on error.
    """

    # Simulated link_map structures (address -> struct data)
    _link_maps: dict[int, dict] = {}
    _next_linkmap_addr: int = DLINFO_LINKMAP_BASE

    @property
    def loaded_libraries(self):
        """Get loaded libraries from state globals (falls back to DynDlopen class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_loaded_libraries', {})
        from .dlopen import DynDlopen
        return DynDlopen.loaded_libraries

    def run(self, handle, request, info_ptr):
        """
        Simulate dlinfo(handle, request, info).

        Args:
            handle: Library handle from dlopen
            request: Request code (RTLD_DI_*)
            info_ptr: Pointer to output buffer

        Returns:
            0 on success, -1 on error
        """
        # Concretize handle
        if self.state.solver.symbolic(handle):
            if self.state.solver.satisfiable():
                handle_val = self.state.solver.eval(handle)
            else:
                log.warning("dlinfo: Symbolic handle")
                return claripy.BVV(-1 & ((1 << self.state.arch.bits) - 1), self.state.arch.bits)
        else:
            handle_val = self.state.solver.eval(handle)

        # Concretize request
        if self.state.solver.symbolic(request):
            if self.state.solver.satisfiable():
                request_val = self.state.solver.eval(request)
            else:
                log.warning("dlinfo: Symbolic request")
                return claripy.BVV(-1 & ((1 << self.state.arch.bits) - 1), self.state.arch.bits)
        else:
            request_val = self.state.solver.eval(request)

        # Concretize info pointer
        if self.state.solver.symbolic(info_ptr):
            if self.state.solver.satisfiable():
                info_ptr_val = self.state.solver.eval(info_ptr)
            else:
                log.warning("dlinfo: Symbolic info pointer")
                return claripy.BVV(-1 & ((1 << self.state.arch.bits) - 1), self.state.arch.bits)
        else:
            info_ptr_val = self.state.solver.eval(info_ptr)

        log.debug(f"dlinfo: handle=0x{handle_val:x}, request={request_val}")

        # Verify handle is valid
        lib = self._get_library(handle_val)
        if lib is None:
            log.warning(f"dlinfo: Invalid handle 0x{handle_val:x}")
            DlError.set_error("dlinfo: invalid handle", self.state)
            return claripy.BVV(-1 & ((1 << self.state.arch.bits) - 1), self.state.arch.bits)

        # Handle the request
        result = self._handle_request(handle_val, request_val, info_ptr_val, lib)
        return result

    def _get_library(self, handle: int):
        """Get library object from handle."""
        lib = self.loaded_libraries.get(handle)
        if lib is not None:
            return lib

        # Try by base address
        for h, loaded_lib in self.loaded_libraries.items():
            if hasattr(loaded_lib, 'mapped_base') and loaded_lib.mapped_base == handle:
                return loaded_lib

        # Also check project's objects
        for obj in self.state.project.loader.all_objects:
            if hasattr(obj, 'mapped_base') and obj.mapped_base == handle:
                return obj

        return None

    def _handle_request(self, handle: int, request: int, info_ptr: int, lib) -> claripy.ast.BV:
        """Handle a specific dlinfo request."""
        if request == RTLD_DI_LMID:
            return self._handle_lmid(handle, info_ptr)
        elif request == RTLD_DI_LINKMAP:
            return self._handle_linkmap(handle, info_ptr, lib)
        elif request == RTLD_DI_ORIGIN:
            return self._handle_origin(handle, info_ptr, lib)
        elif request == RTLD_DI_TLS_MODID:
            return self._handle_tls_modid(handle, info_ptr, lib)
        else:
            log.warning(f"dlinfo: Unsupported request {request}")
            DlError.set_error(f"dlinfo: unsupported request {request}", self.state)
            return claripy.BVV(-1 & ((1 << self.state.arch.bits) - 1), self.state.arch.bits)

    def _handle_lmid(self, handle: int, info_ptr: int) -> claripy.ast.BV:
        """Handle RTLD_DI_LMID request - get namespace ID."""
        # Get namespace from dlmopen tracking
        namespace = DynDlmopen.get_namespace(handle, state=self.state)
        if namespace is None:
            namespace = LM_ID_BASE

        # Write namespace ID to info
        self.state.memory.store(
            info_ptr,
            claripy.BVV(namespace, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        log.debug(f"dlinfo: RTLD_DI_LMID -> {namespace}")
        return claripy.BVV(0, self.state.arch.bits)

    def _handle_linkmap(self, handle: int, info_ptr: int, lib) -> claripy.ast.BV:
        """Handle RTLD_DI_LINKMAP request - get link_map pointer."""
        # Create or get link_map structure
        linkmap_addr = self._get_or_create_linkmap(handle, lib)

        # Write pointer to info
        self.state.memory.store(
            info_ptr,
            claripy.BVV(linkmap_addr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        log.debug(f"dlinfo: RTLD_DI_LINKMAP -> 0x{linkmap_addr:x}")
        return claripy.BVV(0, self.state.arch.bits)

    def _handle_origin(self, handle: int, info_ptr: int, lib) -> claripy.ast.BV:
        """Handle RTLD_DI_ORIGIN request - get library origin directory."""
        import os

        # Get library path
        lib_path = getattr(lib, 'binary', None)
        if lib_path:
            origin = os.path.dirname(os.path.abspath(lib_path))
        else:
            origin = "."

        # Write origin string to memory
        origin_bytes = origin.encode('utf-8') + b'\x00'
        for i, byte in enumerate(origin_bytes):
            self.state.memory.store(
                info_ptr + i,
                claripy.BVV(byte, 8),
                endness=self.state.arch.memory_endness
            )

        log.debug(f"dlinfo: RTLD_DI_ORIGIN -> {origin}")
        return claripy.BVV(0, self.state.arch.bits)

    def _handle_tls_modid(self, handle: int, info_ptr: int, lib) -> claripy.ast.BV:
        """Handle RTLD_DI_TLS_MODID request - get TLS module ID."""
        # For simplicity, use handle as module ID
        modid = handle & 0xFFFF

        self.state.memory.store(
            info_ptr,
            claripy.BVV(modid, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        log.debug(f"dlinfo: RTLD_DI_TLS_MODID -> {modid}")
        return claripy.BVV(0, self.state.arch.bits)

    def _get_or_create_linkmap(self, handle: int, lib) -> int:
        """Get or create a link_map structure for a library."""
        if handle in self._link_maps:
            return self._link_maps[handle]['addr']

        # Allocate new link_map
        addr = self._next_linkmap_addr
        DynDlinfo._next_linkmap_addr += 0x100  # link_map is about 0x60-0x80 bytes

        # link_map structure (simplified):
        # struct link_map {
        #     Elf_Addr l_addr;     // Offset 0: Base address
        #     char *l_name;        // Offset 8: Library name
        #     Elf_Dyn *l_ld;       // Offset 16: Dynamic section
        #     struct link_map *l_next;  // Offset 24: Next in chain
        #     struct link_map *l_prev;  // Offset 32: Previous in chain
        # };

        ptr_size = self.state.arch.bits // 8
        base_addr = getattr(lib, 'mapped_base', 0) or getattr(lib, 'min_addr', 0)
        lib_name = getattr(lib, 'binary', '') or ''

        # Allocate and write library name
        name_addr = self._next_linkmap_addr
        DynDlinfo._next_linkmap_addr += len(lib_name) + 1 + 8

        name_bytes = lib_name.encode('utf-8') + b'\x00'
        for i, byte in enumerate(name_bytes):
            self.state.memory.store(
                name_addr + i,
                claripy.BVV(byte, 8),
                endness=self.state.arch.memory_endness
            )

        # Write link_map fields
        # l_addr
        self.state.memory.store(
            addr,
            claripy.BVV(base_addr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )
        # l_name
        self.state.memory.store(
            addr + ptr_size,
            claripy.BVV(name_addr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )
        # l_ld (NULL for now)
        self.state.memory.store(
            addr + ptr_size * 2,
            claripy.BVV(0, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )
        # l_next (NULL for now)
        self.state.memory.store(
            addr + ptr_size * 3,
            claripy.BVV(0, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )
        # l_prev (NULL for now)
        self.state.memory.store(
            addr + ptr_size * 4,
            claripy.BVV(0, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )

        self._link_maps[handle] = {
            'addr': addr,
            'base': base_addr,
            'name': lib_name,
        }

        return addr

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls._link_maps = {}
        cls._next_linkmap_addr = DLINFO_LINKMAP_BASE
