"""
SimProcedure for __tls_get_addr() - Thread-Local Storage access.

__tls_get_addr is called to get the address of a thread-local variable.
It takes a pointer to a tls_index structure containing module ID and offset.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import TLS_BASE, DEFAULT_TLS_BLOCK_SIZE, PAGE_SIZE

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


class TLSManager:
    """
    Manages Thread-Local Storage for dynamically loaded libraries.

    TLS in ELF uses two models:
    - Initial-exec (IE): For main executable and initially loaded libraries
    - General-dynamic (GD): For dlopen'd libraries, uses __tls_get_addr

    This class simulates TLS blocks and provides address resolution.
    """

    # TLS blocks: module_id -> (base_addr, size)
    _tls_blocks: dict[int, tuple[int, int]] = {}

    # Module ID counter
    _next_module_id: int = 1

    # Base address for TLS region
    _tls_base: int = TLS_BASE

    # Current TLS offset
    _tls_offset: int = 0

    @classmethod
    def register_module(cls, lib) -> int:
        """Register a module for TLS and return its module ID."""
        module_id = cls._next_module_id
        cls._next_module_id += 1

        # Get TLS size from library if available
        tls_size = 0
        if hasattr(lib, 'tls_block_size'):
            tls_size = lib.tls_block_size
        elif hasattr(lib, '_tls_size'):
            tls_size = lib._tls_size
        else:
            # Default small TLS block
            tls_size = DEFAULT_TLS_BLOCK_SIZE

        # Allocate TLS block
        block_addr = cls._tls_base + cls._tls_offset
        cls._tls_offset += (tls_size + 0x10) & ~0xF  # Align to 16 bytes

        cls._tls_blocks[module_id] = (block_addr, tls_size)
        log.debug(f"TLS: Registered module {module_id} at 0x{block_addr:x} (size={tls_size})")

        return module_id

    @classmethod
    def get_address(cls, module_id: int, offset: int) -> int | None:
        """Get the address of a TLS variable."""
        if module_id not in cls._tls_blocks:
            log.warning(f"TLS: Unknown module ID {module_id}")
            return None

        block_addr, block_size = cls._tls_blocks[module_id]

        if offset >= block_size:
            log.warning(f"TLS: Offset {offset} exceeds block size {block_size}")
            # Allow it anyway for flexibility
            pass

        return block_addr + offset

    @classmethod
    def reset(cls):
        """Reset TLS state (for testing)."""
        cls._tls_blocks = {}
        cls._next_module_id = 1
        cls._tls_offset = 0


class DynTlsGetAddr(angr.SimProcedure):
    """
    SimProcedure for __tls_get_addr.

    Signature: void* __tls_get_addr(tls_index *ti)

    The tls_index structure is:
    struct tls_index {
        unsigned long int ti_module;  // Module ID
        unsigned long int ti_offset;  // Offset within TLS block
    };

    Returns the address of the TLS variable.
    """

    def run(self, ti_ptr):
        """
        Simulate __tls_get_addr(ti).

        Args:
            ti_ptr: Pointer to tls_index structure

        Returns:
            Address of the TLS variable
        """
        # Concretize pointer
        if self.state.solver.symbolic(ti_ptr):
            if self.state.solver.satisfiable():
                ti_ptr_val = self.state.solver.eval(ti_ptr)
            else:
                log.warning("__tls_get_addr: Symbolic ti pointer")
                return claripy.BVS("tls_addr", self.state.arch.bits)
        else:
            ti_ptr_val = self.state.solver.eval(ti_ptr)

        # Read tls_index structure
        ptr_size = self.state.arch.bits // 8

        try:
            # Read module ID
            module_id_bv = self.state.memory.load(
                ti_ptr_val,
                ptr_size,
                endness=self.state.arch.memory_endness
            )
            if self.state.solver.symbolic(module_id_bv):
                module_id = self.state.solver.eval(module_id_bv)
            else:
                module_id = self.state.solver.eval(module_id_bv)

            # Read offset
            offset_bv = self.state.memory.load(
                ti_ptr_val + ptr_size,
                ptr_size,
                endness=self.state.arch.memory_endness
            )
            if self.state.solver.symbolic(offset_bv):
                offset = self.state.solver.eval(offset_bv)
            else:
                offset = self.state.solver.eval(offset_bv)

        except Exception as e:
            log.warning(f"__tls_get_addr: Error reading tls_index: {e}")
            return claripy.BVS("tls_addr", self.state.arch.bits)

        log.debug(f"__tls_get_addr: module={module_id}, offset={offset}")

        # Get TLS address
        addr = TLSManager.get_address(module_id, offset)

        if addr is None:
            # Create a new TLS block for unknown module
            log.debug(f"__tls_get_addr: Creating TLS block for module {module_id}")
            TLSManager._tls_blocks[module_id] = (
                TLSManager._tls_base + TLSManager._tls_offset,
                PAGE_SIZE
            )
            TLSManager._tls_offset += PAGE_SIZE
            addr = TLSManager.get_address(module_id, offset)

        if addr is None:
            log.warning(f"__tls_get_addr: Could not resolve TLS address")
            return claripy.BVS("tls_addr", self.state.arch.bits)

        log.debug(f"__tls_get_addr: Resolved to 0x{addr:x}")
        return claripy.BVV(addr, self.state.arch.bits)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        TLSManager.reset()


class DynTlsDescResolver(angr.SimProcedure):
    """
    SimProcedure for _dl_tlsdesc_return and similar TLS descriptor resolvers.

    TLS descriptors are an optimization for TLS access. The descriptor
    contains a function pointer that resolves the TLS address.
    """

    def run(self, tlsdesc_ptr):
        """
        Simulate TLS descriptor resolution.

        Args:
            tlsdesc_ptr: Pointer to TLS descriptor

        Returns:
            Address of the TLS variable
        """
        # For simplicity, treat this like __tls_get_addr
        # TLS descriptors have a more complex structure but the result is similar

        if self.state.solver.symbolic(tlsdesc_ptr):
            log.warning("_dl_tlsdesc: Symbolic descriptor pointer")
            return claripy.BVS("tls_addr", self.state.arch.bits)

        tlsdesc_ptr_val = self.state.solver.eval(tlsdesc_ptr)
        ptr_size = self.state.arch.bits // 8

        try:
            # TLS descriptor typically has module/offset after the function pointer
            module_id_bv = self.state.memory.load(
                tlsdesc_ptr_val + ptr_size,  # Skip function pointer
                ptr_size,
                endness=self.state.arch.memory_endness
            )
            offset_bv = self.state.memory.load(
                tlsdesc_ptr_val + ptr_size * 2,
                ptr_size,
                endness=self.state.arch.memory_endness
            )

            module_id = self.state.solver.eval(module_id_bv)
            offset = self.state.solver.eval(offset_bv)

            addr = TLSManager.get_address(module_id, offset)
            if addr:
                return claripy.BVV(addr, self.state.arch.bits)

        except Exception as e:
            log.debug(f"_dl_tlsdesc: Error: {e}")

        return claripy.BVS("tls_addr", self.state.arch.bits)
