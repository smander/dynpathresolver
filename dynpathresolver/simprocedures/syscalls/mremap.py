"""
SimProcedure for mremap() syscall.

This procedure intercepts memory remapping operations to detect code relocation
that could be used to evade detection or bypass memory protections.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP,
    MREMAP_ALLOC_BASE, PAGE_SIZE,
)

if TYPE_CHECKING:
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynMremap(angr.SimProcedure):
    """
    SimProcedure for mremap() that tracks memory remapping.

    Signature: void *mremap(void *old_address, size_t old_size,
                            size_t new_size, int flags, ... /* void *new_address */)

    This procedure:
    1. Extracts remapping parameters from arguments
    2. Updates the mapping in MemoryRegionTracker
    3. Detects code relocation (executable region moves)
    4. Returns the new mapped address
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # Address allocation counter for moved mappings
    _alloc_base: int = MREMAP_ALLOC_BASE

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_memory_tracker(self):
        """Get memory_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_memory_tracker', self.__class__.memory_tracker)
        return self.__class__.memory_tracker

    def run(self, old_address, old_size, new_size, flags, *args):
        """
        Simulate mremap(old_address, old_size, new_size, flags, [new_address]).

        Args:
            old_address: Current address of mapping
            old_size: Current size of mapping
            new_size: New requested size
            flags: MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP
            args: Optional new_address if MREMAP_FIXED

        Returns:
            New mapped address, or MAP_FAILED (-1) on error
        """
        # Concretize arguments
        old_addr_val = self._concretize(old_address, 0)
        old_size_val = self._concretize(old_size, 4096)
        new_size_val = self._concretize(new_size, 4096)
        flags_val = self._concretize(flags, 0)

        new_addr_val = None
        if flags_val & MREMAP_FIXED and len(args) > 0:
            new_addr_val = self._concretize(args[0], 0)

        log.debug(f"mremap: old_addr=0x{old_addr_val:x}, old_size={old_size_val}, "
                  f"new_size={new_size_val}, flags=0x{flags_val:x}")

        # Determine the new address
        if new_addr_val is not None:
            # MREMAP_FIXED: use specified address
            result_addr = new_addr_val
        elif flags_val & MREMAP_MAYMOVE:
            # May move to new location
            if new_size_val > old_size_val:
                # Need to move to accommodate larger size
                result_addr = self._allocate_address(new_size_val)
            else:
                # Can stay in place
                result_addr = old_addr_val
        else:
            # Cannot move, try to resize in place
            result_addr = old_addr_val

        # Page-align the addresses and sizes
        result_addr = (result_addr // PAGE_SIZE) * PAGE_SIZE
        new_size_val = ((new_size_val + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            memory_tracker.record_mremap(
                state=self.state,
                old_addr=old_addr_val,
                old_size=old_size_val,
                new_addr=result_addr,
                new_size=new_size_val,
                flags=flags_val,
            )

            # Check if executable code was relocated
            old_region = memory_tracker.get_region(old_addr_val)
            if old_region and old_region.is_executable and result_addr != old_addr_val:
                log.warning(f"mremap: Executable code relocated from "
                           f"0x{old_addr_val:x} to 0x{result_addr:x}")
                self._notify_technique(old_addr_val, result_addr, new_size_val)

        return claripy.BVV(result_addr, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_address(cls, size: int) -> int:
        """Allocate an address for moved mapping."""
        addr = cls._alloc_base
        # Align size to page boundary and add guard page
        aligned_size = ((size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE + PAGE_SIZE
        cls._alloc_base += aligned_size
        return addr

    def _notify_technique(self, old_addr: int, new_addr: int, size: int) -> None:
        """Notify the technique about code relocation."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_mremap_exec'):
            try:
                technique._record_mremap_exec(
                    state=self.state,
                    old_addr=old_addr,
                    new_addr=new_addr,
                    size=size,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._alloc_base = MREMAP_ALLOC_BASE
