"""
SimProcedure for mprotect() syscall.

This procedure intercepts memory protection changes to detect:
- W->X transitions (code injection/unpacking)
- Making dynamically allocated memory executable
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
)

if TYPE_CHECKING:
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynMprotect(angr.SimProcedure):
    """
    SimProcedure for mprotect() that tracks permission changes.

    Signature: int mprotect(void *addr, size_t len, int prot)

    This procedure:
    1. Extracts address, length, and new protection from arguments
    2. Updates the mapping in MemoryRegionTracker
    3. Detects W->X transitions (common in code injection)
    4. Returns 0 on success, -1 on error
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

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

    def run(self, addr, length, prot):
        """
        Simulate mprotect(addr, length, prot).

        Args:
            addr: Start address of region
            length: Length of region
            prot: New protection flags

        Returns:
            0 on success, -1 on error
        """
        # Concretize arguments
        addr_val = self._concretize(addr, 0)
        length_val = self._concretize(length, 0)
        prot_val = self._concretize(prot, PROT_READ)

        log.debug(f"mprotect: addr=0x{addr_val:x}, length={length_val}, "
                  f"prot=0x{prot_val:x}")

        # Check for executable flag
        is_making_executable = bool(prot_val & PROT_EXEC)

        if is_making_executable:
            log.info(f"mprotect: Making region executable - "
                     f"addr=0x{addr_val:x}, length={length_val}")

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            # This will detect W->X transitions
            updated = memory_tracker.record_mprotect(
                state=self.state,
                addr=addr_val,
                size=length_val,
                new_prot=prot_val,
            )

            if is_making_executable:
                self._notify_technique(addr_val, length_val, prot_val)

        return claripy.BVV(0, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _notify_technique(self, addr: int, length: int, prot: int) -> None:
        """Notify the technique about protection change."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_mprotect_exec'):
            try:
                technique._record_mprotect_exec(
                    state=self.state,
                    addr=addr,
                    length=length,
                    prot=prot,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
