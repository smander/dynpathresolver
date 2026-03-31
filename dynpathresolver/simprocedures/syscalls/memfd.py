"""
SimProcedure for memfd_create() syscall.

This procedure intercepts memory-backed file descriptor creation,
used for fileless library loading.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    MFD_CLOEXEC, MFD_ALLOW_SEALING,
)

if TYPE_CHECKING:
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynMemfdCreate(angr.SimProcedure):
    """
    SimProcedure for memfd_create() that tracks fileless loading.

    Signature: int memfd_create(const char *name, unsigned int flags)

    This procedure:
    1. Extracts the name from arguments
    2. Records the memfd in MemoryRegionTracker
    3. Returns a file descriptor for correlation with mmap
    4. Enables detection of fileless library loading
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # File descriptor allocation counter (shared with open)
    _fd_counter: int = 100  # Start high to distinguish from regular fds

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

    def run(self, name_ptr, flags):
        """
        Simulate memfd_create(name, flags).

        Args:
            name_ptr: Pointer to name string
            flags: memfd flags (MFD_CLOEXEC, MFD_ALLOW_SEALING)

        Returns:
            File descriptor on success, -1 on error
        """
        # Extract name
        name = self._get_name(name_ptr)
        if name is None:
            name = "<anonymous>"

        # Concretize flags
        flags_val = self._concretize(flags, 0)

        log.info(f"memfd_create: name={name}, flags=0x{flags_val:x}")

        # Allocate file descriptor
        fd = self._allocate_fd()

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            memory_tracker.record_memfd_create(
                state=self.state,
                name=name,
                fd=fd,
            )

        # Record in predictor's LoadBehaviorDetector if available
        self._record_to_predictor(name, fd)

        # This is a strong indicator of fileless loading
        log.warning(f"memfd_create detected - potential fileless loading "
                    f"(name={name}, fd={fd})")

        return claripy.BVV(fd, self.state.arch.bits)

    def _get_name(self, name_ptr) -> str | None:
        """Extract name string from memory."""
        if self.state.solver.symbolic(name_ptr):
            if self.state.solver.satisfiable():
                name_ptr = self.state.solver.eval(name_ptr)
            else:
                return None

        try:
            name_bytes = self.state.mem[name_ptr].string.concrete
            if isinstance(name_bytes, bytes):
                return name_bytes.decode('utf-8', errors='ignore')
            return str(name_bytes)
        except Exception as e:
            log.debug(f"memfd_create: Error reading name: {e}")
            return None

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_fd(cls) -> int:
        """Allocate a new file descriptor for memfd."""
        fd = cls._fd_counter
        cls._fd_counter += 1
        return fd

    def _record_to_predictor(self, name: str, fd: int) -> None:
        """Record memfd_create to predictor's LoadBehaviorDetector."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, 'heuristic_predictor'):
            predictor = technique.heuristic_predictor
            if hasattr(predictor, 'load_detector'):
                try:
                    predictor.load_detector.record_memfd_create(
                        self.state, name, fd
                    )
                except Exception as e:
                    log.debug(f"Failed to record to predictor: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._fd_counter = 100
