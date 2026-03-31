"""
SimProcedure for fopen() that tracks .so file opens and blocks /proc/ reads.

This procedure:
1. Extracts the filename from arguments
2. If path contains .so, records in memory_tracker
3. If path starts with /proc/, returns NULL (anti-debug bypass)
4. Otherwise returns a symbolic FILE* pointer
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

if TYPE_CHECKING:
    from ...tracking.memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynFopen(angr.SimProcedure):
    """
    SimProcedure for fopen() that tracks .so file opens and blocks /proc/ reads.

    Signature: FILE *fopen(const char *pathname, const char *mode)
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # File descriptor allocation counter (shared with DynOpen)
    _fd_counter: int = 100  # Start high to avoid conflicts with DynOpen

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

    def run(self, filename_ptr, mode_ptr):
        """
        Simulate fopen(filename, mode).

        Args:
            filename_ptr: Pointer to filename string
            mode_ptr: Pointer to mode string

        Returns:
            FILE* pointer on success, NULL (0) on failure
        """
        # Extract filename
        filename = self._get_string(filename_ptr)
        if filename is None:
            log.warning("fopen: Could not resolve filename (symbolic)")
            return claripy.BVS("fopen_result", self.state.arch.bits)

        log.debug(f"fopen: filename={filename}")

        # Block /proc/ reads (anti-debug bypass)
        if filename.startswith('/proc/'):
            log.info(f"fopen: blocking /proc/ read: {filename}")
            return claripy.BVV(0, self.state.arch.bits)  # NULL = failed

        # Track .so file opens
        if '.so' in filename:
            memory_tracker = self._get_memory_tracker()
            if memory_tracker:
                fd = self._allocate_fd()
                memory_tracker.record_open(self.state, filename, 0, fd)
                log.info(f"fopen: tracking .so open: {filename}")

        # Return symbolic FILE* (non-NULL to indicate success)
        return claripy.BVS("fopen_result", self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory pointer."""
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
            log.debug(f"fopen: Error reading string: {e}")
            return None

    @classmethod
    def _allocate_fd(cls) -> int:
        """Allocate a new file descriptor."""
        fd = cls._fd_counter
        cls._fd_counter += 1
        return fd

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._fd_counter = 100
