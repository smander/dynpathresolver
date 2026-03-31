"""
SimProcedure for dlerror() - get error string from last dl* call.

dlerror returns a human-readable string describing the most recent error
from dlopen, dlsym, or dlclose. Calling dlerror clears the error.
"""

import logging

import angr
import claripy

from dynpathresolver.config.constants import (
    DLERROR_BUFFER_SIZE, DLERROR_BUFFER_BASE,
    PAGE_SIZE, PAGE_ALIGNMENT_GAP,
)

log = logging.getLogger(__name__)


class DlError:
    """
    Class-level error tracking for dl* functions.

    This class maintains the last error message and provides methods
    for setting and clearing errors.
    """

    # The last error message (None if no error)
    _last_error: str | None = None

    # Address where error string is stored in memory (per-state)
    _error_string_addr: int | None = None

    @classmethod
    def set_error(cls, message: str, state=None) -> None:
        """Set the error message (per-state if state provided)."""
        if state is not None:
            state.globals['dpr_dlerror_last_error'] = message
        else:
            cls._last_error = message
        log.debug(f"dlerror: Error set: {message}")

    @classmethod
    def get_error(cls, state=None) -> str | None:
        """Get and clear the error message (per-state if state provided)."""
        if state is not None:
            error = state.globals.get('dpr_dlerror_last_error')
            state.globals['dpr_dlerror_last_error'] = None
            return error
        error = cls._last_error
        cls._last_error = None
        return error

    @classmethod
    def has_error(cls, state=None) -> bool:
        """Check if there is a pending error (per-state if state provided)."""
        if state is not None:
            return state.globals.get('dpr_dlerror_last_error') is not None
        return cls._last_error is not None

    @classmethod
    def reset(cls) -> None:
        """Reset error state (for testing)."""
        cls._last_error = None
        cls._error_string_addr = None


class DynDlerror(angr.SimProcedure):
    """
    SimProcedure for dlerror.

    Signature: char *dlerror(void)

    Returns a pointer to a string describing the last error, or NULL
    if no error has occurred since the last call to dlerror.

    Note: The returned string is statically allocated and may be
    overwritten by subsequent dlerror calls.
    """

    # Allocated address for error string (shared across calls)
    _error_buffer_addr: int | None = None
    _error_buffer_size: int = DLERROR_BUFFER_SIZE

    def run(self):
        """
        Simulate dlerror().

        Returns:
            Pointer to error string, or NULL if no error
        """
        error = DlError.get_error(self.state)

        if error is None:
            log.debug("dlerror: No error")
            return claripy.BVV(0, self.state.arch.bits)  # NULL

        log.debug(f"dlerror: Returning error: {error}")

        # Allocate buffer for error string if not already done
        if self._error_buffer_addr is None:
            self._error_buffer_addr = self._allocate_error_buffer()

        # Write error string to buffer
        self._write_error_string(error)

        return claripy.BVV(self._error_buffer_addr, self.state.arch.bits)

    def _allocate_error_buffer(self) -> int:
        """Allocate a buffer for the error string."""
        # Find a free memory region
        # Use a high address that's unlikely to conflict
        addr = DLERROR_BUFFER_BASE

        # Check if we can use this address
        project = self.state.project
        for obj in project.loader.all_objects:
            if hasattr(obj, 'max_addr') and obj.max_addr >= addr:
                addr = ((obj.max_addr + PAGE_ALIGNMENT_GAP) // PAGE_SIZE) * PAGE_SIZE

        log.debug(f"dlerror: Allocated error buffer at 0x{addr:x}")
        return addr

    def _write_error_string(self, error: str) -> None:
        """Write error string to the allocated buffer."""
        # Truncate if too long
        if len(error) >= self._error_buffer_size:
            error = error[:self._error_buffer_size - 1]

        # Write string with null terminator
        error_bytes = error.encode('utf-8') + b'\x00'

        for i, byte in enumerate(error_bytes):
            self.state.memory.store(
                self._error_buffer_addr + i,
                claripy.BVV(byte, 8),
                endness=self.state.arch.memory_endness
            )

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls._error_buffer_addr = None
        DlError.reset()
