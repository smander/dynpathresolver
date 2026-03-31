"""
SimProcedures for open() and openat() syscalls.

These procedures track file opens to correlate with mmap() calls,
enabling detection of manual library loading.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND,
    AT_FDCWD,
)

if TYPE_CHECKING:
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynOpen(angr.SimProcedure):
    """
    SimProcedure for open() that tracks file opens.

    Signature: int open(const char *pathname, int flags, ...)

    This procedure:
    1. Extracts the pathname from arguments
    2. Records the open in MemoryRegionTracker
    3. Returns a file descriptor for correlation with mmap
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # File descriptor allocation counter
    _fd_counter: int = 10  # Start after stdin/stdout/stderr

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

    def run(self, pathname_ptr, flags, mode=None):
        """
        Simulate open(pathname, flags, mode).

        Args:
            pathname_ptr: Pointer to pathname string
            flags: Open flags (O_RDONLY, O_RDWR, etc.)
            mode: File creation mode (optional, for O_CREAT)

        Returns:
            File descriptor on success, -1 on error
        """
        # Extract pathname
        pathname = self._get_pathname(pathname_ptr)
        if pathname is None:
            log.warning("open: Could not resolve pathname (symbolic)")
            return claripy.BVS("open_fd", self.state.arch.bits)

        # Concretize flags
        flags_val = self._concretize(flags, O_RDONLY)

        log.debug(f"open: pathname={pathname}, flags=0x{flags_val:x}")

        # Allocate file descriptor
        fd = self._allocate_fd()

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            memory_tracker.record_open(
                state=self.state,
                path=pathname,
                flags=flags_val,
                fd=fd,
            )

        # Record in predictor's LoadBehaviorDetector if available
        self._record_to_predictor(pathname, flags_val, fd)

        # Check for library file patterns
        if self._is_library_path(pathname):
            log.info(f"open: Library file opened - {pathname} (fd={fd})")

        return claripy.BVV(fd, self.state.arch.bits)

    def _get_pathname(self, pathname_ptr) -> str | None:
        """Extract pathname string from memory."""
        if self.state.solver.symbolic(pathname_ptr):
            if self.state.solver.satisfiable():
                pathname_ptr = self.state.solver.eval(pathname_ptr)
            else:
                return None

        try:
            path_bytes = self.state.mem[pathname_ptr].string.concrete
            if isinstance(path_bytes, bytes):
                return path_bytes.decode('utf-8', errors='ignore')
            return str(path_bytes)
        except Exception as e:
            log.debug(f"open: Error reading pathname: {e}")
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
        """Allocate a new file descriptor."""
        fd = cls._fd_counter
        cls._fd_counter += 1
        return fd

    def _is_library_path(self, pathname: str) -> bool:
        """Check if the pathname looks like a library file."""
        library_exts = ('.so', '.dll', '.dylib')
        pathname_lower = pathname.lower()
        return any(ext in pathname_lower for ext in library_exts)

    def _record_to_predictor(self, pathname: str, flags: int, fd: int) -> None:
        """Record open to predictor's LoadBehaviorDetector."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, 'heuristic_predictor'):
            predictor = technique.heuristic_predictor
            if hasattr(predictor, 'load_detector'):
                try:
                    predictor.load_detector.record_open(
                        self.state, pathname, flags, fd
                    )
                except Exception as e:
                    log.debug(f"Failed to record to predictor: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._fd_counter = 10


class DynOpenat(angr.SimProcedure):
    """
    SimProcedure for openat() that tracks file opens.

    Signature: int openat(int dirfd, const char *pathname, int flags, ...)

    This procedure handles openat() by extracting the pathname and
    delegating to DynOpen's tracking logic.
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

    def run(self, dirfd, pathname_ptr, flags, mode=None):
        """
        Simulate openat(dirfd, pathname, flags, mode).

        Args:
            dirfd: Directory file descriptor (AT_FDCWD for current dir)
            pathname_ptr: Pointer to pathname string
            flags: Open flags
            mode: File creation mode (optional)

        Returns:
            File descriptor on success, -1 on error
        """
        # Extract pathname
        pathname = self._get_pathname(pathname_ptr)
        if pathname is None:
            log.warning("openat: Could not resolve pathname (symbolic)")
            return claripy.BVS("openat_fd", self.state.arch.bits)

        # Concretize values
        dirfd_val = self._concretize(dirfd, AT_FDCWD)
        flags_val = self._concretize(flags, O_RDONLY)

        log.debug(f"openat: dirfd={dirfd_val}, pathname={pathname}, "
                  f"flags=0x{flags_val:x}")

        # Allocate file descriptor
        fd = DynOpen._allocate_fd()

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            memory_tracker.record_open(
                state=self.state,
                path=pathname,
                flags=flags_val,
                fd=fd,
            )

        # Record in predictor's LoadBehaviorDetector if available
        self._record_to_predictor(pathname, flags_val, fd)

        return claripy.BVV(fd, self.state.arch.bits)

    def _get_pathname(self, pathname_ptr) -> str | None:
        """Extract pathname string from memory."""
        if self.state.solver.symbolic(pathname_ptr):
            if self.state.solver.satisfiable():
                pathname_ptr = self.state.solver.eval(pathname_ptr)
            else:
                return None

        try:
            path_bytes = self.state.mem[pathname_ptr].string.concrete
            if isinstance(path_bytes, bytes):
                return path_bytes.decode('utf-8', errors='ignore')
            return str(path_bytes)
        except Exception as e:
            log.debug(f"openat: Error reading pathname: {e}")
            return None

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _record_to_predictor(self, pathname: str, flags: int, fd: int) -> None:
        """Record open to predictor's LoadBehaviorDetector."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, 'heuristic_predictor'):
            predictor = technique.heuristic_predictor
            if hasattr(predictor, 'load_detector'):
                try:
                    predictor.load_detector.record_open(
                        self.state, pathname, flags, fd
                    )
                except Exception as e:
                    log.debug(f"Failed to record to predictor: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
