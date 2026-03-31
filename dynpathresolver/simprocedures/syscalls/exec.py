"""
SimProcedures for exec*() syscalls.

These procedures intercept process execution operations to detect:
- Process replacement for staged execution
- Fileless execution via fexecve
- Hidden program execution
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    AT_FDCWD, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
)

if TYPE_CHECKING:
    from ...process_tracker import ProcessExecutionTracker
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class _BaseExecProcedure(angr.SimProcedure):
    """Base class for exec*() SimProcedures with shared utilities."""

    # Class-level configuration (set by DynPathResolver)
    process_tracker: "ProcessExecutionTracker | None" = None
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_process_tracker(self):
        """Get process_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_process_tracker', self.__class__.process_tracker)
        return self.__class__.process_tracker

    def _get_memory_tracker(self):
        """Get memory_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_memory_tracker', self.__class__.memory_tracker)
        return self.__class__.memory_tracker

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory at pointer."""
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
            log.debug(f"exec: Error reading string: {e}")
            return None

    def _get_string_array(self, ptr, max_count: int = 100) -> list[str]:
        """Extract array of strings from memory."""
        result = []

        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return result

        if ptr == 0:
            return result

        try:
            ptr_size = self.state.arch.bytes
            for i in range(max_count):
                str_ptr_addr = ptr + (i * ptr_size)
                str_ptr = self.state.mem[str_ptr_addr].uint64_t.concrete \
                    if ptr_size == 8 else self.state.mem[str_ptr_addr].uint32_t.concrete

                if str_ptr == 0:
                    break

                string = self._get_string(str_ptr)
                if string:
                    result.append(string)
        except Exception as e:
            log.debug(f"exec: Error reading string array: {e}")

        return result

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.process_tracker = None
        cls.memory_tracker = None
        cls.technique = None


class DynExecve(_BaseExecProcedure):
    """
    SimProcedure for execve() that tracks process execution.

    Signature: int execve(const char *pathname, char *const argv[],
                          char *const envp[])
    """

    def run(self, pathname, argv, envp):
        path = self._get_string(pathname)
        if path is None:
            log.warning("execve: Could not resolve pathname")
            return claripy.BVV(-1, self.state.arch.bits)

        log.info(f"execve: path={path}")

        argv_list = self._get_string_array(argv)
        envp_list = self._get_string_array(envp, max_count=10)

        process_tracker = self._get_process_tracker()
        if process_tracker:
            process_tracker.record_execve(
                state=self.state,
                path=path,
                argv=argv_list,
                envp=envp_list,
            )

        # Notify technique
        technique = self._get_technique()
        if technique is not None and hasattr(technique, '_record_exec'):
            try:
                technique._record_exec(
                    state=self.state, path=path, argv=argv_list,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

        return claripy.BVV(-1, self.state.arch.bits)


class DynExecveat(_BaseExecProcedure):
    """
    SimProcedure for execveat() that tracks process execution.

    Signature: int execveat(int dirfd, const char *pathname,
                            char *const argv[], char *const envp[], int flags)
    """

    def _get_string(self, ptr) -> str | None:
        """Override to return empty string for NULL pointer (needed for AT_EMPTY_PATH)."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        if ptr == 0:
            return ""

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"execveat: Error reading string: {e}")
            return None

    def run(self, dirfd, pathname, argv, envp, flags):
        dirfd_val = self._concretize(dirfd, AT_FDCWD)
        flags_val = self._concretize(flags, 0)

        path = self._get_string(pathname)

        # Handle AT_EMPTY_PATH (execute directly from fd)
        if flags_val & AT_EMPTY_PATH:
            log.warning(f"execveat with AT_EMPTY_PATH: executing from fd={dirfd_val}")
            if path is None or path == "":
                path = f"/proc/self/fd/{dirfd_val}"

        if path is None:
            log.warning("execveat: Could not resolve pathname")
            return claripy.BVV(-1, self.state.arch.bits)

        log.info(f"execveat: dirfd={dirfd_val}, path={path}, flags=0x{flags_val:x}")

        argv_list = self._get_string_array(argv)
        envp_list = self._get_string_array(envp, max_count=10)

        process_tracker = self._get_process_tracker()
        if process_tracker:
            process_tracker.record_execveat(
                state=self.state,
                dirfd=dirfd_val,
                path=path,
                argv=argv_list,
                envp=envp_list,
                flags=flags_val,
            )

        return claripy.BVV(-1, self.state.arch.bits)


class DynFexecve(_BaseExecProcedure):
    """
    SimProcedure for fexecve() that tracks fileless execution.

    Signature: int fexecve(int fd, char *const argv[], char *const envp[])

    This is a strong indicator of fileless code execution since the
    program is executed directly from a file descriptor.
    """

    def run(self, fd, argv, envp):
        fd_val = self._concretize(fd, -1)

        log.warning(f"fexecve: fd={fd_val} - FILELESS EXECUTION DETECTED")

        # Try to resolve filepath from memory tracker
        filepath = None
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            filepath = memory_tracker.get_filepath_for_fd(fd_val)
            if filepath:
                log.info(f"fexecve: resolved fd={fd_val} to path={filepath}")

        argv_list = self._get_string_array(argv)
        envp_list = self._get_string_array(envp, max_count=10)

        process_tracker = self._get_process_tracker()
        if process_tracker:
            process_tracker.record_fexecve(
                state=self.state,
                fd=fd_val,
                argv=argv_list,
                envp=envp_list,
                filepath=filepath,
            )

        # Notify technique about fileless execution
        technique = self._get_technique()
        if technique is not None and hasattr(technique, '_record_fileless_exec'):
            try:
                technique._record_fileless_exec(
                    state=self.state, fd=fd_val,
                    filepath=filepath, argv=argv_list,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

        return claripy.BVV(-1, self.state.arch.bits)
