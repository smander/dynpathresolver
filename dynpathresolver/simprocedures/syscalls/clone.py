"""
SimProcedures for clone() and clone3() syscalls.

These procedures intercept process/thread creation to detect
memory-sharing clones that could be used for code injection.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND,
    CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT, CLONE_THREAD,
    CLONE_NEWNS, CLONE_SYSVSEM, CLONE_SETTLS,
    CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_DETACHED,
    CLONE_CHILD_SETTID, CLONE_NEWCGROUP, CLONE_NEWUTS,
    CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, CLONE_IO,
)

if TYPE_CHECKING:
    from ...process_tracker import ProcessExecutionTracker

log = logging.getLogger(__name__)


class DynClone(angr.SimProcedure):
    """
    SimProcedure for clone() that tracks process/thread creation.

    Signature: long clone(unsigned long flags, void *stack,
                          int *parent_tid, int *child_tid, unsigned long tls)

    Note: The exact signature varies by architecture. This handles the
    common x86_64 case.

    This procedure:
    1. Extracts clone flags
    2. Detects memory-sharing clones (CLONE_VM)
    3. Records in ProcessExecutionTracker
    """

    # Class-level configuration (set by DynPathResolver)
    process_tracker: "ProcessExecutionTracker | None" = None
    technique: "object | None" = None

    # PID counter for child processes
    _next_pid: int = 1000

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

    def run(self, flags, stack, parent_tid, child_tid, tls):
        """
        Simulate clone(flags, stack, parent_tid, child_tid, tls).

        Args:
            flags: Clone flags (CLONE_VM, CLONE_THREAD, etc.)
            stack: Stack pointer for child
            parent_tid: Pointer to store parent TID
            child_tid: Pointer to store child TID
            tls: TLS descriptor

        Returns:
            PID of child to parent, 0 to child
        """
        # Concretize arguments
        flags_val = self._concretize(flags, 0)
        stack_val = self._concretize(stack, 0)
        parent_tid_val = self._concretize(parent_tid, 0)
        child_tid_val = self._concretize(child_tid, 0)
        tls_val = self._concretize(tls, 0)

        log.debug(f"clone: flags=0x{flags_val:x}, stack=0x{stack_val:x}")

        # Log security-relevant flags
        self._log_flags(flags_val)

        # Record in process tracker
        process_tracker = self._get_process_tracker()
        if process_tracker:
            process_tracker.record_clone(
                state=self.state,
                flags=flags_val,
                stack=stack_val,
                parent_tid=parent_tid_val,
                child_tid=child_tid_val,
                tls=tls_val,
                clone_type="clone",
            )

        # Notify technique about memory-sharing clones
        if flags_val & CLONE_VM:
            self._notify_memory_sharing(flags_val)

        # Return child PID (we're always the parent in symbolic execution)
        child_pid = self._allocate_pid()
        return claripy.BVV(child_pid, self.state.arch.bits)

    def _log_flags(self, flags: int) -> None:
        """Log security-relevant clone flags."""
        if flags & CLONE_VM:
            log.warning("clone: CLONE_VM - child shares memory with parent")
        if flags & CLONE_THREAD:
            log.debug("clone: CLONE_THREAD - creating thread")
        if flags & CLONE_VFORK:
            log.debug("clone: CLONE_VFORK - vfork-style clone")
        if flags & CLONE_NEWNS:
            log.info("clone: CLONE_NEWNS - new mount namespace")
        if flags & CLONE_NEWPID:
            log.info("clone: CLONE_NEWPID - new PID namespace")
        if flags & CLONE_NEWUSER:
            log.info("clone: CLONE_NEWUSER - new user namespace")

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_pid(cls) -> int:
        """Allocate a PID for child process."""
        pid = cls._next_pid
        cls._next_pid += 1
        return pid

    def _notify_memory_sharing(self, flags: int) -> None:
        """Notify about memory-sharing clone."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_clone_vm'):
            try:
                technique._record_clone_vm(
                    state=self.state,
                    flags=flags,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.process_tracker = None
        cls.technique = None
        cls._next_pid = 1000


class DynClone3(angr.SimProcedure):
    """
    SimProcedure for clone3() that tracks process/thread creation.

    Signature: long clone3(struct clone_args *cl_args, size_t size)

    clone3() is the modern clone interface that uses a structure
    instead of individual arguments.
    """

    # Class-level configuration (set by DynPathResolver)
    process_tracker: "ProcessExecutionTracker | None" = None
    technique: "object | None" = None

    # PID counter
    _next_pid: int = 2000

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

    def run(self, cl_args, size):
        """
        Simulate clone3(cl_args, size).

        Args:
            cl_args: Pointer to clone_args structure
            size: Size of clone_args structure

        Returns:
            PID of child to parent, 0 to child
        """
        # Concretize arguments
        cl_args_val = self._concretize(cl_args, 0)
        size_val = self._concretize(size, 0)

        log.debug(f"clone3: cl_args=0x{cl_args_val:x}, size={size_val}")

        # Extract flags from clone_args structure
        # struct clone_args {
        #   __u64 flags;          // offset 0
        #   __u64 pidfd;          // offset 8
        #   __u64 child_tid;      // offset 16
        #   __u64 parent_tid;     // offset 24
        #   __u64 exit_signal;    // offset 32
        #   __u64 stack;          // offset 40
        #   __u64 stack_size;     // offset 48
        #   __u64 tls;            // offset 56
        #   ...
        # }

        flags_val = 0
        stack_val = 0
        if cl_args_val != 0:
            try:
                flags_val = self.state.mem[cl_args_val].uint64_t.concrete
                stack_val = self.state.mem[cl_args_val + 40].uint64_t.concrete
            except Exception as e:
                log.debug(f"clone3: Error reading clone_args: {e}")

        log.debug(f"clone3: flags=0x{flags_val:x}")

        # Log security-relevant flags
        if flags_val & CLONE_VM:
            log.warning("clone3: CLONE_VM - child shares memory with parent")

        # Record in process tracker
        process_tracker = self._get_process_tracker()
        if process_tracker:
            process_tracker.record_clone(
                state=self.state,
                flags=flags_val,
                stack=stack_val,
                clone_type="clone3",
            )

        # Notify technique about memory-sharing clones
        if flags_val & CLONE_VM:
            self._notify_memory_sharing(flags_val)

        # Return child PID
        child_pid = self._allocate_pid()
        return claripy.BVV(child_pid, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_pid(cls) -> int:
        """Allocate a PID for child process."""
        pid = cls._next_pid
        cls._next_pid += 1
        return pid

    def _notify_memory_sharing(self, flags: int) -> None:
        """Notify about memory-sharing clone."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_clone_vm'):
            try:
                technique._record_clone_vm(
                    state=self.state,
                    flags=flags,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.process_tracker = None
        cls.technique = None
        cls._next_pid = 2000
