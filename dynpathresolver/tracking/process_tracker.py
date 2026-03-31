"""
Process execution tracking for syscall-level detection.

This module tracks process replacement via execve/execveat/fexecve syscalls
to detect hidden program execution and staged loading.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import CLONE_VM, CLONE_THREAD

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class ExecutedProgram:
    """Represents a program executed via exec*() syscalls."""

    path: str
    argv: list[str] = field(default_factory=list)
    envp: list[str] = field(default_factory=list)
    exec_type: str = "execve"  # 'execve', 'execveat', 'fexecve'
    fd: int | None = None  # For fexecve
    dirfd: int | None = None  # For execveat
    flags: int = 0  # For execveat (AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW)
    state_addr: int = 0
    step: int = 0


@dataclass
class ClonedProcess:
    """Represents a process/thread created via clone/clone3."""

    flags: int
    stack_addr: int | None = None
    parent_tid_addr: int | None = None
    child_tid_addr: int | None = None
    tls_addr: int | None = None
    clone_type: str = "clone"  # 'clone', 'clone3', 'fork', 'vfork'
    state_addr: int = 0
    step: int = 0

    @property
    def shares_memory(self) -> bool:
        """Check if child shares memory with parent (CLONE_VM)."""
        return bool(self.flags & CLONE_VM)

    @property
    def is_thread(self) -> bool:
        """Check if this is a thread (CLONE_THREAD)."""
        return bool(self.flags & CLONE_THREAD)


class ProcessExecutionTracker:
    """
    Tracks process execution and creation during symbolic execution.

    This class:
    1. Records execve/execveat/fexecve calls
    2. Tracks clone/clone3/fork/vfork for process creation
    3. Correlates with file descriptors for fexecve
    4. Identifies suspicious execution patterns
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Execution tracking
        self.executed_programs: list[ExecutedProgram] = []
        self.cloned_processes: list[ClonedProcess] = []

        # Statistics
        self.total_execs: int = 0
        self.total_clones: int = 0

    def record_execve(self, state: "angr.SimState", path: str,
                      argv: list[str] | None = None,
                      envp: list[str] | None = None) -> ExecutedProgram:
        """
        Record an execve() syscall.

        Args:
            state: Current symbolic state
            path: Program path to execute
            argv: Command line arguments
            envp: Environment variables

        Returns:
            The recorded ExecutedProgram
        """
        self.total_execs += 1

        program = ExecutedProgram(
            path=path,
            argv=argv or [],
            envp=envp or [],
            exec_type="execve",
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.executed_programs.append(program)

        log.info(f"Tracked execve: path={path}")
        return program

    def record_execveat(self, state: "angr.SimState", dirfd: int, path: str,
                        argv: list[str] | None = None,
                        envp: list[str] | None = None,
                        flags: int = 0) -> ExecutedProgram:
        """
        Record an execveat() syscall.

        Args:
            state: Current symbolic state
            dirfd: Directory file descriptor (AT_FDCWD for current dir)
            path: Program path (relative to dirfd)
            argv: Command line arguments
            envp: Environment variables
            flags: AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW

        Returns:
            The recorded ExecutedProgram
        """
        self.total_execs += 1

        program = ExecutedProgram(
            path=path,
            argv=argv or [],
            envp=envp or [],
            exec_type="execveat",
            dirfd=dirfd,
            flags=flags,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.executed_programs.append(program)

        log.info(f"Tracked execveat: dirfd={dirfd}, path={path}, flags=0x{flags:x}")
        return program

    def record_fexecve(self, state: "angr.SimState", fd: int,
                       argv: list[str] | None = None,
                       envp: list[str] | None = None,
                       filepath: str | None = None) -> ExecutedProgram:
        """
        Record an fexecve() syscall.

        Args:
            state: Current symbolic state
            fd: File descriptor of program to execute
            argv: Command line arguments
            envp: Environment variables
            filepath: Resolved filepath (if known from memory tracker)

        Returns:
            The recorded ExecutedProgram
        """
        self.total_execs += 1

        # fexecve is a strong indicator of fileless execution
        log.warning(f"fexecve detected: fd={fd} - potential fileless execution")

        path = filepath or f"/proc/self/fd/{fd}"

        program = ExecutedProgram(
            path=path,
            argv=argv or [],
            envp=envp or [],
            exec_type="fexecve",
            fd=fd,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.executed_programs.append(program)

        return program

    def record_clone(self, state: "angr.SimState", flags: int,
                     stack: int | None = None,
                     parent_tid: int | None = None,
                     child_tid: int | None = None,
                     tls: int | None = None,
                     clone_type: str = "clone") -> ClonedProcess:
        """
        Record a clone/clone3/fork/vfork syscall.

        Args:
            state: Current symbolic state
            flags: Clone flags (CLONE_VM, CLONE_THREAD, etc.)
            stack: Stack pointer for child
            parent_tid: Address to store parent TID
            child_tid: Address to store child TID
            tls: TLS descriptor
            clone_type: Type of clone ('clone', 'clone3', 'fork', 'vfork')

        Returns:
            The recorded ClonedProcess
        """
        self.total_clones += 1

        process = ClonedProcess(
            flags=flags,
            stack_addr=stack,
            parent_tid_addr=parent_tid,
            child_tid_addr=child_tid,
            tls_addr=tls,
            clone_type=clone_type,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.cloned_processes.append(process)

        # Log security-relevant flags
        if process.shares_memory:
            log.warning(f"clone with CLONE_VM: child shares memory with parent")

        log.debug(f"Tracked {clone_type}: flags=0x{flags:x}")
        return process

    # === Query Methods ===

    def get_executed_programs(self) -> list[ExecutedProgram]:
        """Get all executed programs."""
        return self.executed_programs.copy()

    def get_fexecve_programs(self) -> list[ExecutedProgram]:
        """Get programs executed via fexecve (fileless execution)."""
        return [p for p in self.executed_programs if p.exec_type == "fexecve"]

    def get_memory_sharing_clones(self) -> list[ClonedProcess]:
        """Get clones that share memory with parent (potential code injection)."""
        return [p for p in self.cloned_processes if p.shares_memory]

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_execs': self.total_execs,
            'total_clones': self.total_clones,
            'execve_count': len([p for p in self.executed_programs
                                if p.exec_type == "execve"]),
            'execveat_count': len([p for p in self.executed_programs
                                  if p.exec_type == "execveat"]),
            'fexecve_count': len([p for p in self.executed_programs
                                 if p.exec_type == "fexecve"]),
            'clone_vm_count': len(self.get_memory_sharing_clones()),
        }

    def reset(self):
        """Reset all tracking state."""
        self.executed_programs.clear()
        self.cloned_processes.clear()
        self.total_execs = 0
        self.total_clones = 0
