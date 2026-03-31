"""
Security policy tracking for syscall-level detection.

This module tracks security-relevant syscalls like prctl, ptrace, and
seccomp to detect anti-debugging techniques and sandbox evasion.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import (
    PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_SET_DUMPABLE, PR_GET_DUMPABLE,
    PR_SET_SECCOMP, PR_GET_SECCOMP, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS,
    PR_SET_NAME, PR_GET_NAME,
    PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSER,
    PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSER,
    PTRACE_CONT, PTRACE_KILL, PTRACE_SINGLESTEP,
    PTRACE_ATTACH, PTRACE_DETACH, PTRACE_SEIZE,
    SECCOMP_MODE_DISABLED, SECCOMP_MODE_STRICT, SECCOMP_MODE_FILTER,
)

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class PrctlEvent:
    """Represents a prctl() syscall."""

    option: int
    option_name: str
    arg2: int
    arg3: int
    arg4: int
    arg5: int
    state_addr: int = 0
    step: int = 0


@dataclass
class PtraceEvent:
    """Represents a ptrace() syscall."""

    request: int
    request_name: str
    pid: int
    addr: int
    data: int
    state_addr: int = 0
    step: int = 0

    @property
    def is_anti_debug(self) -> bool:
        """Check if this is likely an anti-debug technique."""
        return self.request == PTRACE_TRACEME

    @property
    def is_code_injection(self) -> bool:
        """Check if this could be used for code injection."""
        return self.request in (PTRACE_POKETEXT, PTRACE_POKEDATA)


@dataclass
class SecurityPolicyChange:
    """Represents a security policy change."""

    policy_type: str  # 'seccomp', 'dumpable', 'no_new_privs'
    old_value: int | None
    new_value: int
    state_addr: int = 0
    step: int = 0


class SecurityPolicyTracker:
    """
    Tracks security-relevant syscalls during symbolic execution.

    This class:
    1. Records prctl() calls for security policy changes
    2. Tracks ptrace() for anti-debug and code injection
    3. Monitors seccomp policy changes
    4. Identifies suspicious security manipulations
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Event tracking
        self.prctl_events: list[PrctlEvent] = []
        self.ptrace_events: list[PtraceEvent] = []
        self.policy_changes: list[SecurityPolicyChange] = []

        # Current policy state
        self.seccomp_mode: int = SECCOMP_MODE_DISABLED
        self.is_dumpable: bool = True
        self.no_new_privs: bool = False
        self.is_traced: bool = False

        # Statistics
        self.total_prctls: int = 0
        self.total_ptraces: int = 0

    def record_prctl(self, state: "angr.SimState", option: int,
                     arg2: int = 0, arg3: int = 0,
                     arg4: int = 0, arg5: int = 0) -> PrctlEvent:
        """
        Record a prctl() syscall.

        Args:
            state: Current symbolic state
            option: prctl option (PR_SET_*)
            arg2-arg5: Additional arguments

        Returns:
            The recorded PrctlEvent
        """
        self.total_prctls += 1

        option_name = self._get_prctl_name(option)

        event = PrctlEvent(
            option=option,
            option_name=option_name,
            arg2=arg2,
            arg3=arg3,
            arg4=arg4,
            arg5=arg5,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.prctl_events.append(event)

        # Track security policy changes
        self._handle_prctl_policy(state, option, arg2)

        log.debug(f"Tracked prctl: {option_name} ({option})")
        return event

    def _handle_prctl_policy(self, state: "angr.SimState",
                            option: int, arg: int) -> None:
        """Handle security policy changes from prctl."""
        step = state.history.depth if state.history else 0

        if option == PR_SET_SECCOMP:
            old_mode = self.seccomp_mode
            self.seccomp_mode = arg
            self.policy_changes.append(SecurityPolicyChange(
                policy_type='seccomp',
                old_value=old_mode,
                new_value=arg,
                state_addr=state.addr,
                step=step,
            ))
            log.info(f"Seccomp mode changed: {old_mode} -> {arg}")

        elif option == PR_SET_DUMPABLE:
            old_dumpable = self.is_dumpable
            self.is_dumpable = bool(arg)
            self.policy_changes.append(SecurityPolicyChange(
                policy_type='dumpable',
                old_value=int(old_dumpable),
                new_value=arg,
                state_addr=state.addr,
                step=step,
            ))
            if not self.is_dumpable:
                log.warning("Process set non-dumpable (anti-debug indicator)")

        elif option == PR_SET_NO_NEW_PRIVS:
            old_privs = self.no_new_privs
            self.no_new_privs = bool(arg)
            self.policy_changes.append(SecurityPolicyChange(
                policy_type='no_new_privs',
                old_value=int(old_privs),
                new_value=arg,
                state_addr=state.addr,
                step=step,
            ))

    def _get_prctl_name(self, option: int) -> str:
        """Get human-readable prctl option name."""
        names = {
            PR_SET_PDEATHSIG: "PR_SET_PDEATHSIG",
            PR_GET_PDEATHSIG: "PR_GET_PDEATHSIG",
            PR_SET_DUMPABLE: "PR_SET_DUMPABLE",
            PR_GET_DUMPABLE: "PR_GET_DUMPABLE",
            PR_SET_SECCOMP: "PR_SET_SECCOMP",
            PR_GET_SECCOMP: "PR_GET_SECCOMP",
            PR_SET_NO_NEW_PRIVS: "PR_SET_NO_NEW_PRIVS",
            PR_GET_NO_NEW_PRIVS: "PR_GET_NO_NEW_PRIVS",
            PR_SET_NAME: "PR_SET_NAME",
            PR_GET_NAME: "PR_GET_NAME",
        }
        return names.get(option, f"UNKNOWN({option})")

    def record_ptrace(self, state: "angr.SimState", request: int,
                      pid: int = 0, addr: int = 0,
                      data: int = 0) -> PtraceEvent:
        """
        Record a ptrace() syscall.

        Args:
            state: Current symbolic state
            request: ptrace request (PTRACE_*)
            pid: Target process ID
            addr: Address argument
            data: Data argument

        Returns:
            The recorded PtraceEvent
        """
        self.total_ptraces += 1

        request_name = self._get_ptrace_name(request)

        event = PtraceEvent(
            request=request,
            request_name=request_name,
            pid=pid,
            addr=addr,
            data=data,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.ptrace_events.append(event)

        # Handle specific ptrace operations
        if event.is_anti_debug:
            self.is_traced = True
            log.warning("PTRACE_TRACEME detected - anti-debug technique")

        if event.is_code_injection:
            log.warning(f"ptrace code injection: {request_name} "
                       f"pid={pid} addr=0x{addr:x}")

        log.debug(f"Tracked ptrace: {request_name} pid={pid}")
        return event

    def _get_ptrace_name(self, request: int) -> str:
        """Get human-readable ptrace request name."""
        names = {
            PTRACE_TRACEME: "PTRACE_TRACEME",
            PTRACE_PEEKTEXT: "PTRACE_PEEKTEXT",
            PTRACE_PEEKDATA: "PTRACE_PEEKDATA",
            PTRACE_PEEKUSER: "PTRACE_PEEKUSER",
            PTRACE_POKETEXT: "PTRACE_POKETEXT",
            PTRACE_POKEDATA: "PTRACE_POKEDATA",
            PTRACE_POKEUSER: "PTRACE_POKEUSER",
            PTRACE_CONT: "PTRACE_CONT",
            PTRACE_KILL: "PTRACE_KILL",
            PTRACE_SINGLESTEP: "PTRACE_SINGLESTEP",
            PTRACE_ATTACH: "PTRACE_ATTACH",
            PTRACE_DETACH: "PTRACE_DETACH",
            PTRACE_SEIZE: "PTRACE_SEIZE",
        }
        return names.get(request, f"UNKNOWN({request})")

    # === Query Methods ===

    def get_anti_debug_events(self) -> list[PtraceEvent]:
        """Get ptrace events that indicate anti-debug techniques."""
        return [e for e in self.ptrace_events if e.is_anti_debug]

    def get_code_injection_events(self) -> list[PtraceEvent]:
        """Get ptrace events that could be code injection."""
        return [e for e in self.ptrace_events if e.is_code_injection]

    def get_policy_changes(self) -> list[SecurityPolicyChange]:
        """Get all security policy changes."""
        return self.policy_changes.copy()

    def has_anti_debug(self) -> bool:
        """Check if any anti-debug techniques were detected."""
        if self.is_traced:
            return True
        if not self.is_dumpable:
            return True
        return len(self.get_anti_debug_events()) > 0

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_prctls': self.total_prctls,
            'total_ptraces': self.total_ptraces,
            'seccomp_mode': self.seccomp_mode,
            'is_dumpable': self.is_dumpable,
            'no_new_privs': self.no_new_privs,
            'is_traced': self.is_traced,
            'anti_debug_count': len(self.get_anti_debug_events()),
            'code_injection_count': len(self.get_code_injection_events()),
            'policy_changes': len(self.policy_changes),
        }

    def reset(self):
        """Reset all tracking state."""
        self.prctl_events.clear()
        self.ptrace_events.clear()
        self.policy_changes.clear()
        self.seccomp_mode = SECCOMP_MODE_DISABLED
        self.is_dumpable = True
        self.no_new_privs = False
        self.is_traced = False
        self.total_prctls = 0
        self.total_ptraces = 0
