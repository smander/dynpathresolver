"""
SimProcedure for ptrace() syscall.

This procedure intercepts process tracing operations to detect
anti-debugging techniques and code injection via ptrace.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSER,
    PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSER,
    PTRACE_CONT, PTRACE_KILL, PTRACE_SINGLESTEP,
    PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_ATTACH, PTRACE_DETACH,
    PTRACE_SEIZE,
)

if TYPE_CHECKING:
    from ...security_tracker import SecurityPolicyTracker
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynPtrace(angr.SimProcedure):
    """
    SimProcedure for ptrace() that tracks process tracing.

    Signature: long ptrace(enum __ptrace_request request, pid_t pid,
                           void *addr, void *data)

    This procedure:
    1. Extracts ptrace request and arguments
    2. Detects anti-debug (PTRACE_TRACEME)
    3. Detects code injection (PTRACE_POKETEXT/POKEDATA)
    4. Records events in SecurityPolicyTracker
    """

    # Class-level configuration (set by DynPathResolver)
    security_tracker: "SecurityPolicyTracker | None" = None
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # Track whether PTRACE_TRACEME has been called (anti-debug detection)
    _is_traced: bool = False

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_security_tracker(self):
        """Get security_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_security_tracker', self.__class__.security_tracker)
        return self.__class__.security_tracker

    def _get_memory_tracker(self):
        """Get memory_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_memory_tracker', self.__class__.memory_tracker)
        return self.__class__.memory_tracker

    def run(self, request, pid, addr, data):
        """
        Simulate ptrace(request, pid, addr, data).

        Args:
            request: ptrace operation (PTRACE_*)
            pid: Target process ID (0 for self in TRACEME)
            addr: Address argument (meaning depends on request)
            data: Data argument (meaning depends on request)

        Returns:
            Request-specific return value
        """
        # Concretize arguments
        request_val = self._concretize(request, 0)
        pid_val = self._concretize(pid, 0)
        addr_val = self._concretize(addr, 0)
        data_val = self._concretize(data, 0)

        log.debug(f"ptrace: request={request_val}, pid={pid_val}, "
                  f"addr=0x{addr_val:x}, data=0x{data_val:x}")

        # Record in security tracker
        security_tracker = self._get_security_tracker()
        if security_tracker:
            security_tracker.record_ptrace(
                state=self.state,
                request=request_val,
                pid=pid_val,
                addr=addr_val,
                data=data_val,
            )

        # Handle specific requests
        result = self._handle_request(request_val, pid_val, addr_val, data_val)

        return claripy.BVV(result, self.state.arch.bits)

    def _handle_request(self, request: int, pid: int,
                        addr: int, data: int) -> int:
        """Handle specific ptrace requests."""
        if request == PTRACE_TRACEME:
            # Anti-debug: process requests to be traced
            # If already traced, this fails - common anti-debug check
            if self.state.globals.get('dpr_ptrace_is_traced', False):
                log.info("ptrace TRACEME: already traced, returning -1")
                return -1  # EPERM
            else:
                self.state.globals['dpr_ptrace_is_traced'] = True
                log.warning("ptrace TRACEME: anti-debug technique detected")
                self._notify_anti_debug()
                return 0

        elif request == PTRACE_ATTACH:
            # Attach to another process
            log.info(f"ptrace ATTACH to pid={pid}")
            return 0

        elif request == PTRACE_SEIZE:
            # Modern attach without stopping
            log.info(f"ptrace SEIZE pid={pid}")
            return 0

        elif request == PTRACE_DETACH:
            # Detach from traced process
            log.debug(f"ptrace DETACH from pid={pid}")
            return 0

        elif request == PTRACE_PEEKTEXT:
            # Read word from tracee's text
            log.debug(f"ptrace PEEKTEXT pid={pid} addr=0x{addr:x}")
            # Return some placeholder data
            return 0

        elif request == PTRACE_PEEKDATA:
            # Read word from tracee's data
            log.debug(f"ptrace PEEKDATA pid={pid} addr=0x{addr:x}")
            return 0

        elif request == PTRACE_POKETEXT:
            # Write word to tracee's text - CODE INJECTION
            log.warning(f"ptrace POKETEXT: code injection to pid={pid} "
                       f"addr=0x{addr:x} data=0x{data:x}")
            self._notify_code_injection(pid, addr, data, "POKETEXT")
            return 0

        elif request == PTRACE_POKEDATA:
            # Write word to tracee's data - potential code injection
            log.warning(f"ptrace POKEDATA: data injection to pid={pid} "
                       f"addr=0x{addr:x} data=0x{data:x}")
            self._notify_code_injection(pid, addr, data, "POKEDATA")
            return 0

        elif request == PTRACE_GETREGS:
            # Get registers - used in debugging
            log.debug(f"ptrace GETREGS pid={pid}")
            return 0

        elif request == PTRACE_SETREGS:
            # Set registers - could be used to hijack execution
            log.info(f"ptrace SETREGS pid={pid}")
            return 0

        elif request == PTRACE_CONT:
            # Continue execution
            log.debug(f"ptrace CONT pid={pid}")
            return 0

        elif request == PTRACE_SINGLESTEP:
            # Single step execution
            log.debug(f"ptrace SINGLESTEP pid={pid}")
            return 0

        elif request == PTRACE_KILL:
            # Kill traced process
            log.info(f"ptrace KILL pid={pid}")
            return 0

        else:
            # Unknown request
            log.debug(f"ptrace: unknown request {request}")
            return 0

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _notify_anti_debug(self) -> None:
        """Notify about anti-debug detection."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_anti_debug'):
            try:
                technique._record_anti_debug(
                    state=self.state,
                    technique='ptrace_traceme',
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    def _notify_code_injection(self, pid: int, addr: int,
                               data: int, poke_type: str) -> None:
        """Notify about code injection via ptrace."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_ptrace_injection'):
            try:
                technique._record_ptrace_injection(
                    state=self.state,
                    pid=pid,
                    addr=addr,
                    data=data,
                    poke_type=poke_type,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.security_tracker = None
        cls.memory_tracker = None
        cls.technique = None
        cls._is_traced = False
