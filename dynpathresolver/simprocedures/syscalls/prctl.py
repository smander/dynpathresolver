"""
SimProcedure for prctl() syscall.

This procedure intercepts process control operations to detect
security policy changes and anti-debugging techniques.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_SET_DUMPABLE, PR_GET_DUMPABLE,
    PR_SET_SECCOMP, PR_GET_SECCOMP, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS,
    PR_SET_NAME, PR_GET_NAME,
)

if TYPE_CHECKING:
    from ...security_tracker import SecurityPolicyTracker

log = logging.getLogger(__name__)


class DynPrctl(angr.SimProcedure):
    """
    SimProcedure for prctl() that tracks security policy changes.

    Signature: int prctl(int option, unsigned long arg2, unsigned long arg3,
                         unsigned long arg4, unsigned long arg5)

    This procedure:
    1. Extracts prctl option and arguments
    2. Records security-relevant changes in SecurityPolicyTracker
    3. Detects anti-debug techniques (PR_SET_DUMPABLE=0)
    4. Returns appropriate values based on the option
    """

    # Class-level configuration (set by DynPathResolver)
    security_tracker: "SecurityPolicyTracker | None" = None
    technique: "object | None" = None

    # Simulated state for GET operations
    _dumpable: int = 1
    _seccomp: int = 0
    _no_new_privs: int = 0

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

    def run(self, option, arg2, arg3, arg4, arg5):
        """
        Simulate prctl(option, arg2, arg3, arg4, arg5).

        Args:
            option: prctl operation (PR_SET_*, PR_GET_*)
            arg2-arg5: Operation-specific arguments

        Returns:
            0 on success, -1 on error, or value for GET operations
        """
        # Concretize arguments
        option_val = self._concretize(option, 0)
        arg2_val = self._concretize(arg2, 0)
        arg3_val = self._concretize(arg3, 0)
        arg4_val = self._concretize(arg4, 0)
        arg5_val = self._concretize(arg5, 0)

        log.debug(f"prctl: option={option_val}, arg2={arg2_val}")

        # Record in security tracker
        security_tracker = self._get_security_tracker()
        if security_tracker:
            security_tracker.record_prctl(
                state=self.state,
                option=option_val,
                arg2=arg2_val,
                arg3=arg3_val,
                arg4=arg4_val,
                arg5=arg5_val,
            )

        # Handle specific options
        result = self._handle_option(option_val, arg2_val)

        # Notify technique about security-relevant changes
        self._notify_technique(option_val, arg2_val)

        return claripy.BVV(result, self.state.arch.bits)

    def _handle_option(self, option: int, arg: int) -> int:
        """Handle specific prctl options and return appropriate value."""
        if option == PR_SET_DUMPABLE:
            self.state.globals['dpr_prctl_dumpable'] = arg
            if arg == 0:
                log.warning("prctl PR_SET_DUMPABLE=0: anti-debug indicator")
            return 0

        elif option == PR_GET_DUMPABLE:
            return self.state.globals.get('dpr_prctl_dumpable', 1)

        elif option == PR_SET_SECCOMP:
            self.state.globals['dpr_prctl_seccomp'] = arg
            log.info(f"prctl PR_SET_SECCOMP: mode={arg}")
            return 0

        elif option == PR_GET_SECCOMP:
            return self.state.globals.get('dpr_prctl_seccomp', 0)

        elif option == PR_SET_NO_NEW_PRIVS:
            self.state.globals['dpr_prctl_no_new_privs'] = arg
            return 0

        elif option == PR_GET_NO_NEW_PRIVS:
            return self.state.globals.get('dpr_prctl_no_new_privs', 0)

        elif option == PR_SET_NAME:
            # Process name change - just acknowledge it
            return 0

        elif option == PR_GET_NAME:
            # Would need to write to arg2 pointer - skip for now
            return 0

        else:
            # Unknown option - return success
            return 0

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _notify_technique(self, option: int, arg: int) -> None:
        """Notify the technique about security policy changes."""
        technique = self._get_technique()
        if technique is None:
            return

        # Notify about anti-debug
        if option == PR_SET_DUMPABLE and arg == 0:
            if hasattr(technique, '_record_anti_debug'):
                try:
                    technique._record_anti_debug(
                        state=self.state,
                        technique='prctl_dumpable',
                    )
                except Exception as e:
                    log.debug(f"Failed to notify technique: {e}")

        # Notify about seccomp
        if option == PR_SET_SECCOMP:
            if hasattr(technique, '_record_seccomp'):
                try:
                    technique._record_seccomp(
                        state=self.state,
                        mode=arg,
                    )
                except Exception as e:
                    log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.security_tracker = None
        cls.technique = None
        cls._dumpable = 1
        cls._seccomp = 0
        cls._no_new_privs = 0
