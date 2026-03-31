"""
SimProcedures for signal handling syscalls.

These procedures track signal handler registration to detect
library loading that occurs in signal handlers.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    SIG_DFL, SIG_IGN,
    SA_NOCLDSTOP, SA_NOCLDWAIT, SA_SIGINFO, SA_RESTART,
    SA_NODEFER, SA_RESETHAND,
)

if TYPE_CHECKING:
    from ...signal_handler import SignalHandlerTracker

log = logging.getLogger(__name__)


class DynSigaction(angr.SimProcedure):
    """
    SimProcedure for sigaction() that tracks signal handlers.

    Signature: int sigaction(int signum, const struct sigaction *act,
                             struct sigaction *oldact)

    This procedure:
    1. Extracts signal number and handler address
    2. Records the handler in SignalHandlerTracker
    3. Optionally writes old handler to oldact
    4. Returns 0 on success
    """

    # Class-level configuration (set by DynPathResolver)
    signal_tracker: "SignalHandlerTracker | None" = None
    technique: "object | None" = None

    # sigaction struct offsets (Linux x86_64)
    # struct sigaction {
    #     void (*sa_handler)(int);       // offset 0
    #     sigset_t sa_mask;              // offset 8
    #     int sa_flags;                  // offset 136
    #     void (*sa_restorer)(void);     // offset 144
    # }
    SA_HANDLER_OFFSET = 0
    SA_MASK_OFFSET = 8
    SA_FLAGS_OFFSET = 136

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_signal_tracker(self):
        """Get signal_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_signal_tracker', self.__class__.signal_tracker)
        return self.__class__.signal_tracker

    def run(self, signum, act, oldact):
        """
        Simulate sigaction(signum, act, oldact).

        Args:
            signum: Signal number
            act: Pointer to new sigaction struct (or NULL)
            oldact: Pointer to receive old sigaction struct (or NULL)

        Returns:
            0 on success, -1 on error
        """
        # Concretize arguments
        signum_val = self._concretize(signum, 0)
        act_val = self._concretize(act, 0)
        oldact_val = self._concretize(oldact, 0)

        log.debug(f"sigaction: signum={signum_val}, act=0x{act_val:x}, "
                  f"oldact=0x{oldact_val:x}")

        # Handle oldact - write current handler if requested
        signal_tracker = self._get_signal_tracker()
        if oldact_val != 0 and signal_tracker:
            old_handler = signal_tracker.get_handler(signum_val)
            if old_handler:
                self._write_sigaction(oldact_val, old_handler.handler_addr,
                                      old_handler.flags, old_handler.mask)

        # Handle act - register new handler if provided
        if act_val != 0:
            handler_addr = self._read_handler(act_val)
            flags = self._read_flags(act_val)
            mask = self._read_mask(act_val)

            log.info(f"sigaction: Registering handler for signal {signum_val} "
                     f"at 0x{handler_addr:x}")

            # Record in signal tracker if available
            if signal_tracker:
                signal_tracker.record_sigaction(
                    state=self.state,
                    signum=signum_val,
                    handler_addr=handler_addr,
                    flags=flags,
                    mask=mask,
                )

        return claripy.BVV(0, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _read_handler(self, act_addr: int) -> int:
        """Read sa_handler from sigaction struct."""
        try:
            handler = self.state.memory.load(
                act_addr + self.SA_HANDLER_OFFSET,
                self.state.arch.bytes,
                endness=self.state.arch.memory_endness
            )
            return self._concretize(handler, 0)
        except Exception as e:
            log.debug(f"Error reading handler: {e}")
            return 0

    def _read_flags(self, act_addr: int) -> int:
        """Read sa_flags from sigaction struct."""
        try:
            flags = self.state.memory.load(
                act_addr + self.SA_FLAGS_OFFSET,
                4,  # int is 4 bytes
                endness=self.state.arch.memory_endness
            )
            return self._concretize(flags, 0)
        except Exception as e:
            log.debug(f"Error reading flags: {e}")
            return 0

    def _read_mask(self, act_addr: int) -> int:
        """Read sa_mask from sigaction struct (simplified)."""
        try:
            # Just read first 8 bytes of mask
            mask = self.state.memory.load(
                act_addr + self.SA_MASK_OFFSET,
                8,
                endness=self.state.arch.memory_endness
            )
            return self._concretize(mask, 0)
        except Exception as e:
            log.debug(f"Error reading mask: {e}")
            return 0

    def _write_sigaction(self, addr: int, handler: int, flags: int,
                         mask: int) -> None:
        """Write sigaction struct to memory."""
        try:
            self.state.memory.store(
                addr + self.SA_HANDLER_OFFSET,
                claripy.BVV(handler, self.state.arch.bits),
                endness=self.state.arch.memory_endness
            )
            self.state.memory.store(
                addr + self.SA_FLAGS_OFFSET,
                claripy.BVV(flags, 32),
                endness=self.state.arch.memory_endness
            )
        except Exception as e:
            log.debug(f"Error writing sigaction: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.signal_tracker = None
        cls.technique = None


class DynSignal(angr.SimProcedure):
    """
    SimProcedure for signal() that tracks signal handlers.

    Signature: sighandler_t signal(int signum, sighandler_t handler)

    Simpler interface than sigaction - just signal number and handler.
    """

    # Class-level configuration (set by DynPathResolver)
    signal_tracker: "SignalHandlerTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_signal_tracker(self):
        """Get signal_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_signal_tracker', self.__class__.signal_tracker)
        return self.__class__.signal_tracker

    def run(self, signum, handler):
        """
        Simulate signal(signum, handler).

        Args:
            signum: Signal number
            handler: Handler function pointer (or SIG_DFL, SIG_IGN)

        Returns:
            Previous handler on success, SIG_ERR (-1) on error
        """
        # Concretize arguments
        signum_val = self._concretize(signum, 0)
        handler_val = self._concretize(handler, 0)

        log.info(f"signal: signum={signum_val}, handler=0x{handler_val:x}")

        # Get old handler for return value
        old_handler = 0
        signal_tracker = self._get_signal_tracker()
        if signal_tracker:
            old = signal_tracker.get_handler(signum_val)
            if old:
                old_handler = old.handler_addr

            # Record new handler
            signal_tracker.record_signal(
                state=self.state,
                signum=signum_val,
                handler_addr=handler_val,
            )

        return claripy.BVV(old_handler, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.signal_tracker = None
        cls.technique = None


class DynRaise(angr.SimProcedure):
    """
    SimProcedure for raise() that tracks signal raising.

    Signature: int raise(int sig)
    """

    # Class-level configuration
    signal_tracker: "SignalHandlerTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_signal_tracker(self):
        """Get signal_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_signal_tracker', self.__class__.signal_tracker)
        return self.__class__.signal_tracker

    def run(self, sig):
        """
        Simulate raise(sig).

        Args:
            sig: Signal to raise

        Returns:
            0 on success
        """
        sig_val = self._concretize(sig, 0)

        log.info(f"raise: signal={sig_val}")

        signal_tracker = self._get_signal_tracker()
        if signal_tracker:
            signal_tracker.record_raise(self.state, sig_val)

            # Look up registered handler and redirect execution to it
            handler = signal_tracker.get_handler(sig_val)
            if handler and handler.handler_addr not in (0, 1):  # Not SIG_DFL/SIG_IGN
                log.warning(f"raise: redirecting to signal handler at 0x{handler.handler_addr:x}")
                signal_tracker.record_handler_invocation(self.state, sig_val)
                self.call(handler.handler_addr, [sig_val], continue_at='_handler_return')
                return  # Don't return value yet, wait for handler

        return claripy.BVV(0, self.state.arch.bits)

    def _handler_return(self, handler_result=None):
        """Return point after signal handler execution."""
        return claripy.BVV(0, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.signal_tracker = None
        cls.technique = None
