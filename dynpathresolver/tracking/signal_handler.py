"""
Signal handler tracking for detecting code execution via signals.

This module tracks signal handler registration to detect:
1. Libraries loaded in signal handlers
2. Code execution triggered by signals
3. Asynchronous control flow hijacking
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import (
    SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE,
    SIGKILL, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM, SIGTERM,
    SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP,
    SIGNAL_NAMES, SIG_DFL, SIG_IGN,
)

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class SignalHandler:
    """Represents a registered signal handler."""

    signal: int
    handler_addr: int
    flags: int = 0
    mask: int = 0
    registered_at: int = 0  # Program address where registered
    step: int = 0


@dataclass
class SignalEvent:
    """Represents a signal-related event."""

    event_type: str  # 'register', 'invoke', 'raise'
    signal: int
    handler_addr: int | None
    source_addr: int
    step: int
    context: dict = field(default_factory=dict)


class SignalHandlerTracker:
    """
    Tracks signal handler registration and invocation.

    This class:
    1. Monitors sigaction/signal calls
    2. Tracks registered handlers by signal number
    3. Records handler invocations
    4. Correlates with library loading in handlers
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Registered handlers: signal -> SignalHandler
        self.handlers: dict[int, SignalHandler] = {}

        # Event history
        self.events: list[SignalEvent] = []

        # Handlers that loaded libraries
        self.loading_handlers: list[SignalHandler] = []

        # Statistics
        self.total_registrations: int = 0
        self.total_invocations: int = 0

    def record_sigaction(self, state: "angr.SimState", signum: int,
                         handler_addr: int, flags: int = 0,
                         mask: int = 0) -> SignalHandler:
        """
        Record a sigaction() call.

        Args:
            state: Current symbolic state
            signum: Signal number
            handler_addr: Address of handler function
            flags: Signal flags (SA_RESTART, etc.)
            mask: Signal mask

        Returns:
            The created SignalHandler
        """
        self.total_registrations += 1

        signal_name = SIGNAL_NAMES.get(signum, f"SIG{signum}")

        handler = SignalHandler(
            signal=signum,
            handler_addr=handler_addr,
            flags=flags,
            mask=mask,
            registered_at=state.addr,
            step=state.history.depth if state.history else 0,
        )

        # Store (overwrites previous handler for same signal)
        old_handler = self.handlers.get(signum)
        self.handlers[signum] = handler

        # Record event
        event = SignalEvent(
            event_type='register',
            signal=signum,
            handler_addr=handler_addr,
            source_addr=state.addr,
            step=handler.step,
            context={
                'old_handler': old_handler.handler_addr if old_handler else None,
                'flags': flags,
            }
        )
        self.events.append(event)

        log.info(f"Signal handler registered: {signal_name} -> 0x{handler_addr:x}")

        return handler

    def record_signal(self, state: "angr.SimState", signum: int,
                      handler_addr: int) -> SignalHandler:
        """
        Record a signal() call (simpler than sigaction).

        Args:
            state: Current symbolic state
            signum: Signal number
            handler_addr: Address of handler function

        Returns:
            The created SignalHandler
        """
        return self.record_sigaction(state, signum, handler_addr)

    def record_raise(self, state: "angr.SimState", signum: int) -> None:
        """
        Record a raise() or kill(getpid(), sig) call.

        Args:
            state: Current symbolic state
            signum: Signal number being raised
        """
        signal_name = SIGNAL_NAMES.get(signum, f"SIG{signum}")

        event = SignalEvent(
            event_type='raise',
            signal=signum,
            handler_addr=self.handlers.get(signum, SignalHandler(0, 0)).handler_addr,
            source_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.events.append(event)

        log.info(f"Signal raised: {signal_name}")

    def record_handler_invocation(self, state: "angr.SimState",
                                   signum: int) -> None:
        """
        Record when a signal handler is invoked.

        Args:
            state: Current symbolic state
            signum: Signal number
        """
        self.total_invocations += 1

        handler = self.handlers.get(signum)
        if not handler:
            return

        signal_name = SIGNAL_NAMES.get(signum, f"SIG{signum}")

        event = SignalEvent(
            event_type='invoke',
            signal=signum,
            handler_addr=handler.handler_addr,
            source_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.events.append(event)

        log.info(f"Signal handler invoked: {signal_name} at 0x{handler.handler_addr:x}")

    def mark_handler_loaded_library(self, handler: SignalHandler) -> None:
        """Mark that a handler loaded a library."""
        if handler not in self.loading_handlers:
            self.loading_handlers.append(handler)
            log.warning(f"Signal handler loaded library: signal {handler.signal}")

    # === Query Methods ===

    def get_handler(self, signum: int) -> SignalHandler | None:
        """Get the handler for a signal."""
        return self.handlers.get(signum)

    def get_all_handlers(self) -> list[SignalHandler]:
        """Get all registered handlers."""
        return list(self.handlers.values())

    def get_events(self) -> list[SignalEvent]:
        """Get all signal events."""
        return self.events.copy()

    def get_loading_handlers(self) -> list[SignalHandler]:
        """Get handlers that loaded libraries."""
        return self.loading_handlers.copy()

    def has_signal_based_loading(self) -> bool:
        """Check if any library loading happened in signal handlers."""
        return len(self.loading_handlers) > 0

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_registrations': self.total_registrations,
            'total_invocations': self.total_invocations,
            'active_handlers': len(self.handlers),
            'loading_handlers': len(self.loading_handlers),
            'total_events': len(self.events),
        }

    def reset(self):
        """Reset all tracking state."""
        self.handlers.clear()
        self.events.clear()
        self.loading_handlers.clear()
        self.total_registrations = 0
        self.total_invocations = 0
