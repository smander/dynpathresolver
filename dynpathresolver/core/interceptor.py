"""Event interceptor for detecting unresolved control flow."""

import angr
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class EventInterceptor:
    """Monitors execution for unresolved control flow events."""

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.pending_resolutions: list[dict[str, Any]] = []

    def attach(self, state: "angr.SimState") -> None:
        """Attach breakpoints to a simulation state."""
        state.inspect.b('exit', when=angr.BP_BEFORE, action=self._on_exit)

    def _on_exit(self, state: "angr.SimState") -> None:
        """Callback for exit (jump/branch) events."""
        ip = state.regs.ip

        if state.solver.symbolic(ip):
            self.pending_resolutions.append({
                'type': 'indirect_jump',
                'state': state,
                'target_expr': ip,
                'source_addr': state.history.addr if state.history else None,
            })

    def drain_pending(self) -> list[dict[str, Any]]:
        """Return and clear all pending resolution events."""
        events = self.pending_resolutions
        self.pending_resolutions = []
        return events
