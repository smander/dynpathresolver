"""Event resolution mixin for DynPathResolver — indirect jump/call and vtable resolution."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class ResolutionMixin:
    """Mixin providing control flow event handling and resolution."""

    def _handle_event(
        self,
        simgr: "angr.SimulationManager",
        event: dict,
    ) -> None:
        """Handle a control flow resolution event."""
        if event['type'] == 'indirect_jump':
            self._resolve_indirect(simgr, event)
        elif event['type'] == 'vtable_call':
            self._resolve_vtable(simgr, event)

    def _resolve_indirect(
        self,
        simgr: "angr.SimulationManager",
        event: dict,
    ) -> None:
        """Resolve an indirect jump/call."""
        state = event['state']
        target_expr = event['target_expr']
        source_addr = event.get('source_addr')

        if self.resolver is None or self.cfg_patcher is None:
            return

        targets = self.resolver.resolve(state, target_expr)

        for addr in targets:
            # Fork state at resolved target
            forked = state.copy()
            forked.regs.ip = addr
            simgr.active.append(forked)

            # Attach interceptor to forked state
            if self.interceptor:
                self.interceptor.attach(forked)

            # Record discovery
            self.cfg_patcher.record_resolution(
                source_addr=source_addr or 0,
                target_addr=addr,
                resolution_type='indirect_jump',
                metadata={'all_solutions': targets},
            )

    def _resolve_vtable(
        self,
        simgr: "angr.SimulationManager",
        event: dict,
    ) -> None:
        """Resolve a vtable virtual call."""
        state = event['state']
        ptr_expr = event.get('ptr_expr')
        offset = event.get('offset', 0)
        source_addr = event.get('source_addr')

        if self.vtable_resolver is None or self.cfg_patcher is None:
            return
        if ptr_expr is None:
            return

        target = self.vtable_resolver.resolve_virtual_call(state, ptr_expr, offset)
        if target is None:
            return

        forked = state.copy()
        forked.regs.ip = target
        simgr.active.append(forked)

        if self.interceptor:
            self.interceptor.attach(forked)

        self.cfg_patcher.record_resolution(
            source_addr=source_addr or 0,
            target_addr=target,
            resolution_type='vtable_call',
            metadata={'offset': offset},
        )

    def _check_rop_jop(self, simgr: "angr.SimulationManager") -> None:
        """Check for ROP/JOP patterns in active states."""
        for state in simgr.active:
            # Check ROP
            if self.rop_detector and self.indirect_flow_tracker:
                chain = self.rop_detector.analyze_state(
                    state,
                    self.indirect_flow_tracker.return_targets
                )
                if chain:
                    log.warning(f"ROP chain detected at step {self._step_count}")

            # Check JOP
            if self.jop_detector and self.indirect_flow_tracker:
                chain = self.jop_detector.analyze_state(
                    state,
                    self.indirect_flow_tracker
                )
                if chain:
                    log.warning(f"JOP chain detected at step {self._step_count}")
