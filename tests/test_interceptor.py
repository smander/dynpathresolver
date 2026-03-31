"""Tests for EventInterceptor."""

import pytest
import claripy


class TestEventInterceptor:
    def test_attach_to_state(self, angr_project):
        """Test that interceptor can attach to a state."""
        from dynpathresolver.core.interceptor import EventInterceptor

        interceptor = EventInterceptor(angr_project)
        state = angr_project.factory.blank_state()

        interceptor.attach(state)

        # Should have registered breakpoints
        assert len(interceptor.pending_resolutions) == 0

    def test_drain_pending_clears_queue(self, angr_project):
        """Test that drain_pending returns and clears events."""
        from dynpathresolver.core.interceptor import EventInterceptor

        interceptor = EventInterceptor(angr_project)

        # Manually add an event
        interceptor.pending_resolutions.append({
            'type': 'indirect_jump',
            'state': None,
            'target_expr': None,
        })

        events = interceptor.drain_pending()

        assert len(events) == 1
        assert len(interceptor.pending_resolutions) == 0

    def test_detects_symbolic_ip(self, angr_project):
        """Test detection of symbolic instruction pointer."""
        from dynpathresolver.core.interceptor import EventInterceptor

        interceptor = EventInterceptor(angr_project)
        state = angr_project.factory.blank_state()
        interceptor.attach(state)

        # Set IP to symbolic value
        symbolic_ip = claripy.BVS('ip', 64)
        state.regs.ip = symbolic_ip

        # Manually trigger the exit callback
        interceptor._on_exit(state)

        events = interceptor.drain_pending()
        assert len(events) == 1
        assert events[0]['type'] == 'indirect_jump'

    def test_ignores_concrete_ip(self, angr_project):
        """Test that concrete IPs don't trigger events."""
        from dynpathresolver.core.interceptor import EventInterceptor

        interceptor = EventInterceptor(angr_project)
        state = angr_project.factory.blank_state()
        interceptor.attach(state)

        # IP is concrete by default
        interceptor._on_exit(state)

        events = interceptor.drain_pending()
        assert len(events) == 0
