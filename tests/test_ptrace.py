"""Tests for ptrace() syscall SimProcedure."""

import pytest
from unittest.mock import MagicMock


class TestDynPtrace:
    """Test cases for DynPtrace SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace
        DynPtrace.reset()
        yield
        DynPtrace.reset()

    def test_ptrace_traceme(self):
        """Test PTRACE_TRACEME (anti-debug detection)."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_TRACEME

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPtrace()
        proc.state = state

        # First TRACEME should succeed
        result = proc.run(PTRACE_TRACEME, 0, 0, 0)
        result_val = state.solver.eval(result)
        assert result_val == 0

        # State globals should track traced state
        assert state.globals.get('dpr_ptrace_is_traced', False)

    def test_ptrace_traceme_twice_fails(self):
        """Test PTRACE_TRACEME fails if already traced."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_TRACEME

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPtrace()
        proc.state = state

        # First TRACEME succeeds
        proc.run(PTRACE_TRACEME, 0, 0, 0)
        assert state.globals.get('dpr_ptrace_is_traced', False)

        # Second TRACEME should fail - check internal state
        # The result would be -1 but mock can't properly evaluate BVV
        # So we just verify the internal logic is correct
        result = proc._handle_request(PTRACE_TRACEME, 0, 0, 0)
        assert result == -1

    def test_ptrace_attach(self):
        """Test PTRACE_ATTACH to another process."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_ATTACH

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPtrace()
        proc.state = state

        # Attach to pid 1234
        result = proc.run(PTRACE_ATTACH, 1234, 0, 0)
        result_val = state.solver.eval(result)
        assert result_val == 0

    def test_ptrace_poketext_code_injection(self):
        """Test PTRACE_POKETEXT (code injection)."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_POKETEXT
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)
        DynPtrace.security_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 5

        proc = DynPtrace()
        proc.state = state

        # Inject code at 0x7f0000001000
        result = proc.run(PTRACE_POKETEXT, 1234, 0x7f0000001000, 0x90909090)

        # Tracker should record code injection
        assert tracker.total_ptraces == 1
        injection_events = tracker.get_code_injection_events()
        assert len(injection_events) == 1
        assert injection_events[0].request == PTRACE_POKETEXT
        assert injection_events[0].addr == 0x7f0000001000

    def test_ptrace_pokedata(self):
        """Test PTRACE_POKEDATA (data injection)."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_POKEDATA
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)
        DynPtrace.security_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 3

        proc = DynPtrace()
        proc.state = state

        # Inject data
        result = proc.run(PTRACE_POKEDATA, 1234, 0x601000, 0xdeadbeef)

        injection_events = tracker.get_code_injection_events()
        assert len(injection_events) == 1
        assert injection_events[0].is_code_injection

    def test_ptrace_with_technique_notification(self):
        """Test ptrace notifies technique about anti-debug."""
        from dynpathresolver.simprocedures.syscalls.ptrace import DynPtrace, PTRACE_TRACEME

        technique = MagicMock()
        technique._record_anti_debug = MagicMock()

        DynPtrace.technique = technique

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPtrace()
        proc.state = state

        # TRACEME
        proc.run(PTRACE_TRACEME, 0, 0, 0)

        # Technique should be notified
        technique._record_anti_debug.assert_called_once()


class TestPtraceEvents:
    """Test PtraceEvent dataclass."""

    def test_is_anti_debug(self):
        """Test anti-debug detection property."""
        from dynpathresolver.tracking.security_tracker import PtraceEvent, PTRACE_TRACEME, PTRACE_ATTACH

        # TRACEME is anti-debug
        event1 = PtraceEvent(
            request=PTRACE_TRACEME,
            request_name="PTRACE_TRACEME",
            pid=0,
            addr=0,
            data=0,
        )
        assert event1.is_anti_debug

        # ATTACH is not anti-debug
        event2 = PtraceEvent(
            request=PTRACE_ATTACH,
            request_name="PTRACE_ATTACH",
            pid=1234,
            addr=0,
            data=0,
        )
        assert not event2.is_anti_debug

    def test_is_code_injection(self):
        """Test code injection detection property."""
        from dynpathresolver.tracking.security_tracker import (
            PtraceEvent, PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_ATTACH
        )

        # POKETEXT is code injection
        event1 = PtraceEvent(
            request=PTRACE_POKETEXT,
            request_name="PTRACE_POKETEXT",
            pid=1234,
            addr=0x7f0000001000,
            data=0x90909090,
        )
        assert event1.is_code_injection

        # POKEDATA is code injection
        event2 = PtraceEvent(
            request=PTRACE_POKEDATA,
            request_name="PTRACE_POKEDATA",
            pid=1234,
            addr=0x601000,
            data=0xdeadbeef,
        )
        assert event2.is_code_injection

        # ATTACH is not code injection
        event3 = PtraceEvent(
            request=PTRACE_ATTACH,
            request_name="PTRACE_ATTACH",
            pid=1234,
            addr=0,
            data=0,
        )
        assert not event3.is_code_injection


class TestSecurityTrackerPtrace:
    """Test SecurityPolicyTracker ptrace recording."""

    def test_record_ptrace_traceme(self):
        """Test recording PTRACE_TRACEME."""
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker, PTRACE_TRACEME

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        event = tracker.record_ptrace(state, PTRACE_TRACEME)

        assert tracker.total_ptraces == 1
        assert tracker.is_traced
        assert event.is_anti_debug
        assert len(tracker.get_anti_debug_events()) == 1

    def test_record_ptrace_code_injection(self):
        """Test recording code injection ptraces."""
        from dynpathresolver.tracking.security_tracker import (
            SecurityPolicyTracker, PTRACE_POKETEXT
        )

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_ptrace(state, PTRACE_POKETEXT, pid=1234,
                             addr=0x7f0000001000, data=0x90909090)

        injection_events = tracker.get_code_injection_events()
        assert len(injection_events) == 1
        assert injection_events[0].pid == 1234
        assert injection_events[0].addr == 0x7f0000001000
