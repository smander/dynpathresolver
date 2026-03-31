"""Tests for prctl() syscall SimProcedure."""

import pytest
from unittest.mock import MagicMock


class TestDynPrctl:
    """Test cases for DynPrctl SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.prctl import DynPrctl
        DynPrctl.reset()
        yield
        DynPrctl.reset()

    def test_prctl_set_dumpable_zero(self):
        """Test PR_SET_DUMPABLE=0 (anti-debug indicator)."""
        from dynpathresolver.simprocedures.syscalls.prctl import DynPrctl, PR_SET_DUMPABLE

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPrctl()
        proc.state = state

        result = proc.run(PR_SET_DUMPABLE, 0, 0, 0, 0)

        # Should return 0 (success)
        assert result is not None
        # State globals should reflect change
        assert state.globals.get('dpr_prctl_dumpable', 1) == 0

    def test_prctl_get_dumpable(self):
        """Test PR_GET_DUMPABLE returns current value."""
        from dynpathresolver.simprocedures.syscalls.prctl import (
            DynPrctl, PR_SET_DUMPABLE, PR_GET_DUMPABLE
        )

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPrctl()
        proc.state = state

        # Set dumpable to 0
        proc.run(PR_SET_DUMPABLE, 0, 0, 0, 0)

        # Get dumpable
        result = proc.run(PR_GET_DUMPABLE, 0, 0, 0, 0)

        # Should return 0
        result_val = state.solver.eval(result)
        assert result_val == 0

    def test_prctl_set_seccomp(self):
        """Test PR_SET_SECCOMP."""
        from dynpathresolver.simprocedures.syscalls.prctl import DynPrctl, PR_SET_SECCOMP

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPrctl()
        proc.state = state

        # Set seccomp mode 2 (filter)
        result = proc.run(PR_SET_SECCOMP, 2, 0, 0, 0)

        assert result is not None
        assert state.globals.get('dpr_prctl_seccomp', 0) == 2

    def test_prctl_with_security_tracker(self):
        """Test prctl with SecurityPolicyTracker."""
        from dynpathresolver.simprocedures.syscalls.prctl import DynPrctl, PR_SET_DUMPABLE
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        DynPrctl.security_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 5

        proc = DynPrctl()
        proc.state = state

        # Set non-dumpable
        proc.run(PR_SET_DUMPABLE, 0, 0, 0, 0)

        # Tracker should have recorded this
        assert tracker.total_prctls == 1
        assert not tracker.is_dumpable
        assert len(tracker.policy_changes) == 1

    def test_prctl_no_new_privs(self):
        """Test PR_SET_NO_NEW_PRIVS."""
        from dynpathresolver.simprocedures.syscalls.prctl import (
            DynPrctl, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS
        )

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynPrctl()
        proc.state = state

        # Set no_new_privs
        proc.run(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        # Check state globals was updated
        assert state.globals.get('dpr_prctl_no_new_privs', 0) == 1


class TestSecurityPolicyTracker:
    """Test SecurityPolicyTracker class."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        assert tracker.total_prctls == 0
        assert tracker.total_ptraces == 0
        assert tracker.is_dumpable
        assert not tracker.no_new_privs
        assert not tracker.is_traced

    def test_record_prctl_dumpable(self):
        """Test recording prctl that sets dumpable."""
        from dynpathresolver.tracking.security_tracker import (
            SecurityPolicyTracker, PR_SET_DUMPABLE
        )

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 3

        event = tracker.record_prctl(state, PR_SET_DUMPABLE, 0)

        assert tracker.total_prctls == 1
        assert event.option == PR_SET_DUMPABLE
        assert not tracker.is_dumpable
        assert len(tracker.policy_changes) == 1
        assert tracker.policy_changes[0].policy_type == 'dumpable'

    def test_record_prctl_seccomp(self):
        """Test recording prctl that enables seccomp."""
        from dynpathresolver.tracking.security_tracker import (
            SecurityPolicyTracker, PR_SET_SECCOMP, SECCOMP_MODE_FILTER
        )

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 3

        tracker.record_prctl(state, PR_SET_SECCOMP, SECCOMP_MODE_FILTER)

        assert tracker.seccomp_mode == SECCOMP_MODE_FILTER
        assert len(tracker.policy_changes) == 1
        assert tracker.policy_changes[0].policy_type == 'seccomp'

    def test_has_anti_debug(self):
        """Test anti-debug detection."""
        from dynpathresolver.tracking.security_tracker import (
            SecurityPolicyTracker, PR_SET_DUMPABLE, PTRACE_TRACEME
        )

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Initially no anti-debug
        assert not tracker.has_anti_debug()

        # Set non-dumpable
        tracker.record_prctl(state, PR_SET_DUMPABLE, 0)
        assert tracker.has_anti_debug()

    def test_get_statistics(self):
        """Test getting statistics."""
        from dynpathresolver.tracking.security_tracker import (
            SecurityPolicyTracker, PR_SET_DUMPABLE, PTRACE_TRACEME
        )

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_prctl(state, PR_SET_DUMPABLE, 0)
        tracker.record_ptrace(state, PTRACE_TRACEME)

        stats = tracker.get_statistics()

        assert stats['total_prctls'] == 1
        assert stats['total_ptraces'] == 1
        assert not stats['is_dumpable']
        assert stats['is_traced']
        assert stats['anti_debug_count'] == 1

    def test_reset(self):
        """Test tracker reset."""
        from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker, PR_SET_DUMPABLE

        project = MagicMock()
        tracker = SecurityPolicyTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_prctl(state, PR_SET_DUMPABLE, 0)

        tracker.reset()

        assert tracker.total_prctls == 0
        assert tracker.is_dumpable
        assert len(tracker.policy_changes) == 0
