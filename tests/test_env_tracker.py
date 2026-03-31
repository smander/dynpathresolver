"""Tests for environment variable tracking."""

import pytest
from unittest.mock import MagicMock


class TestEnvironmentTracker:
    """Test EnvironmentTracker class."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        assert len(tracker.variables) == 0
        assert len(tracker.ld_preload_entries) == 0
        assert len(tracker.ld_audit_entries) == 0
        assert tracker.total_setenv == 0

    def test_record_setenv_basic(self):
        """Test recording basic setenv."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "MY_VAR", "my_value")

        assert tracker.total_setenv == 1
        assert "MY_VAR" in tracker.variables
        assert tracker.variables["MY_VAR"].value == "my_value"

    def test_record_setenv_ld_preload(self):
        """Test recording LD_PRELOAD setenv."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_PRELOAD", "/lib/evil.so:/lib/hook.so")

        assert "LD_PRELOAD" in tracker.variables
        assert tracker.variables["LD_PRELOAD"].is_security_relevant
        assert len(tracker.ld_preload_entries) == 2
        assert tracker.ld_preload_entries[0].path == "/lib/evil.so"
        assert tracker.ld_preload_entries[1].path == "/lib/hook.so"

    def test_record_setenv_ld_audit(self):
        """Test recording LD_AUDIT setenv."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_AUDIT", "/lib/audit.so")

        assert "LD_AUDIT" in tracker.variables
        assert len(tracker.ld_audit_entries) == 1
        assert tracker.ld_audit_entries[0].path == "/lib/audit.so"

    def test_record_setenv_no_overwrite(self):
        """Test setenv with overwrite=0."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Set initial value
        tracker.record_setenv(state, "VAR", "original", overwrite=1)

        # Try to overwrite with overwrite=0
        tracker.record_setenv(state, "VAR", "new", overwrite=0)

        # Should keep original value
        assert tracker.variables["VAR"].value == "original"

    def test_record_putenv(self):
        """Test recording putenv."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_putenv(state, "PATH=/usr/bin:/bin")

        assert tracker.total_putenv == 1
        assert "PATH" in tracker.variables
        assert tracker.variables["PATH"].value == "/usr/bin:/bin"

    def test_record_unsetenv(self):
        """Test recording unsetenv."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Set then unset
        tracker.record_setenv(state, "VAR", "value")
        assert "VAR" in tracker.variables

        tracker.record_unsetenv(state, "VAR")
        assert "VAR" not in tracker.variables

    def test_unsetenv_ld_preload(self):
        """Test unsetting LD_PRELOAD clears entries."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_PRELOAD", "/lib/evil.so")
        assert len(tracker.ld_preload_entries) == 1

        tracker.record_unsetenv(state, "LD_PRELOAD")
        assert len(tracker.ld_preload_entries) == 0

    def test_get_ld_preload(self):
        """Test getting LD_PRELOAD paths."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_PRELOAD", "/a.so /b.so")

        paths = tracker.get_ld_preload()
        assert len(paths) == 2
        assert "/a.so" in paths
        assert "/b.so" in paths

    def test_get_ld_library_path(self):
        """Test getting LD_LIBRARY_PATH directories."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_LIBRARY_PATH", "/custom/lib:/other/lib")

        dirs = tracker.get_ld_library_path()
        assert len(dirs) == 2
        assert "/custom/lib" in dirs
        assert "/other/lib" in dirs

    def test_has_library_injection(self):
        """Test detecting library injection."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # No injection initially
        assert not tracker.has_library_injection()

        # Add LD_PRELOAD
        tracker.record_setenv(state, "LD_PRELOAD", "/evil.so")
        assert tracker.has_library_injection()

    def test_get_security_variables(self):
        """Test getting security-relevant variables."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "PATH", "/usr/bin")
        tracker.record_setenv(state, "LD_PRELOAD", "/evil.so")
        tracker.record_setenv(state, "LD_DEBUG", "libs")

        security_vars = tracker.get_security_variables()
        assert len(security_vars) == 2
        names = [v.name for v in security_vars]
        assert "LD_PRELOAD" in names
        assert "LD_DEBUG" in names
        assert "PATH" not in names

    def test_get_statistics(self):
        """Test getting statistics."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_PRELOAD", "/a.so")
        tracker.record_putenv(state, "PATH=/bin")
        tracker.record_unsetenv(state, "OLD_VAR")

        stats = tracker.get_statistics()
        assert stats['total_setenv'] == 1
        assert stats['total_putenv'] == 1
        assert stats['total_unsetenv'] == 1
        assert stats['ld_preload_count'] == 1

    def test_reset(self):
        """Test resetting tracker."""
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_setenv(state, "LD_PRELOAD", "/evil.so")

        tracker.reset()

        assert len(tracker.variables) == 0
        assert len(tracker.ld_preload_entries) == 0
        assert tracker.total_setenv == 0


class TestDynSetenv:
    """Test DynSetenv SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.env import DynSetenv
        DynSetenv.reset()
        yield
        DynSetenv.reset()

    def test_basic_setenv(self):
        """Test basic setenv operation."""
        from dynpathresolver.simprocedures.syscalls.env import DynSetenv
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)
        DynSetenv.env_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(return_value=0x1000)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 1

        # Mock memory read for name and value
        def mem_side_effect(addr):
            mock = MagicMock()
            if addr == 0x1000:
                mock.string.concrete = b"TEST_VAR"
            else:
                mock.string.concrete = b"test_value"
            return mock

        state.mem.__getitem__ = MagicMock(side_effect=mem_side_effect)

        proc = DynSetenv()
        proc.state = state

        result = proc.run(0x1000, 0x2000, 1)

        assert result is not None
        assert tracker.total_setenv == 1


class TestDynPutenv:
    """Test DynPutenv SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.env import DynPutenv
        DynPutenv.reset()
        yield
        DynPutenv.reset()

    def test_basic_putenv(self):
        """Test basic putenv operation."""
        from dynpathresolver.simprocedures.syscalls.env import DynPutenv
        from dynpathresolver.tracking.env_tracker import EnvironmentTracker

        project = MagicMock()
        tracker = EnvironmentTracker(project)
        DynPutenv.env_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(return_value=0x1000)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 1

        # Mock memory read
        state.mem.__getitem__ = MagicMock()
        state.mem.__getitem__.return_value.string.concrete = b"VAR=value"

        proc = DynPutenv()
        proc.state = state

        result = proc.run(0x1000)

        assert result is not None
        assert tracker.total_putenv == 1
        assert "VAR" in tracker.variables
