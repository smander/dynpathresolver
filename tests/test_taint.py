"""Tests for taint tracking."""

import pytest
from unittest.mock import MagicMock


class TestTaintTracker:
    """Test TaintTracker class."""

    def test_initialization(self):
        """Test tracker initialization."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        assert tracker.shadow is not None
        assert len(tracker.tainted_control_flows) == 0
        assert len(tracker.tainted_library_paths) == 0
        assert not tracker._propagation_enabled

    def test_initialization_with_shadow(self):
        """Test initialization with existing shadow memory."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()
        tracker = TaintTracker(shadow=shadow)

        assert tracker.shadow is shadow

    def test_taint_input(self):
        """Test tainting input."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 5

        tracker.taint_input(state, 0x1000, 10, "test_label", "test_source")

        assert tracker.is_tainted(0x1000)
        assert tracker.get_taint_label(0x1000) == "test_label"

    def test_taint_network_data(self):
        """Test tainting network data."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_network_data(state, 0x1000, 100)

        assert tracker.is_tainted(0x1000)
        assert tracker.get_taint_label(0x1000) == "network"

    def test_taint_file_data(self):
        """Test tainting file data."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_file_data(state, 0x1000, 50, filename="secret.dat")

        assert tracker.is_tainted(0x1000)
        assert "file:secret.dat" in tracker.get_taint_label(0x1000)

    def test_taint_user_input(self):
        """Test tainting user input."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_user_input(state, 0x1000, 20)

        assert tracker.is_tainted(0x1000)
        assert tracker.get_taint_label(0x1000) == "user_input"

    def test_taint_env_variable(self):
        """Test tainting environment variable."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_env_variable(state, 0x1000, 30, var_name="PATH")

        assert tracker.is_tainted(0x1000)
        assert "env:PATH" in tracker.get_taint_label(0x1000)

    def test_propagate(self):
        """Test manual taint propagation."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_input(state, 0x1000, 10, "source")
        tracker.propagate(0x1000, 0x2000, 10)

        assert tracker.is_tainted(0x2000)
        assert tracker.get_taint_label(0x2000) == "source"

    def test_is_range_tainted(self):
        """Test range taint checking."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_input(state, 0x1005, 1, "test")

        assert tracker.is_range_tainted(0x1000, 10)
        assert not tracker.is_range_tainted(0x2000, 10)

    def test_check_tainted_control_flow(self):
        """Test tainted control flow detection."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 10

        # Taint the target address
        tracker.taint_input(state, 0x500000, 4, "malicious", "network")

        # Check if control flow to tainted address is detected
        result = tracker.check_tainted_control_flow(state, 0x500000)

        assert result is not None
        assert result.target == 0x500000
        assert result.taint_label == "malicious"
        assert tracker.has_tainted_control_flow()

    def test_check_tainted_control_flow_clean(self):
        """Test that clean control flow is not flagged."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 10

        result = tracker.check_tainted_control_flow(state, 0x500000)

        assert result is None
        assert not tracker.has_tainted_control_flow()

    def test_check_tainted_library_path(self):
        """Test tainted library path detection."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 10

        # Taint the path string memory
        tracker.taint_input(state, 0x600000, 20, "user_controlled", "user_input")

        result = tracker.check_tainted_library_path(
            state, 0x600000, "/tmp/evil.so", 0x401000
        )

        assert result is not None
        assert result.path == "/tmp/evil.so"
        assert result.taint_label == "user_controlled"
        assert tracker.has_tainted_library_paths()

    def test_check_tainted_library_path_clean(self):
        """Test that clean library path is not flagged."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 10

        result = tracker.check_tainted_library_path(
            state, 0x600000, "/lib/libc.so.6", 0x401000
        )

        assert result is None
        assert not tracker.has_tainted_library_paths()

    def test_get_taint_sources(self):
        """Test getting taint sources."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_network_data(state, 0x1000, 10)
        tracker.taint_file_data(state, 0x2000, 20)

        sources = tracker.get_taint_sources()

        assert len(sources) == 2

    def test_get_tainted_ranges(self):
        """Test getting tainted ranges."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_input(state, 0x1000, 10, "label1")
        tracker.taint_input(state, 0x2000, 5, "label2")

        ranges = tracker.get_tainted_ranges()

        assert len(ranges) == 2

    def test_get_statistics(self):
        """Test statistics."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 10

        tracker.taint_input(state, 0x1000, 10, "test")
        tracker.taint_input(state, 0x500000, 4, "malicious")
        tracker.check_tainted_control_flow(state, 0x500000)

        stats = tracker.get_statistics()

        assert stats['tainted_bytes'] > 0
        assert stats['taint_sources'] == 2
        assert stats['tainted_control_flows'] == 1

    def test_reset(self):
        """Test reset."""
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        tracker = TaintTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.taint_input(state, 0x1000, 10, "test")

        tracker.reset()

        assert not tracker.is_tainted(0x1000)
        assert len(tracker.tainted_control_flows) == 0
        assert len(tracker.tainted_library_paths) == 0


class TestTaintedControlFlow:
    """Test TaintedControlFlow dataclass."""

    def test_creation(self):
        """Test creating TaintedControlFlow."""
        from dynpathresolver.tracking.taint_tracker import TaintedControlFlow

        event = TaintedControlFlow(
            addr=0x400000,
            target=0x500000,
            taint_label="network",
            source_type="network",
            step=10,
        )

        assert event.addr == 0x400000
        assert event.target == 0x500000
        assert event.taint_label == "network"
        assert event.step == 10


class TestTaintedLibraryPath:
    """Test TaintedLibraryPath dataclass."""

    def test_creation(self):
        """Test creating TaintedLibraryPath."""
        from dynpathresolver.tracking.taint_tracker import TaintedLibraryPath

        event = TaintedLibraryPath(
            path="/tmp/evil.so",
            taint_label="user_input",
            source_type="user_input",
            load_addr=0x401000,
            step=15,
        )

        assert event.path == "/tmp/evil.so"
        assert event.taint_label == "user_input"
        assert event.load_addr == 0x401000
        assert event.step == 15
