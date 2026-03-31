"""Tests for IFUNC tracking."""

import pytest
from unittest.mock import MagicMock


class TestIFuncTracker:
    """Test IFuncTracker class."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker

        project = MagicMock()
        tracker = IFuncTracker(project)

        assert len(tracker.ifunc_symbols) == 0
        assert len(tracker.resolutions) == 0

    def test_is_ifunc_resolver_unknown(self):
        """Test checking unknown address."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker

        project = MagicMock()
        tracker = IFuncTracker(project)

        assert not tracker.is_ifunc_resolver(0x401000)

    def test_track_resolution_unknown(self):
        """Test tracking resolution of unknown IFUNC."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker

        project = MagicMock()
        tracker = IFuncTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        result = tracker.track_resolution(state, 0x401000, 0x402000)

        assert result is None
        assert len(tracker.resolutions) == 0

    def test_track_resolution_known(self):
        """Test tracking resolution of known IFUNC."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker, IFuncSymbol

        project = MagicMock()
        tracker = IFuncTracker(project)

        # Add a known IFUNC
        ifunc = IFuncSymbol(
            name="memcpy",
            resolver_addr=0x401000,
            library="libc.so.6",
        )
        tracker.ifunc_symbols[0x401000] = ifunc

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 5

        # Track resolution
        result = tracker.track_resolution(state, 0x401000, 0x402000)

        assert result is not None
        assert result.symbol_name == "memcpy"
        assert result.resolver_addr == 0x401000
        assert result.resolved_addr == 0x402000
        assert len(tracker.resolutions) == 1

    def test_get_resolution_for_symbol(self):
        """Test getting resolutions for specific symbol."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker, IFuncSymbol

        project = MagicMock()
        tracker = IFuncTracker(project)

        # Add IFUNCs
        tracker.ifunc_symbols[0x401000] = IFuncSymbol(
            name="memcpy", resolver_addr=0x401000, library="libc"
        )
        tracker.ifunc_symbols[0x402000] = IFuncSymbol(
            name="strlen", resolver_addr=0x402000, library="libc"
        )

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Track resolutions
        tracker.track_resolution(state, 0x401000, 0x500000)
        tracker.track_resolution(state, 0x402000, 0x600000)
        tracker.track_resolution(state, 0x401000, 0x500000)  # Same again

        memcpy_resolutions = tracker.get_resolution_for_symbol("memcpy")
        assert len(memcpy_resolutions) == 2

        strlen_resolutions = tracker.get_resolution_for_symbol("strlen")
        assert len(strlen_resolutions) == 1

    def test_resolver_call_count(self):
        """Test resolver call counting."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker, IFuncSymbol

        project = MagicMock()
        tracker = IFuncTracker(project)

        tracker.ifunc_symbols[0x401000] = IFuncSymbol(
            name="memcpy", resolver_addr=0x401000, library="libc"
        )

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Call resolver multiple times
        tracker.track_resolution(state, 0x401000, 0x500000)
        tracker.track_resolution(state, 0x401000, 0x500000)
        tracker.track_resolution(state, 0x401000, 0x500000)

        assert tracker.resolver_call_count[0x401000] == 3

    def test_get_statistics(self):
        """Test getting statistics."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker, IFuncSymbol

        project = MagicMock()
        tracker = IFuncTracker(project)

        tracker.ifunc_symbols[0x401000] = IFuncSymbol(
            name="memcpy", resolver_addr=0x401000, library="libc"
        )
        tracker.ifunc_symbols[0x402000] = IFuncSymbol(
            name="strlen", resolver_addr=0x402000, library="libc"
        )

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.track_resolution(state, 0x401000, 0x500000)

        stats = tracker.get_statistics()
        assert stats['total_ifuncs'] == 2
        assert stats['total_resolutions'] == 1
        assert stats['unique_resolvers_called'] == 1

    def test_reset(self):
        """Test resetting tracker."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncTracker, IFuncSymbol

        project = MagicMock()
        tracker = IFuncTracker(project)

        tracker.ifunc_symbols[0x401000] = IFuncSymbol(
            name="memcpy", resolver_addr=0x401000, library="libc"
        )

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.track_resolution(state, 0x401000, 0x500000)

        tracker.reset()

        # IFUNCs should be preserved, but resolutions cleared
        assert len(tracker.ifunc_symbols) == 1
        assert len(tracker.resolutions) == 0
        assert len(tracker.resolver_call_count) == 0


class TestIFuncSymbol:
    """Test IFuncSymbol dataclass."""

    def test_ifunc_symbol_creation(self):
        """Test creating IFuncSymbol."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncSymbol

        ifunc = IFuncSymbol(
            name="memcpy",
            resolver_addr=0x401000,
            library="libc.so.6",
            symbol_addr=0x400000,
        )

        assert ifunc.name == "memcpy"
        assert ifunc.resolver_addr == 0x401000
        assert ifunc.library == "libc.so.6"
        assert ifunc.symbol_addr == 0x400000


class TestIFuncResolution:
    """Test IFuncResolution dataclass."""

    def test_ifunc_resolution_creation(self):
        """Test creating IFuncResolution."""
        from dynpathresolver.tracking.ifunc_tracker import IFuncResolution

        resolution = IFuncResolution(
            symbol_name="memcpy",
            resolver_addr=0x401000,
            resolved_addr=0x500000,
            library="libc.so.6",
            state_addr=0x400000,
            step=10,
        )

        assert resolution.symbol_name == "memcpy"
        assert resolution.resolver_addr == 0x401000
        assert resolution.resolved_addr == 0x500000
        assert resolution.step == 10
