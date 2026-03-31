"""Tests for MemoryRegionTracker."""

import pytest
from unittest.mock import MagicMock, PropertyMock

from dynpathresolver.tracking.memory_tracker import (
    MemoryRegionTracker,
    MappedRegion,
    OpenFile,
    PROT_READ, PROT_WRITE, PROT_EXEC,
    MAP_PRIVATE, MAP_ANONYMOUS,
)


class TestMappedRegion:
    """Tests for MappedRegion dataclass."""

    def test_basic_creation(self):
        """Test creating a MappedRegion."""
        region = MappedRegion(
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
        )
        assert region.addr == 0x7f000000
        assert region.size == 4096
        assert region.is_executable is True
        assert region.is_writable is False

    def test_writable_region(self):
        """Test a writable region."""
        region = MappedRegion(
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_WRITE,
            flags=MAP_PRIVATE,
        )
        assert region.is_writable is True
        assert region.is_executable is False

    def test_rwx_region(self):
        """Test an RWX region."""
        region = MappedRegion(
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_WRITE | PROT_EXEC,
            flags=MAP_PRIVATE,
        )
        assert region.is_writable is True
        assert region.is_executable is True

    def test_contains(self):
        """Test address containment check."""
        region = MappedRegion(
            addr=0x1000,
            size=0x1000,
            prot=PROT_READ,
            flags=MAP_PRIVATE,
        )
        assert region.contains(0x1000) is True
        assert region.contains(0x1500) is True
        assert region.contains(0x1fff) is True
        assert region.contains(0x2000) is False
        assert region.contains(0x0fff) is False

    def test_update_protection(self):
        """Test protection update."""
        region = MappedRegion(
            addr=0x1000,
            size=0x1000,
            prot=PROT_READ | PROT_WRITE,
            flags=MAP_PRIVATE,
        )
        assert region.is_executable is False

        region.update_protection(PROT_READ | PROT_EXEC)
        assert region.is_executable is True
        assert region.is_writable is False


class TestMemoryRegionTracker:
    """Tests for MemoryRegionTracker class."""

    @pytest.fixture
    def mock_project(self):
        """Create a mock angr project."""
        return MagicMock()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        return state

    @pytest.fixture
    def tracker(self, mock_project):
        """Create a MemoryRegionTracker."""
        return MemoryRegionTracker(mock_project)

    def test_record_open(self, tracker, mock_state):
        """Test recording an open() call."""
        tracker.record_open(mock_state, "/lib/test.so", 0, 5)

        assert 5 in tracker.open_files
        assert tracker.open_files[5].path == "/lib/test.so"
        assert tracker.total_opens == 1

    def test_record_mmap(self, tracker, mock_state):
        """Test recording an mmap() call."""
        region = tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
            fd=5,
        )

        assert region.addr == 0x7f000000
        assert region.is_executable is True
        assert tracker.total_mmaps == 1
        assert len(tracker.executable_mappings) == 1

    def test_mmap_with_open_correlation(self, tracker, mock_state):
        """Test correlating mmap with prior open."""
        # First open a file
        tracker.record_open(mock_state, "/lib/payload.so", 0, 5)

        # Then mmap it
        region = tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
            fd=5,
        )

        # Should have filepath from open
        assert region.filepath == "/lib/payload.so"

    def test_record_mprotect(self, tracker, mock_state):
        """Test recording an mprotect() call."""
        # First create a region
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_WRITE,
            flags=MAP_PRIVATE,
        )

        # Then change protection
        tracker.record_mprotect(
            mock_state,
            addr=0x7f000000,
            size=4096,
            new_prot=PROT_READ | PROT_EXEC,
        )

        assert tracker.total_mprotects == 1
        # Should detect W->X transition
        assert len(tracker.wx_transitions) == 1

    def test_is_executable(self, tracker, mock_state):
        """Test is_executable query."""
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
        )

        assert tracker.is_executable(0x7f000000) is True
        assert tracker.is_executable(0x7f000500) is True
        assert tracker.is_executable(0x7f001000) is False

    def test_is_dynamically_mapped(self, tracker, mock_state):
        """Test is_dynamically_mapped query."""
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ,
            flags=MAP_PRIVATE,
        )

        assert tracker.is_dynamically_mapped(0x7f000000) is True
        assert tracker.is_dynamically_mapped(0x8f000000) is False

    def test_find_library_loads(self, tracker, mock_state):
        """Test finding library loads."""
        # Open and map a .so file
        tracker.record_open(mock_state, "/lib/payload.so", 0, 5)
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
            fd=5,
        )

        libraries = tracker.find_library_loads()
        assert len(libraries) == 1
        assert libraries[0].filepath == "/lib/payload.so"

    def test_memfd_create(self, tracker, mock_state):
        """Test memfd_create tracking."""
        tracker.record_memfd_create(mock_state, "payload", 100)

        assert 100 in tracker.memfd_files
        assert tracker.memfd_files[100] == "payload"

    def test_reset(self, tracker, mock_state):
        """Test resetting tracker state."""
        tracker.record_open(mock_state, "/lib/test.so", 0, 5)
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
        )

        tracker.reset()

        assert len(tracker.regions) == 0
        assert len(tracker.open_files) == 0
        assert tracker.total_mmaps == 0

    def test_get_statistics(self, tracker, mock_state):
        """Test getting statistics."""
        tracker.record_open(mock_state, "/lib/test.so", 0, 5)
        tracker.record_mmap(
            mock_state,
            addr=0x7f000000,
            size=4096,
            prot=PROT_READ | PROT_EXEC,
            flags=MAP_PRIVATE,
            fd=5,
        )

        stats = tracker.get_statistics()
        assert stats['total_opens'] == 1
        assert stats['total_mmaps'] == 1
        assert stats['executable_regions'] == 1
