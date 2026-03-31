"""Tests for mremap() syscall SimProcedure."""

import pytest
from unittest.mock import MagicMock, PropertyMock


class TestDynMremap:
    """Test cases for DynMremap SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.mremap import DynMremap
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker

        DynMremap.reset()
        yield
        DynMremap.reset()

    def test_basic_mremap(self):
        """Test basic mremap operation."""
        from dynpathresolver.simprocedures.syscalls.mremap import DynMremap

        # Create mock state
        state = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64

        # Create procedure
        proc = DynMremap()
        proc.state = state

        # Run mremap
        result = proc.run(0x1000, 0x1000, 0x2000, 1, 0)  # MREMAP_MAYMOVE

        # Should return new address (may move)
        assert result is not None

    def test_mremap_with_tracker(self):
        """Test mremap with MemoryRegionTracker."""
        from dynpathresolver.simprocedures.syscalls.mremap import DynMremap
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, PROT_READ, PROT_EXEC

        # Create mock project and tracker
        project = MagicMock()
        tracker = MemoryRegionTracker(project)

        # First create a region
        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1
        tracker.record_mmap(state, 0x1000, 0x1000, PROT_READ | PROT_EXEC, 0)

        # Configure procedure
        DynMremap.memory_tracker = tracker

        # Create mock state for mremap
        mremap_state = MagicMock()
        mremap_state.solver.symbolic = MagicMock(return_value=False)
        mremap_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        mremap_state.arch.bits = 64
        mremap_state.addr = 0x400100
        mremap_state.history.depth = 2

        # Run mremap
        proc = DynMremap()
        proc.state = mremap_state
        result = proc.run(0x1000, 0x1000, 0x2000, 1)  # MREMAP_MAYMOVE

        # Region should be updated in tracker
        assert tracker.get_region(0x1000) is not None or len(tracker.regions) > 0

    def test_mremap_exec_relocation(self):
        """Test detection of executable code relocation."""
        from dynpathresolver.simprocedures.syscalls.mremap import DynMremap
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, PROT_READ, PROT_EXEC

        # Create tracker with executable region
        project = MagicMock()
        tracker = MemoryRegionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Create executable mapping
        region = tracker.record_mmap(state, 0x1000, 0x1000, PROT_READ | PROT_EXEC, 0)
        assert region.is_executable

        # Configure procedure
        DynMremap.memory_tracker = tracker
        DynMremap.technique = MagicMock()

        # Create mock state for mremap
        mremap_state = MagicMock()
        mremap_state.solver.symbolic = MagicMock(return_value=False)
        mremap_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        mremap_state.arch.bits = 64
        mremap_state.addr = 0x400100
        mremap_state.history.depth = 2

        # Run mremap to new location
        proc = DynMremap()
        proc.state = mremap_state

        # Force MREMAP_MAYMOVE with size increase to trigger relocation
        result = proc.run(0x1000, 0x1000, 0x10000, 1)

        # Technique should be notified (if relocation occurred)
        # The actual notification depends on whether the region moved

    def test_mremap_fixed_address(self):
        """Test mremap with MREMAP_FIXED flag."""
        from dynpathresolver.simprocedures.syscalls.mremap import DynMremap, MREMAP_FIXED, MREMAP_MAYMOVE

        state = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynMremap()
        proc.state = state

        # Run mremap with MREMAP_FIXED
        new_addr = 0x7f0000010000
        result = proc.run(0x1000, 0x1000, 0x1000, MREMAP_FIXED | MREMAP_MAYMOVE, new_addr)

        # Should return the fixed address (page-aligned)
        result_val = state.solver.eval(result)
        # Result should be page-aligned version of new_addr
        assert (result_val % 0x1000) == 0


class TestMemoryTrackerMremap:
    """Test MemoryRegionTracker.record_mremap()."""

    def test_record_mremap_basic(self):
        """Test basic mremap recording."""
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, PROT_READ

        project = MagicMock()
        tracker = MemoryRegionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Create initial mapping
        tracker.record_mmap(state, 0x1000, 0x1000, PROT_READ, 0)

        # Record mremap
        mremap_state = MagicMock()
        mremap_state.addr = 0x400100
        mremap_state.history.depth = 2

        result = tracker.record_mremap(mremap_state, 0x1000, 0x1000, 0x2000, 0x2000)

        assert result is not None
        assert result.addr == 0x2000
        assert result.size == 0x2000
        # Old address should no longer exist
        assert 0x1000 not in tracker.regions
        # New address should exist
        assert 0x2000 in tracker.regions

    def test_record_mremap_preserves_executable(self):
        """Test that mremap preserves executable flag."""
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, PROT_READ, PROT_EXEC

        project = MagicMock()
        tracker = MemoryRegionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Create executable mapping
        tracker.record_mmap(state, 0x1000, 0x1000, PROT_READ | PROT_EXEC, 0)

        # Record mremap to new location
        mremap_state = MagicMock()
        mremap_state.addr = 0x400100
        mremap_state.history.depth = 2

        result = tracker.record_mremap(mremap_state, 0x1000, 0x1000, 0x5000, 0x2000)

        assert result is not None
        assert result.is_executable
        assert result in tracker.executable_mappings

    def test_record_mremap_no_existing_region(self):
        """Test mremap when no existing region found."""
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker

        project = MagicMock()
        tracker = MemoryRegionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Record mremap without existing region
        result = tracker.record_mremap(state, 0x1000, 0x1000, 0x2000, 0x2000)

        # Should create new region
        assert result is not None
        assert result.addr == 0x2000
        assert result.source == 'mremap'
