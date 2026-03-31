"""Tests for syscall SimProcedures."""

import pytest
from unittest.mock import MagicMock, PropertyMock
import claripy

from dynpathresolver.simprocedures.syscalls import (
    DynMmap, DynMunmap, DynMprotect,
    DynOpen, DynOpenat, DynMemfdCreate,
    DynSigaction, DynSignal, DynRaise,
)
from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, PROT_EXEC


class TestDynMmap:
    """Tests for DynMmap SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynMmap.reset()
        yield
        DynMmap.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynMmap has required class attributes."""
        assert hasattr(DynMmap, 'memory_tracker')
        assert hasattr(DynMmap, 'technique')
        assert hasattr(DynMmap, '_alloc_base')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynMmap.memory_tracker = MagicMock()
        DynMmap.technique = MagicMock()
        DynMmap._alloc_base = 0x99999999

        DynMmap.reset()

        assert DynMmap.memory_tracker is None
        assert DynMmap.technique is None
        assert DynMmap._alloc_base == 0x7f0000000000

    def test_run_basic(self, mock_state):
        """Test basic mmap execution."""
        mmap = DynMmap()
        mmap.state = mock_state

        result = mmap.run(0, 4096, 1, 2, -1, 0)

        assert result is not None
        # Should return a BVV with allocated address

    def test_run_with_memory_tracker(self, mock_state):
        """Test mmap with memory tracker."""
        tracker = MagicMock()
        tracker.record_mmap = MagicMock(return_value=MagicMock(is_executable=False))
        DynMmap.memory_tracker = tracker

        mmap = DynMmap()
        mmap.state = mock_state

        result = mmap.run(0, 4096, 1, 2, -1, 0)

        # Verify record_mmap was called
        tracker.record_mmap.assert_called_once()


class TestDynMprotect:
    """Tests for DynMprotect SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynMprotect.reset()
        yield
        DynMprotect.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        return state

    def test_class_attributes_exist(self):
        """Test that DynMprotect has required class attributes."""
        assert hasattr(DynMprotect, 'memory_tracker')
        assert hasattr(DynMprotect, 'technique')

    def test_run_basic(self, mock_state):
        """Test basic mprotect execution."""
        mprotect = DynMprotect()
        mprotect.state = mock_state

        result = mprotect.run(0x7f000000, 4096, PROT_EXEC)

        assert result is not None


class TestDynOpen:
    """Tests for DynOpen SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynOpen.reset()
        yield
        DynOpen.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(return_value=0x600000)
        state.solver.satisfiable = MagicMock(return_value=True)
        # Mock memory read
        state.mem = MagicMock()
        state.mem.__getitem__ = MagicMock(return_value=MagicMock(
            string=MagicMock(concrete=b"/lib/test.so")
        ))
        return state

    def test_class_attributes_exist(self):
        """Test that DynOpen has required class attributes."""
        assert hasattr(DynOpen, 'memory_tracker')
        assert hasattr(DynOpen, 'technique')
        assert hasattr(DynOpen, '_fd_counter')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynOpen._fd_counter = 999

        DynOpen.reset()

        assert DynOpen._fd_counter == 10


class TestDynMemfdCreate:
    """Tests for DynMemfdCreate SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynMemfdCreate.reset()
        yield
        DynMemfdCreate.reset()

    def test_class_attributes_exist(self):
        """Test that DynMemfdCreate has required class attributes."""
        assert hasattr(DynMemfdCreate, 'memory_tracker')
        assert hasattr(DynMemfdCreate, 'technique')
        assert hasattr(DynMemfdCreate, '_fd_counter')


class TestDynSigaction:
    """Tests for DynSigaction SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynSigaction.reset()
        yield
        DynSigaction.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.arch.bytes = 8
        state.arch.memory_endness = 'Iend_LE'
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.memory = MagicMock()
        state.memory.load = MagicMock(return_value=0x401000)
        return state

    def test_class_attributes_exist(self):
        """Test that DynSigaction has required class attributes."""
        assert hasattr(DynSigaction, 'signal_tracker')
        assert hasattr(DynSigaction, 'technique')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynSigaction.signal_tracker = MagicMock()
        DynSigaction.technique = MagicMock()

        DynSigaction.reset()

        assert DynSigaction.signal_tracker is None
        assert DynSigaction.technique is None


class TestDynSignal:
    """Tests for DynSignal SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynSignal.reset()
        yield
        DynSignal.reset()

    def test_class_attributes_exist(self):
        """Test that DynSignal has required class attributes."""
        assert hasattr(DynSignal, 'signal_tracker')
        assert hasattr(DynSignal, 'technique')


class TestDynRaise:
    """Tests for DynRaise SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynRaise.reset()
        yield
        DynRaise.reset()

    def test_class_attributes_exist(self):
        """Test that DynRaise has required class attributes."""
        assert hasattr(DynRaise, 'signal_tracker')
        assert hasattr(DynRaise, 'technique')
