"""Tests for control flow tracking and ROP/JOP detection."""

import pytest
from unittest.mock import MagicMock

from dynpathresolver.analysis.control_flow import (
    IndirectFlowTracker,
    IndirectFlowEvent,
    RopDetector,
    RopGadget,
    RopChain,
    JopDetector,
    JopGadget,
    JopChain,
)


class TestIndirectFlowEvent:
    """Tests for IndirectFlowEvent dataclass."""

    def test_basic_creation(self):
        """Test creating an IndirectFlowEvent."""
        event = IndirectFlowEvent(
            event_type='call',
            source_addr=0x400000,
            target_addr=0x7f000000,
            is_dynamic_target=True,
        )
        assert event.event_type == 'call'
        assert event.source_addr == 0x400000
        assert event.target_addr == 0x7f000000
        assert event.is_dynamic_target is True


class TestIndirectFlowTracker:
    """Tests for IndirectFlowTracker class."""

    @pytest.fixture
    def mock_project(self):
        """Create a mock angr project."""
        return MagicMock()

    @pytest.fixture
    def mock_memory_tracker(self):
        """Create a mock MemoryRegionTracker."""
        tracker = MagicMock()
        tracker.is_dynamically_mapped = MagicMock(return_value=False)
        return tracker

    @pytest.fixture
    def tracker(self, mock_project, mock_memory_tracker):
        """Create an IndirectFlowTracker."""
        return IndirectFlowTracker(mock_project, mock_memory_tracker)

    def test_initialization(self, tracker):
        """Test tracker initialization."""
        assert tracker.events == []
        assert tracker.dynamic_calls == []
        assert tracker.dynamic_jumps == []
        assert tracker.total_indirect_calls == 0

    def test_get_statistics(self, tracker):
        """Test getting statistics."""
        stats = tracker.get_statistics()
        assert 'total_indirect_calls' in stats
        assert 'total_indirect_jumps' in stats
        assert 'dynamic_calls' in stats

    def test_has_dynamic_execution(self, tracker):
        """Test has_dynamic_execution check."""
        assert tracker.has_dynamic_execution() is False

        # Add a dynamic call
        event = IndirectFlowEvent(
            event_type='call',
            source_addr=0x400000,
            target_addr=0x7f000000,
            is_dynamic_target=True,
        )
        tracker.dynamic_calls.append(event)

        assert tracker.has_dynamic_execution() is True

    def test_reset(self, tracker):
        """Test resetting tracker."""
        event = IndirectFlowEvent(
            event_type='call',
            source_addr=0x400000,
            target_addr=0x7f000000,
        )
        tracker.events.append(event)
        tracker.total_indirect_calls = 10

        tracker.reset()

        assert len(tracker.events) == 0
        assert tracker.total_indirect_calls == 0


class TestRopGadget:
    """Tests for RopGadget dataclass."""

    def test_basic_creation(self):
        """Test creating a RopGadget."""
        gadget = RopGadget(
            addr=0x400100,
            instructions=['pop rdi', 'ret'],
            gadget_type='ret',
            length=2,
        )
        assert gadget.addr == 0x400100
        assert len(gadget.instructions) == 2
        assert gadget.gadget_type == 'ret'


class TestRopDetector:
    """Tests for RopDetector class."""

    @pytest.fixture
    def mock_project(self):
        """Create a mock angr project."""
        project = MagicMock()
        project.arch = MagicMock()
        project.arch.name = 'AMD64'
        project.arch.bits = 64
        project.loader = MagicMock()
        project.loader.all_objects = []
        return project

    @pytest.fixture
    def detector(self, mock_project):
        """Create a RopDetector."""
        return RopDetector(mock_project)

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.gadgets == {}
        assert detector.detected_chains == []
        assert detector.max_gadget_length == 10
        assert detector.min_chain_length == 3

    def test_get_detected_chains(self, detector):
        """Test getting detected chains."""
        chain = RopChain(
            gadgets=[],
            start_addr=0x400000,
            detected_at_step=10,
        )
        detector.detected_chains.append(chain)

        chains = detector.get_detected_chains()
        assert len(chains) == 1
        assert chains[0].start_addr == 0x400000

    def test_reset(self, detector):
        """Test resetting detector."""
        chain = RopChain(
            gadgets=[],
            start_addr=0x400000,
            detected_at_step=10,
        )
        detector.detected_chains.append(chain)

        detector.reset()

        assert len(detector.detected_chains) == 0


class TestJopGadget:
    """Tests for JopGadget dataclass."""

    def test_basic_creation(self):
        """Test creating a JopGadget."""
        gadget = JopGadget(
            addr=0x400200,
            instructions=['jmp rax'],
            gadget_type='dispatcher',
            target_reg='rax',
        )
        assert gadget.addr == 0x400200
        assert gadget.gadget_type == 'dispatcher'
        assert gadget.target_reg == 'rax'


class TestJopDetector:
    """Tests for JopDetector class."""

    @pytest.fixture
    def mock_project(self):
        """Create a mock angr project."""
        project = MagicMock()
        project.arch = MagicMock()
        project.arch.name = 'AMD64'
        project.arch.bits = 64
        project.loader = MagicMock()
        project.loader.all_objects = []
        return project

    @pytest.fixture
    def detector(self, mock_project):
        """Create a JopDetector."""
        return JopDetector(mock_project)

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.dispatchers == {}
        assert detector.functional_gadgets == {}
        assert detector.detected_chains == []

    def test_get_detected_chains(self, detector):
        """Test getting detected chains."""
        chain = JopChain(
            dispatcher=None,
            gadgets=[],
            detected_at_step=10,
        )
        detector.detected_chains.append(chain)

        chains = detector.get_detected_chains()
        assert len(chains) == 1

    def test_reset(self, detector):
        """Test resetting detector."""
        chain = JopChain(
            dispatcher=None,
            gadgets=[],
            detected_at_step=10,
        )
        detector.detected_chains.append(chain)

        detector.reset()

        assert len(detector.detected_chains) == 0
