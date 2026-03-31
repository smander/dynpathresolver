"""Tests for multi-stage payload tracking."""

import pytest
from unittest.mock import MagicMock


class TestStageTracker:
    """Test StageTracker class."""

    def test_initialization(self):
        """Test tracker initialization."""
        from dynpathresolver.tracking.stage_tracker import StageTracker

        tracker = StageTracker()

        assert len(tracker.stages) == 0
        assert len(tracker.transitions) == 0
        assert tracker._current_stage == 0
        assert tracker._stage_counter == 0

    def test_initialization_with_trackers(self):
        """Test initialization with memory and taint trackers."""
        from dynpathresolver.tracking.stage_tracker import StageTracker
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker
        from dynpathresolver.tracking.taint_tracker import TaintTracker

        memory_tracker = MagicMock(spec=MemoryRegionTracker)
        taint_tracker = MagicMock(spec=TaintTracker)

        tracker = StageTracker(
            memory_tracker=memory_tracker,
            taint_tracker=taint_tracker,
        )

        assert tracker.memory_tracker is memory_tracker
        assert tracker.taint_tracker is taint_tracker

    def test_record_stage(self):
        """Test recording a stage."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 5

        stage = tracker.record_stage(
            state,
            entry_addr=0x401000,
            regions=[0x400000],
            source=StageSource.NETWORK,
            size=0x1000,
        )

        assert stage.stage_num == 1
        assert stage.entry_addr == 0x401000
        assert stage.source == StageSource.NETWORK
        assert len(tracker.stages) == 1

    def test_record_network_stage(self):
        """Test recording network-loaded stage."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        stage = tracker.record_network_stage(
            state,
            entry_addr=0x500000,
            regions=[0x500000],
            size=0x2000,
            url="http://evil.com/payload",
        )

        assert stage.source == StageSource.NETWORK
        assert stage.metadata['url'] == "http://evil.com/payload"

    def test_record_decrypted_stage(self):
        """Test recording decrypted stage."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        stage = tracker.record_decrypted_stage(
            state,
            entry_addr=0x600000,
            regions=[0x600000],
            size=0x1000,
            method="xor",
        )

        assert stage.source == StageSource.DECRYPTED
        assert stage.metadata['decryption_method'] == "xor"

    def test_record_unpacked_stage(self):
        """Test recording unpacked stage."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        stage = tracker.record_unpacked_stage(
            state,
            entry_addr=0x700000,
            regions=[0x700000],
            size=0x3000,
            packer="UPX",
        )

        assert stage.source == StageSource.UNPACKED
        assert stage.metadata['packer'] == "UPX"

    def test_record_transition(self):
        """Test recording stage transition."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 10

        # Create stages
        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)

        # Record transition
        transition = tracker.record_transition(
            state,
            to_stage=2,
            transition_addr=0x401234,
            transition_type="call",
        )

        assert transition.from_stage == 0
        assert transition.to_stage == 2
        assert transition.transition_type == "call"
        assert len(tracker.transitions) == 1
        assert tracker._current_stage == 2

    def test_stage_marked_executed(self):
        """Test that stage is marked executed on transition."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 10

        stage = tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)
        assert not stage.is_executed

        tracker.record_transition(state, to_stage=1, transition_addr=0x500000)

        assert stage.is_executed
        assert stage.executed_at_step is not None

    def test_get_stage_chain(self):
        """Test getting execution chain."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        # Create and execute multiple stages
        stage1 = tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        state.history.depth = 5
        stage2 = tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)
        state.history.depth = 10
        stage3 = tracker.record_stage(state, 0x600000, [0x600000], StageSource.DECRYPTED)

        # Mark stages as executed
        stage1.is_executed = True
        stage1.executed_at_step = 2
        stage3.is_executed = True
        stage3.executed_at_step = 12

        chain = tracker.get_stage_chain()

        assert len(chain) == 2
        assert chain[0] == stage1
        assert chain[1] == stage3

    def test_get_stage(self):
        """Test getting stage by number."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)

        stage = tracker.get_stage(2)

        assert stage is not None
        assert stage.entry_addr == 0x500000

        assert tracker.get_stage(99) is None

    def test_get_current_stage(self):
        """Test getting current stage."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_transition(state, to_stage=1, transition_addr=0x400000)

        current = tracker.get_current_stage()

        assert current is not None
        assert current.stage_num == 1

    def test_has_multi_stage(self):
        """Test multi-stage detection."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        assert not tracker.has_multi_stage()

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        assert not tracker.has_multi_stage()

        tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)
        assert tracker.has_multi_stage()

    def test_get_network_stages(self):
        """Test getting network stages."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)
        tracker.record_stage(state, 0x600000, [0x600000], StageSource.DECRYPTED)
        tracker.record_stage(state, 0x700000, [0x700000], StageSource.NETWORK)

        network_stages = tracker.get_network_stages()

        assert len(network_stages) == 2

    def test_get_decrypted_stages(self):
        """Test getting decrypted stages."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_stage(state, 0x500000, [0x500000], StageSource.DECRYPTED)

        decrypted_stages = tracker.get_decrypted_stages()

        assert len(decrypted_stages) == 1

    def test_mark_region_pending(self):
        """Test marking region as pending."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        tracker.mark_region_pending(
            0x500000,
            StageSource.NETWORK,
            metadata={'url': 'http://test.com'},
        )

        assert 0x500000 in tracker._pending_regions
        assert tracker._pending_regions[0x500000]['source'] == StageSource.NETWORK

    def test_get_statistics(self):
        """Test statistics."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.record_stage(state, 0x500000, [0x500000], StageSource.NETWORK)
        tracker.record_transition(state, to_stage=1, transition_addr=0x400000)

        stats = tracker.get_statistics()

        assert stats['total_stages'] == 2
        assert stats['executed_stages'] == 1
        assert stats['transitions'] == 1
        assert stats['network_stages'] == 1

    def test_reset(self):
        """Test reset."""
        from dynpathresolver.tracking.stage_tracker import StageTracker, StageSource

        tracker = StageTracker()

        state = MagicMock()
        state.history.depth = 1

        tracker.record_stage(state, 0x400000, [0x400000], StageSource.EMBEDDED)
        tracker.mark_region_pending(0x500000, StageSource.NETWORK)

        tracker.reset()

        assert len(tracker.stages) == 0
        assert len(tracker.transitions) == 0
        assert len(tracker._pending_regions) == 0
        assert tracker._current_stage == 0


class TestPayloadStage:
    """Test PayloadStage dataclass."""

    def test_creation(self):
        """Test creating PayloadStage."""
        from dynpathresolver.tracking.stage_tracker import PayloadStage, StageSource

        stage = PayloadStage(
            stage_num=1,
            entry_addr=0x401000,
            memory_regions=[0x400000, 0x500000],
            source=StageSource.NETWORK,
            loaded_at_step=5,
            parent_stage=0,
            size=0x2000,
        )

        assert stage.stage_num == 1
        assert stage.entry_addr == 0x401000
        assert len(stage.memory_regions) == 2
        assert stage.source == StageSource.NETWORK
        assert not stage.is_executed


class TestStageTransition:
    """Test StageTransition dataclass."""

    def test_creation(self):
        """Test creating StageTransition."""
        from dynpathresolver.tracking.stage_tracker import StageTransition

        transition = StageTransition(
            from_stage=0,
            to_stage=1,
            transition_addr=0x401234,
            transition_type="call",
            step=10,
        )

        assert transition.from_stage == 0
        assert transition.to_stage == 1
        assert transition.transition_type == "call"


class TestStageSource:
    """Test StageSource enum."""

    def test_values(self):
        """Test enum values exist."""
        from dynpathresolver.tracking.stage_tracker import StageSource

        assert StageSource.NETWORK is not None
        assert StageSource.FILE is not None
        assert StageSource.DECRYPTED is not None
        assert StageSource.UNPACKED is not None
        assert StageSource.EMBEDDED is not None
        assert StageSource.GENERATED is not None
