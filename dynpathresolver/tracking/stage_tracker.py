"""
Multi-stage payload tracking.

This module tracks multi-stage payload loading patterns commonly used
by sophisticated malware, where initial code downloads/decrypts and
executes subsequent stages.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.enums import StageSource
from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker, MappedRegion
from dynpathresolver.tracking.taint_tracker import TaintTracker
from dynpathresolver.utils.state_helpers import get_step

log = logging.getLogger(__name__)


@dataclass
class PayloadStage:
    """Represents a single stage of a multi-stage payload."""

    stage_num: int
    entry_addr: int
    memory_regions: list[int]  # Region start addresses
    source: StageSource
    loaded_at_step: int
    parent_stage: int | None = None
    size: int = 0
    is_executed: bool = False
    executed_at_step: int | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class StageTransition:
    """Records a transition between stages."""

    from_stage: int
    to_stage: int
    transition_addr: int  # Address where transition occurred
    transition_type: str  # 'call', 'jump', 'return', 'exception'
    step: int


class StageTracker:
    """
    Tracks multi-stage payload loading.

    Monitors for:
    - Memory allocation followed by network/file reads
    - Decryption followed by execution in decrypted region
    - Unpacking with execution in unpacked code
    - Code generation/JIT compilation
    """

    def __init__(
        self,
        memory_tracker: MemoryRegionTracker | None = None,
        taint_tracker: TaintTracker | None = None,
    ):
        """
        Initialize stage tracker.

        Args:
            memory_tracker: Memory region tracker
            taint_tracker: Taint tracker for source tracking
        """
        self.memory_tracker = memory_tracker
        self.taint_tracker = taint_tracker
        self.stages: list[PayloadStage] = []
        self.transitions: list[StageTransition] = []
        self._current_stage = 0
        self._stage_counter = 0
        self._pending_regions: dict[int, dict] = {}  # addr -> metadata

    def record_stage(
        self,
        state: "angr.SimState",
        entry_addr: int,
        regions: list[int],
        source: StageSource,
        parent_stage: int | None = None,
        size: int = 0,
        metadata: dict | None = None,
    ) -> PayloadStage:
        """
        Record a new payload stage.

        Args:
            state: Current angr state
            entry_addr: Entry point address
            regions: List of memory region addresses
            source: Source of this stage
            parent_stage: Parent stage number (if any)
            size: Total size of stage code
            metadata: Additional metadata

        Returns:
            The created PayloadStage
        """
        self._stage_counter += 1
        step = self._get_step(state)

        stage = PayloadStage(
            stage_num=self._stage_counter,
            entry_addr=entry_addr,
            memory_regions=regions,
            source=source,
            loaded_at_step=step,
            parent_stage=parent_stage or self._current_stage,
            size=size,
            metadata=metadata or {},
        )

        self.stages.append(stage)
        log.info(
            f"Recorded stage {stage.stage_num}: entry=0x{entry_addr:x}, "
            f"source={source.name}, parent={parent_stage}"
        )

        return stage

    def record_network_stage(
        self,
        state: "angr.SimState",
        entry_addr: int,
        regions: list[int],
        size: int = 0,
        url: str | None = None,
    ) -> PayloadStage:
        """Convenience method to record a network-loaded stage."""
        metadata = {'url': url} if url else {}
        return self.record_stage(
            state, entry_addr, regions, StageSource.NETWORK, size=size, metadata=metadata
        )

    def record_decrypted_stage(
        self,
        state: "angr.SimState",
        entry_addr: int,
        regions: list[int],
        size: int = 0,
        method: str | None = None,
    ) -> PayloadStage:
        """Convenience method to record a decrypted stage."""
        metadata = {'decryption_method': method} if method else {}
        return self.record_stage(
            state, entry_addr, regions, StageSource.DECRYPTED, size=size, metadata=metadata
        )

    def record_unpacked_stage(
        self,
        state: "angr.SimState",
        entry_addr: int,
        regions: list[int],
        size: int = 0,
        packer: str | None = None,
    ) -> PayloadStage:
        """Convenience method to record an unpacked stage."""
        metadata = {'packer': packer} if packer else {}
        return self.record_stage(
            state, entry_addr, regions, StageSource.UNPACKED, size=size, metadata=metadata
        )

    def record_transition(
        self,
        state: "angr.SimState",
        to_stage: int,
        transition_addr: int,
        transition_type: str = "call",
    ) -> StageTransition:
        """
        Record a transition between stages.

        Args:
            state: Current angr state
            to_stage: Destination stage number
            transition_addr: Address where transition occurred
            transition_type: Type of transition

        Returns:
            The created StageTransition
        """
        transition = StageTransition(
            from_stage=self._current_stage,
            to_stage=to_stage,
            transition_addr=transition_addr,
            transition_type=transition_type,
            step=self._get_step(state),
        )

        self.transitions.append(transition)

        # Update current stage and mark as executed
        old_stage = self._current_stage
        self._current_stage = to_stage

        # Mark the new stage as executed
        for stage in self.stages:
            if stage.stage_num == to_stage:
                stage.is_executed = True
                stage.executed_at_step = transition.step
                break

        log.info(
            f"Stage transition: {old_stage} -> {to_stage} "
            f"via {transition_type} at 0x{transition_addr:x}"
        )

        return transition

    def detect_stage_transition(
        self,
        state: "angr.SimState",
        target_addr: int,
    ) -> PayloadStage | None:
        """
        Detect if a control flow transfer is a stage transition.

        Args:
            state: Current angr state
            target_addr: Target address of jump/call

        Returns:
            PayloadStage if transitioning to a new stage, None otherwise
        """
        # Check if target is in a different stage's memory
        for stage in self.stages:
            if stage.stage_num == self._current_stage:
                continue

            if target_addr in stage.memory_regions:
                # Record the transition
                self.record_transition(
                    state, stage.stage_num, target_addr, "jump"
                )
                return stage

            # Check if target is within any region
            for region_addr in stage.memory_regions:
                if self.memory_tracker:
                    region = self.memory_tracker.get_region(region_addr)
                    if region and region_addr <= target_addr < region_addr + region.size:
                        self.record_transition(
                            state, stage.stage_num, target_addr, "jump"
                        )
                        return stage

        # Check if target is in dynamically allocated executable memory
        if self.memory_tracker:
            region = self.memory_tracker.find_region_containing(target_addr)
            if region and region.is_executable and region.addr not in [
                r for s in self.stages for r in s.memory_regions
            ]:
                # New executable region not in any stage - potential new stage
                source = self._infer_source(region)
                stage = self.record_stage(
                    state,
                    target_addr,
                    [region.addr],
                    source,
                    size=region.size,
                )
                self.record_transition(state, stage.stage_num, target_addr, "jump")
                return stage

        return None

    def _infer_source(self, region: MappedRegion) -> StageSource:
        """Infer the source of a memory region."""
        # Check if region is tainted
        if self.taint_tracker and region.addr:
            label = self.taint_tracker.get_taint_label(region.addr)
            if label:
                if 'network' in label.lower():
                    return StageSource.NETWORK
                if 'file' in label.lower():
                    return StageSource.FILE

        # Check if region has a file source
        if region.filepath:
            return StageSource.FILE

        # If writable and executable, likely decrypted/generated
        if region.is_writable and region.is_executable:
            return StageSource.DECRYPTED

        return StageSource.EMBEDDED

    def mark_region_pending(
        self,
        addr: int,
        source: StageSource,
        metadata: dict | None = None,
    ) -> None:
        """
        Mark a memory region as pending execution (potential stage).

        Call this when memory is allocated and populated, before execution.

        Args:
            addr: Region address
            source: Expected source type
            metadata: Additional metadata
        """
        self._pending_regions[addr] = {
            'source': source,
            'metadata': metadata or {},
        }

    def check_pending_execution(
        self,
        state: "angr.SimState",
        exec_addr: int,
    ) -> PayloadStage | None:
        """
        Check if execution at an address triggers a pending stage.

        Args:
            state: Current angr state
            exec_addr: Execution address

        Returns:
            PayloadStage if pending stage was activated
        """
        for region_addr, info in list(self._pending_regions.items()):
            # Check if execution is within this region
            if self.memory_tracker:
                region = self.memory_tracker.get_region(region_addr)
                if region and region_addr <= exec_addr < region_addr + region.size:
                    # Create stage
                    stage = self.record_stage(
                        state,
                        exec_addr,
                        [region_addr],
                        info['source'],
                        size=region.size,
                        metadata=info['metadata'],
                    )
                    stage.is_executed = True
                    stage.executed_at_step = self._get_step(state)

                    # Remove from pending
                    del self._pending_regions[region_addr]

                    # Record transition
                    self.record_transition(state, stage.stage_num, exec_addr, "execution")
                    return stage

        return None

    def get_stage_chain(self) -> list[PayloadStage]:
        """
        Get the execution chain of stages.

        Returns:
            List of stages in execution order
        """
        executed = [s for s in self.stages if s.is_executed]
        return sorted(executed, key=lambda s: s.executed_at_step or 0)

    def get_stage(self, stage_num: int) -> PayloadStage | None:
        """Get a stage by number."""
        for stage in self.stages:
            if stage.stage_num == stage_num:
                return stage
        return None

    def get_current_stage(self) -> PayloadStage | None:
        """Get the current execution stage."""
        return self.get_stage(self._current_stage)

    def get_stage_count(self) -> int:
        """Get total number of stages."""
        return len(self.stages)

    def get_executed_stage_count(self) -> int:
        """Get number of executed stages."""
        return sum(1 for s in self.stages if s.is_executed)

    def has_multi_stage(self) -> bool:
        """Check if multi-stage loading was detected."""
        return len(self.stages) > 1

    def get_network_stages(self) -> list[PayloadStage]:
        """Get all network-loaded stages."""
        return [s for s in self.stages if s.source == StageSource.NETWORK]

    def get_decrypted_stages(self) -> list[PayloadStage]:
        """Get all decrypted stages."""
        return [s for s in self.stages if s.source == StageSource.DECRYPTED]

    def _get_step(self, state: "angr.SimState") -> int:
        """Get current execution step from state."""
        return get_step(state)

    def get_statistics(self) -> dict:
        """Get stage tracking statistics."""
        return {
            'total_stages': len(self.stages),
            'executed_stages': self.get_executed_stage_count(),
            'transitions': len(self.transitions),
            'current_stage': self._current_stage,
            'network_stages': len(self.get_network_stages()),
            'decrypted_stages': len(self.get_decrypted_stages()),
            'pending_regions': len(self._pending_regions),
        }

    def reset(self) -> None:
        """Reset stage tracker state."""
        self.stages.clear()
        self.transitions.clear()
        self._current_stage = 0
        self._stage_counter = 0
        self._pending_regions.clear()
