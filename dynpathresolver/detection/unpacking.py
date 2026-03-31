"""Unpacking support for detecting self-modifying code."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class UnpackingDetector:
    """Detects writes to executable memory regions (self-modifying code)."""

    def __init__(self, project: "angr.Project"):
        """
        Initialize the unpacking detector.

        Args:
            project: The angr project to monitor
        """
        self.project = project
        self._written_regions: list[tuple[int, int]] = []

    def is_executable_region(self, addr: int) -> bool:
        """
        Check if an address is within an executable memory region.

        Args:
            addr: Memory address to check

        Returns:
            True if address is in an executable segment, False otherwise
        """
        try:
            for segment in self.project.loader.main_object.segments:
                if segment.min_addr <= addr < segment.max_addr:
                    if segment.is_executable:
                        return True
        except (AttributeError, TypeError):
            log.debug("Could not check segments for executable regions")
        return False

    def record_write(self, state: "angr.SimState", addr: int, size: int) -> None:
        """
        Record a memory write if it targets an executable region.

        Args:
            state: The simulation state where the write occurred
            addr: Start address of the write
            size: Number of bytes written
        """
        if size <= 0:
            log.debug(f"Ignoring invalid write of size {size} at 0x{addr:x}")
            return
        if self.is_executable_region(addr):
            end_addr = addr + size
            self._written_regions.append((addr, end_addr))
            log.info(f"Detected write to executable region: 0x{addr:x}-0x{end_addr:x}")

    def get_unpacked_regions(self) -> list[tuple[int, int]]:
        """
        Get all recorded writes to executable regions.

        Returns:
            List of (start, end) tuples representing written regions
        """
        return list(self._written_regions)

    def has_unpacking_activity(self) -> bool:
        """
        Check if any writes to executable regions have been detected.

        Returns:
            True if unpacking activity detected, False otherwise
        """
        return len(self._written_regions) > 0


class UnpackingHandler:
    """Handles memory write breakpoints and delegates to detector."""

    def __init__(self, project: "angr.Project", detector: UnpackingDetector):
        """
        Initialize the unpacking handler.

        Args:
            project: The angr project
            detector: UnpackingDetector instance for tracking writes
        """
        self.project = project
        self.detector = detector

    def install_write_breakpoint(self, state: "angr.SimState") -> None:
        """
        Install a memory write breakpoint on the state.

        Uses angr's inspect API to hook memory writes.

        Args:
            state: The simulation state to instrument
        """
        state.inspect.b('mem_write', when='after', action=self.on_memory_write)
        log.debug("Installed memory write breakpoint on state")

    def on_memory_write(self, state: "angr.SimState") -> None:
        """
        Callback for memory write events.

        Extracts write address and size, then delegates to detector.

        Args:
            state: The simulation state after the write
        """
        try:
            # Get the write address and length from inspect state
            write_addr = state.inspect.mem_write_address
            write_length = state.inspect.mem_write_length

            # Concretize the values
            addr = state.solver.eval(write_addr)
            size = state.solver.eval(write_length)

            # Delegate to detector
            self.detector.record_write(state, addr, size)
        except Exception as e:
            log.debug(f"Error processing memory write: {e}")

    def should_rescan(self) -> bool:
        """
        Check if CFG rescan is needed due to unpacking.

        Returns:
            True if unpacking was detected and rescan is recommended
        """
        return self.detector.has_unpacking_activity()

    def get_new_entry_points(self) -> list[int]:
        """
        Get potential new entry points from unpacked regions.

        Returns the start address of each unpacked region as a
        potential new code entry point.

        Returns:
            List of addresses that could be new code entry points
        """
        regions = self.detector.get_unpacked_regions()
        return [start for start, end in regions]
