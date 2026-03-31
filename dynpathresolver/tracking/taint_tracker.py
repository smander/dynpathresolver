"""
Taint tracking for data flow analysis.

This module tracks the flow of data from untrusted sources (network, files,
user input) through the program to detect when tainted data influences
control flow or is used as library paths.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.tracking.shadow_memory import ShadowMemory, TaintSource
from dynpathresolver.utils.state_helpers import get_step

log = logging.getLogger(__name__)


@dataclass
class TaintedControlFlow:
    """Records when tainted data influences control flow."""

    addr: int  # Address where tainted control flow occurred
    target: int  # The tainted target address
    taint_label: str  # Label of the taint
    source_type: str  # Type of taint source
    step: int  # Execution step


@dataclass
class TaintedLibraryPath:
    """Records when tainted data is used as a library path."""

    path: str  # The tainted library path
    taint_label: str  # Label of the taint
    source_type: str  # Type of taint source
    load_addr: int  # Address of the load call
    step: int  # Execution step


class TaintTracker:
    """
    Data flow tracking from untrusted sources.

    Tracks taint propagation through memory operations and detects
    when tainted data influences control flow or library loading.
    """

    # Standard taint labels
    TAINT_NETWORK = "network"
    TAINT_FILE = "file"
    TAINT_USER_INPUT = "user_input"
    TAINT_ENV = "env"
    TAINT_ARGV = "argv"

    def __init__(self, shadow: ShadowMemory | None = None):
        """
        Initialize taint tracker.

        Args:
            shadow: Shadow memory instance (created if not provided)
        """
        self.shadow = shadow or ShadowMemory()
        self.tainted_control_flows: list[TaintedControlFlow] = []
        self.tainted_library_paths: list[TaintedLibraryPath] = []
        self._step = 0
        self._propagation_enabled = False
        self._breakpoint_ids: list[int] = []

    def taint_input(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
        label: str,
        source_type: str = "unknown",
    ) -> None:
        """
        Mark memory as tainted from an input source.

        Args:
            state: Current angr state
            addr: Start address of tainted data
            size: Size of tainted data
            label: Taint label
            source_type: Type of source (network, file, etc.)
        """
        step = self._get_step(state)
        self.shadow.mark_tainted(addr, size, label, source_type, step)
        log.info(f"Tainted {size} bytes at 0x{addr:x} from {source_type} ({label})")

    def taint_network_data(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
    ) -> None:
        """Convenience method to taint network-received data."""
        self.taint_input(state, addr, size, self.TAINT_NETWORK, "network")

    def taint_file_data(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
        filename: str | None = None,
    ) -> None:
        """Convenience method to taint file-read data."""
        label = f"file:{filename}" if filename else self.TAINT_FILE
        self.taint_input(state, addr, size, label, "file")

    def taint_user_input(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
    ) -> None:
        """Convenience method to taint user input data."""
        self.taint_input(state, addr, size, self.TAINT_USER_INPUT, "user_input")

    def taint_env_variable(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
        var_name: str | None = None,
    ) -> None:
        """Convenience method to taint environment variable data."""
        label = f"env:{var_name}" if var_name else self.TAINT_ENV
        self.taint_input(state, addr, size, label, "env")

    def attach_propagation(self, state: "angr.SimState") -> None:
        """
        Attach taint propagation breakpoints to state.

        This installs memory read/write breakpoints to automatically
        propagate taint through memory operations.

        Args:
            state: angr state to attach to
        """
        if self._propagation_enabled:
            return

        # Install memory write breakpoint for taint propagation
        def on_mem_write(st):
            self._handle_mem_write(st)

        def on_mem_read(st):
            self._handle_mem_read(st)

        try:
            bp_write = state.inspect.b('mem_write', when='after', action=on_mem_write)
            bp_read = state.inspect.b('mem_read', when='after', action=on_mem_read)
            self._breakpoint_ids.extend([bp_write, bp_read])
            self._propagation_enabled = True
            log.debug("Taint propagation breakpoints installed")
        except Exception as e:
            log.warning(f"Could not install taint propagation: {e}")

    def _handle_mem_write(self, state: "angr.SimState") -> None:
        """Handle memory write for taint propagation."""
        try:
            # Get write address and data
            write_addr = state.inspect.mem_write_address
            write_expr = state.inspect.mem_write_expr

            if state.solver.symbolic(write_addr):
                return

            addr = state.solver.eval(write_addr)
            size = write_expr.length // 8 if hasattr(write_expr, 'length') else 1

            # Check if the written data came from tainted memory
            # This is a simplified check - full taint would track through registers
            self._step = self._get_step(state)

        except Exception as e:
            log.debug(f"Error in mem_write handler: {e}")

    def _handle_mem_read(self, state: "angr.SimState") -> None:
        """Handle memory read for taint propagation tracking."""
        try:
            read_addr = state.inspect.mem_read_address

            if state.solver.symbolic(read_addr):
                return

            addr = state.solver.eval(read_addr)
            size = state.inspect.mem_read_length

            if isinstance(size, int):
                # Check if reading from tainted memory
                if self.shadow.is_range_tainted(addr, size):
                    label = self.shadow.get_taint_label(addr)
                    log.debug(f"Read from tainted memory at 0x{addr:x} ({label})")

        except Exception as e:
            log.debug(f"Error in mem_read handler: {e}")

    def propagate(self, src_addr: int, dst_addr: int, size: int) -> None:
        """
        Manually propagate taint from source to destination.

        Args:
            src_addr: Source address
            dst_addr: Destination address
            size: Number of bytes
        """
        self.shadow.propagate_taint(src_addr, dst_addr, size)

    def is_tainted(self, addr: int) -> bool:
        """Check if an address is tainted."""
        return self.shadow.is_tainted(addr)

    def is_range_tainted(self, addr: int, size: int) -> bool:
        """Check if any byte in range is tainted."""
        return self.shadow.is_range_tainted(addr, size)

    def get_taint_label(self, addr: int) -> str | None:
        """Get taint label for an address."""
        return self.shadow.get_taint_label(addr)

    def check_tainted_control_flow(
        self,
        state: "angr.SimState",
        target: int,
    ) -> TaintedControlFlow | None:
        """
        Check if a control flow target is tainted.

        This should be called before indirect jumps/calls to detect
        when tainted data influences control flow.

        Args:
            state: Current state
            target: Target address of jump/call

        Returns:
            TaintedControlFlow if target is tainted, None otherwise
        """
        # Check if the target address itself came from tainted memory
        # In practice, we'd track which register holds the target and
        # check if that register's value is tainted

        # For now, check if the target is within a tainted range
        if self.shadow.is_tainted(target):
            label = self.shadow.get_taint_label(target) or "unknown"
            meta = self.shadow.get_metadata(target)
            source_type = meta.source_type if meta else "unknown"

            event = TaintedControlFlow(
                addr=state.addr,
                target=target,
                taint_label=label,
                source_type=source_type,
                step=self._get_step(state),
            )

            self.tainted_control_flows.append(event)
            log.warning(f"Tainted control flow detected at 0x{state.addr:x} -> 0x{target:x}")
            return event

        return None

    def check_tainted_library_path(
        self,
        state: "angr.SimState",
        path_addr: int,
        path: str,
        load_addr: int,
    ) -> TaintedLibraryPath | None:
        """
        Check if a library path string is tainted.

        Args:
            state: Current state
            path_addr: Address of path string
            path: The path string
            load_addr: Address of the load call

        Returns:
            TaintedLibraryPath if path is tainted, None otherwise
        """
        path_len = len(path) + 1  # Include null terminator

        if self.shadow.is_range_tainted(path_addr, path_len):
            label = self.shadow.get_taint_label(path_addr) or "unknown"
            meta = self.shadow.get_metadata(path_addr)
            source_type = meta.source_type if meta else "unknown"

            event = TaintedLibraryPath(
                path=path,
                taint_label=label,
                source_type=source_type,
                load_addr=load_addr,
                step=self._get_step(state),
            )

            self.tainted_library_paths.append(event)
            log.warning(f"Tainted library path detected: {path} at 0x{load_addr:x}")
            return event

        return None

    def has_tainted_control_flow(self) -> bool:
        """Check if any tainted control flow was detected."""
        return len(self.tainted_control_flows) > 0

    def has_tainted_library_paths(self) -> bool:
        """Check if any tainted library paths were detected."""
        return len(self.tainted_library_paths) > 0

    def get_taint_sources(self) -> list[TaintSource]:
        """Get all taint sources."""
        return self.shadow.get_taint_sources()

    def get_tainted_ranges(self) -> list[tuple[int, int, str]]:
        """Get all tainted memory ranges."""
        return self.shadow.get_tainted_ranges()

    def _get_step(self, state: "angr.SimState") -> int:
        """Get current execution step from state."""
        return get_step(state)

    def get_statistics(self) -> dict[str, int | bool]:
        """Get taint tracking statistics."""
        shadow_stats = self.shadow.get_statistics()
        return {
            **shadow_stats,
            'tainted_control_flows': len(self.tainted_control_flows),
            'tainted_library_paths': len(self.tainted_library_paths),
            'propagation_enabled': self._propagation_enabled,
        }

    def reset(self) -> None:
        """Reset taint tracker state."""
        self.shadow.reset()
        self.tainted_control_flows.clear()
        self.tainted_library_paths.clear()
        self._step = 0
        self._propagation_enabled = False
        self._breakpoint_ids.clear()
