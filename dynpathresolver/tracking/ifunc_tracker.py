"""
GNU IFUNC (Indirect Function) tracking.

This module tracks IFUNC resolution, which allows functions to be
resolved at runtime by a resolver function. This can be exploited
for code injection or hooking.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import STT_GNU_IFUNC

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class IFuncSymbol:
    """Represents a GNU IFUNC symbol."""

    name: str
    resolver_addr: int
    library: str
    symbol_addr: int = 0  # PLT/GOT address


@dataclass
class IFuncResolution:
    """Represents an IFUNC resolution event."""

    symbol_name: str
    resolver_addr: int
    resolved_addr: int
    library: str
    state_addr: int = 0
    step: int = 0


class IFuncTracker:
    """
    Tracks GNU IFUNC indirect function resolution.

    This class:
    1. Scans binary for STT_GNU_IFUNC symbols
    2. Tracks when IFUNC resolvers are called
    3. Records the resolved function addresses
    4. Detects suspicious resolver behavior
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Discovered IFUNCs
        self.ifunc_symbols: dict[int, IFuncSymbol] = {}  # resolver_addr -> IFuncSymbol

        # Resolution events
        self.resolutions: list[IFuncResolution] = []

        # Track resolver calls
        self.resolver_call_count: dict[int, int] = {}  # resolver_addr -> count

    def scan_for_ifuncs(self) -> list[IFuncSymbol]:
        """
        Scan the binary for GNU IFUNC symbols.

        Returns:
            List of discovered IFuncSymbol objects
        """
        discovered = []

        for obj in self.project.loader.all_objects:
            if not hasattr(obj, 'symbols'):
                continue

            obj_name = obj.provides if hasattr(obj, 'provides') else str(obj)

            for sym in obj.symbols:
                # Check if symbol is IFUNC type
                if self._is_ifunc_symbol(sym):
                    ifunc = IFuncSymbol(
                        name=sym.name,
                        resolver_addr=sym.rebased_addr,
                        library=obj_name,
                        symbol_addr=sym.rebased_addr,
                    )
                    self.ifunc_symbols[sym.rebased_addr] = ifunc
                    discovered.append(ifunc)
                    log.info(f"Found IFUNC: {sym.name} resolver at 0x{sym.rebased_addr:x}")

        log.info(f"Discovered {len(discovered)} IFUNC symbols")
        return discovered

    def _is_ifunc_symbol(self, sym) -> bool:
        """Check if a symbol is an IFUNC."""
        # Check symbol type
        if hasattr(sym, 'type') and sym.type == 'STT_GNU_IFUNC':
            return True

        # Check via ELF info if available
        if hasattr(sym, 'elftype') and sym.elftype == STT_GNU_IFUNC:
            return True

        # Check binding info
        try:
            if hasattr(sym, 'sym') and hasattr(sym.sym, 'entry'):
                st_info = sym.sym.entry.st_info
                st_type = st_info & 0xf
                if st_type == STT_GNU_IFUNC:
                    return True
        except Exception:
            pass

        return False

    def is_ifunc_resolver(self, addr: int) -> bool:
        """Check if an address is a known IFUNC resolver."""
        return addr in self.ifunc_symbols

    def get_ifunc_for_resolver(self, resolver_addr: int) -> IFuncSymbol | None:
        """Get the IFuncSymbol for a resolver address."""
        return self.ifunc_symbols.get(resolver_addr)

    def track_resolution(self, state: "angr.SimState", resolver_addr: int,
                        resolved_addr: int) -> IFuncResolution | None:
        """
        Track an IFUNC resolution event.

        Args:
            state: Current symbolic state
            resolver_addr: Address of the resolver function
            resolved_addr: The address returned by the resolver

        Returns:
            The recorded IFuncResolution, or None if not a known IFUNC
        """
        ifunc = self.ifunc_symbols.get(resolver_addr)
        if not ifunc:
            log.debug(f"Unknown resolver at 0x{resolver_addr:x}")
            return None

        # Track call count
        self.resolver_call_count[resolver_addr] = \
            self.resolver_call_count.get(resolver_addr, 0) + 1

        step = state.history.depth if state.history else 0

        resolution = IFuncResolution(
            symbol_name=ifunc.name,
            resolver_addr=resolver_addr,
            resolved_addr=resolved_addr,
            library=ifunc.library,
            state_addr=state.addr,
            step=step,
        )
        self.resolutions.append(resolution)

        log.info(f"IFUNC resolved: {ifunc.name} -> 0x{resolved_addr:x}")

        # Detect suspicious behavior
        self._check_suspicious_resolution(resolution)

        return resolution

    def _check_suspicious_resolution(self, resolution: IFuncResolution) -> None:
        """Check for suspicious IFUNC resolution patterns."""
        # Check if resolved address is in suspicious region
        resolved = resolution.resolved_addr

        # Check if resolving to dynamically mapped memory
        # (This would need memory_tracker integration)

        # Check for multiple different resolutions of same IFUNC
        same_ifunc = [r for r in self.resolutions
                      if r.symbol_name == resolution.symbol_name]
        if len(same_ifunc) > 1:
            unique_targets = set(r.resolved_addr for r in same_ifunc)
            if len(unique_targets) > 1:
                log.warning(f"IFUNC {resolution.symbol_name} resolved to "
                           f"multiple different addresses: {unique_targets}")

    # === Query Methods ===

    def get_resolutions(self) -> list[IFuncResolution]:
        """Get all IFUNC resolutions."""
        return self.resolutions.copy()

    def get_resolution_for_symbol(self, name: str) -> list[IFuncResolution]:
        """Get all resolutions for a specific IFUNC symbol."""
        return [r for r in self.resolutions if r.symbol_name == name]

    def get_ifunc_symbols(self) -> list[IFuncSymbol]:
        """Get all discovered IFUNC symbols."""
        return list(self.ifunc_symbols.values())

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_ifuncs': len(self.ifunc_symbols),
            'total_resolutions': len(self.resolutions),
            'unique_resolvers_called': len(self.resolver_call_count),
        }

    def reset(self) -> None:
        """Reset resolution tracking (keeps discovered IFUNCs)."""
        self.resolutions.clear()
        self.resolver_call_count.clear()
