"""Directed symbolic execution for reaching dynamic loading sites."""

import logging
from collections import deque
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import UNREACHABLE_DISTANCE

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class DirectedAnalyzer:
    """
    Finds dlopen/dlsym/LoadLibrary call sites via static CFG analysis.

    Uses angr's CFGFast to identify basic blocks containing calls to
    dynamic loading functions, enabling directed exploration toward
    these sites.
    """

    # Target functions for dynamic library loading across platforms
    TARGET_FUNCTIONS = {
        # POSIX/Linux
        'dlopen',
        'dlsym',
        'dlclose',
        'dlmopen',
        'dlvsym',
        # Windows
        'LoadLibraryA',
        'LoadLibraryW',
        'LoadLibraryExA',
        'LoadLibraryExW',
        'GetProcAddress',
        'FreeLibrary',
        'GetModuleHandleA',
        'GetModuleHandleW',
        'GetModuleHandleExA',
        'GetModuleHandleExW',
        # macOS specific
        'NSLinkModule',
        'NSCreateObjectFileImageFromFile',
    }

    def __init__(self, project: "angr.Project") -> None:
        """
        Initialize the directed analyzer.

        Args:
            project: The angr project to analyze.
        """
        self.project = project
        self.target_sites: set[int] = set()

    def find_dynamic_loading_sites(self) -> set[int]:
        """
        Build a CFG and find all call sites to dynamic loading functions.

        Returns:
            Set of addresses where dynamic loading functions are called.
        """
        try:
            # Build fast CFG for static analysis
            cfg = self.project.analyses.CFGFast()
        except Exception as e:
            log.warning(f"Failed to build CFG: {e}")
            return set()

        sites: set[int] = set()

        # Get all functions from the CFG knowledge base
        for func_addr, func in cfg.kb.functions.items():
            func_name = func.name if hasattr(func, 'name') else ''

            # Check if this function is a target
            if func_name in self.TARGET_FUNCTIONS:
                # Find all call sites to this function
                for caller_addr in self._find_callers(cfg, func_addr):
                    sites.add(caller_addr)
                    log.debug(f"Found {func_name} call site at 0x{caller_addr:x}")

                # Also add the function entry as a target site
                sites.add(func_addr)

        # Also scan for PLT/IAT entries
        sites.update(self._find_plt_call_sites(cfg))

        self.target_sites = sites
        log.info(f"Found {len(sites)} dynamic loading sites")
        return sites

    def _find_callers(self, cfg, target_addr: int) -> set[int]:
        """
        Find all addresses that call the target address.

        Args:
            cfg: The angr CFG.
            target_addr: Address of the function being called.

        Returns:
            Set of caller addresses.
        """
        callers: set[int] = set()

        try:
            # Use CFG's callgraph to find callers
            if hasattr(cfg.kb, 'callgraph'):
                callgraph = cfg.kb.callgraph
                if target_addr in callgraph:
                    for pred in callgraph.predecessors(target_addr):
                        callers.add(pred)
        except Exception as e:
            log.debug(f"Error finding callers: {e}")

        return callers

    def _find_plt_call_sites(self, cfg) -> set[int]:
        """
        Find call sites through PLT/IAT entries for target functions.

        Args:
            cfg: The angr CFG.

        Returns:
            Set of PLT/IAT call site addresses.
        """
        sites: set[int] = set()

        try:
            # Check for symbols in the project loader
            for name in self.TARGET_FUNCTIONS:
                sym = self.project.loader.find_symbol(name)
                if sym:
                    # Add the symbol address (PLT entry)
                    sites.add(sym.rebased_addr)

                    # Find callers to this symbol
                    if sym.rebased_addr in cfg.kb.functions:
                        for caller in self._find_callers(cfg, sym.rebased_addr):
                            sites.add(caller)
        except Exception as e:
            log.debug(f"Error scanning PLT: {e}")

        return sites


class DirectedExploration:
    """
    Prioritizes symbolic execution states by distance to target sites.

    Uses reverse BFS from target sites to compute shortest distances,
    then prioritizes states closer to targets during exploration.
    """

    # Default score for unknown/unreachable addresses
    UNKNOWN_DISTANCE = UNREACHABLE_DISTANCE

    def __init__(self, target_sites: set[int]) -> None:
        """
        Initialize the directed exploration.

        Args:
            target_sites: Set of target addresses to reach.
        """
        self.target_sites = target_sites
        self.distances: dict[int, int] = {}

    def compute_distances(self, cfg) -> dict[int, int]:
        """
        Compute distances from each basic block to target sites using reverse BFS.

        Args:
            cfg: The angr CFG to compute distances on.

        Returns:
            Dictionary mapping addresses to their distance from targets.
        """
        distances: dict[int, int] = {}

        # Initialize targets with distance 0
        queue: deque[tuple[int, int]] = deque()
        for target in self.target_sites:
            distances[target] = 0
            queue.append((target, 0))

        try:
            # Get the graph for traversal
            if hasattr(cfg, 'graph'):
                graph = cfg.graph
            else:
                # Fallback: no graph available
                self.distances = distances
                return distances

            # Reverse BFS from targets
            while queue:
                node_addr, dist = queue.popleft()

                # Find predecessors (nodes that can reach this node)
                try:
                    for pred in graph.predecessors(node_addr):
                        pred_addr = pred.addr if hasattr(pred, 'addr') else pred

                        if pred_addr not in distances:
                            distances[pred_addr] = dist + 1
                            queue.append((pred_addr, dist + 1))
                except Exception:
                    # Node might not be in graph
                    pass
        except Exception as e:
            log.debug(f"Error computing distances: {e}")

        self.distances = distances
        log.info(f"Computed distances for {len(distances)} blocks")
        return distances

    def score_state(self, state) -> int:
        """
        Score a state based on its distance to target sites.

        Lower scores are better (closer to targets).

        Args:
            state: An angr state to score.

        Returns:
            Distance score (lower is better), or UNKNOWN_DISTANCE if unknown.
        """
        addr = state.addr
        return self.distances.get(addr, self.UNKNOWN_DISTANCE)

    def prioritize(self, states: list) -> list:
        """
        Sort states by their distance scores (lowest/closest first).

        Args:
            states: List of angr states to prioritize.

        Returns:
            Sorted list of states with closest to targets first.
        """
        return sorted(states, key=self.score_state)

    def should_prune(self, state, max_distance: int = 100) -> bool:
        """
        Determine if a state should be pruned based on distance.

        Args:
            state: The state to check.
            max_distance: Maximum allowed distance from targets.

        Returns:
            True if the state is too far from targets and should be pruned.
        """
        distance = self.score_state(state)
        return distance > max_distance
