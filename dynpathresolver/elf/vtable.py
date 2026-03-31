"""Vtable resolver for C++ virtual function calls."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import angr
    import claripy


class VtableResolver:
    """Resolves C++ virtual calls by backtracking through state history."""

    # Typical vtable offsets are small (methods are at 0, 8, 16, ...)
    MAX_VTABLE_OFFSET = 0x100

    def __init__(
        self,
        project: "angr.Project",
        max_backtrack_depth: int = 1000,
    ):
        self.project = project
        self.max_backtrack_depth = max_backtrack_depth
        self.vtable_cache: dict[int, str] = {}

    def cache_vtable(self, addr: int, class_name: str) -> None:
        """Cache a known vtable address and its class."""
        self.vtable_cache[addr] = class_name

    def is_potential_vtable_offset(self, offset: int) -> bool:
        """Check if an offset looks like a vtable method offset."""
        return 0 <= offset <= self.MAX_VTABLE_OFFSET

    def resolve_virtual_call(
        self,
        state: "angr.SimState",
        ptr_expr: "claripy.ast.BV",
        offset: int,
    ) -> int | None:
        """
        Attempt to resolve a virtual call target.

        Args:
            state: Current simulation state
            ptr_expr: Expression for the object pointer
            offset: Offset into the vtable

        Returns:
            Resolved method address, or None if unresolved
        """
        if not self.is_potential_vtable_offset(offset):
            return None

        # Try to find allocation site via backtracking
        alloc_site = self._find_allocation_site(state, ptr_expr)

        if alloc_site is None:
            return None

        # Try to get vtable for this allocation
        vtable_addr = self._get_vtable_for_alloc(state, alloc_site)

        if vtable_addr is None:
            return None

        # Read method address from vtable
        return self._read_vtable_entry(state, vtable_addr, offset)

    def _find_allocation_site(
        self,
        state: "angr.SimState",
        ptr_expr: "claripy.ast.BV",
    ) -> dict[str, Any] | None:
        """Walk state history backwards to find where ptr originated."""
        if not hasattr(state, 'history') or state.history is None:
            return None

        depth = 0
        for hist in state.history.lineage:
            if depth >= self.max_backtrack_depth:
                break
            depth += 1

            # Look for allocation patterns (new, malloc)
            if self._is_allocation_call(hist):
                return {
                    'addr': hist.addr,
                    'history': hist,
                }

        return None

    def _is_allocation_call(self, history: Any) -> bool:
        """Check if a history node represents an allocation call."""
        # This is a simplified heuristic - would need enhancement
        # for real-world use to detect operator new, malloc, etc.
        return False

    def _get_vtable_for_alloc(
        self,
        state: "angr.SimState",
        alloc_site: dict[str, Any],
    ) -> int | None:
        """Determine vtable address for an allocation site."""
        # Check cache first
        addr = alloc_site.get('addr')
        if addr in self.vtable_cache:
            # Would need to map class name to vtable addr
            pass

        # Would analyze constructor to find vtable write
        return None

    def _read_vtable_entry(
        self,
        state: "angr.SimState",
        vtable_addr: int,
        offset: int,
    ) -> int | None:
        """Read a method address from a vtable."""
        try:
            entry = state.memory.load(
                vtable_addr + offset,
                size=self.project.arch.bytes,
                endness=self.project.arch.memory_endness,
            )
            if state.solver.symbolic(entry):
                return None
            return state.solver.eval(entry)
        except Exception:
            return None
