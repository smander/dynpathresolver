"""Speculative resolver for indirect control flow targets."""

import claripy
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr


class SpeculativeResolver:
    """Attempts to resolve symbolic jump targets to concrete addresses."""

    def __init__(self, project: "angr.Project", max_forks: int = 8):
        self.project = project
        self.max_forks = max_forks

    def resolve(self, state: "angr.SimState", target_expr: claripy.ast.BV) -> list[int]:
        """
        Resolve a symbolic target expression to concrete addresses.

        Args:
            state: Current simulation state with constraints
            target_expr: Symbolic expression for the jump target

        Returns:
            List of valid concrete addresses (up to max_forks)
        """
        valid_ranges = self._get_executable_ranges()
        if not valid_ranges:
            return []

        # Build constraint: target must be in executable memory
        constraints = []
        for start, end in valid_ranges:
            constraints.append(claripy.And(
                claripy.UGE(target_expr, start),
                claripy.ULE(target_expr, end)
            ))

        if not constraints:
            return []

        region_constraint = claripy.Or(*constraints)

        # Find solutions up to max_forks
        solutions = []
        temp_state = state.copy()
        temp_state.solver.add(region_constraint)

        for _ in range(self.max_forks):
            if not temp_state.solver.satisfiable():
                break
            addr = temp_state.solver.eval(target_expr)
            solutions.append(addr)
            temp_state.solver.add(target_expr != addr)

        return solutions

    def _get_executable_ranges(self) -> list[tuple[int, int]]:
        """Get all executable memory ranges from loaded objects."""
        ranges = []
        for obj in self.project.loader.all_objects:
            if not hasattr(obj, 'segments'):
                continue
            for seg in obj.segments:
                if seg.is_executable:
                    ranges.append((seg.min_addr, seg.max_addr))
        return ranges
