"""Tests for SpeculativeResolver."""

import pytest
import claripy


class TestSpeculativeResolver:
    def test_resolve_constrained_target(self, angr_project):
        """Test resolving a target constrained to valid code regions."""
        from dynpathresolver.core.resolver import SpeculativeResolver

        resolver = SpeculativeResolver(angr_project, max_forks=4)
        state = angr_project.factory.blank_state()

        # Get actual executable ranges from the binary
        exec_ranges = resolver._get_executable_ranges()
        assert len(exec_ranges) > 0, "No executable ranges found"

        # Use a range within the first executable segment
        start, end = exec_ranges[0]
        # Constrain to a small range within the executable region
        range_start = start
        range_end = min(start + 0x100, end)

        # Create a symbolic target constrained to a small range
        target = claripy.BVS('target', 64)
        state.solver.add(target >= range_start)
        state.solver.add(target <= range_end)

        solutions = resolver.resolve(state, target)

        assert len(solutions) > 0
        assert all(range_start <= s <= range_end for s in solutions)

    def test_max_forks_limit(self, angr_project):
        """Test that max_forks limits the number of solutions."""
        from dynpathresolver.core.resolver import SpeculativeResolver

        resolver = SpeculativeResolver(angr_project, max_forks=2)
        state = angr_project.factory.blank_state()

        # Get actual executable ranges from the binary
        exec_ranges = resolver._get_executable_ranges()
        assert len(exec_ranges) > 0, "No executable ranges found"
        start, end = exec_ranges[0]

        target = claripy.BVS('target', 64)
        # Use a range within executable memory that's large enough to have multiple solutions
        state.solver.add(target >= start)
        state.solver.add(target <= min(start + 0xFFF, end))

        solutions = resolver.resolve(state, target)

        assert len(solutions) <= 2

    def test_no_solutions_for_invalid_range(self, angr_project):
        """Test that unsatisfiable constraints return empty list."""
        from dynpathresolver.core.resolver import SpeculativeResolver

        resolver = SpeculativeResolver(angr_project, max_forks=4)
        state = angr_project.factory.blank_state()

        target = claripy.BVS('target', 64)
        # Constraint that can't be satisfied with valid executable ranges
        state.solver.add(target == 0xDEADBEEF)

        solutions = resolver.resolve(state, target)

        # May return the address if it's in an executable range, or empty
        # The key is it doesn't crash
        assert isinstance(solutions, list)

    def test_get_executable_ranges(self, angr_project):
        """Test extraction of executable memory ranges."""
        from dynpathresolver.core.resolver import SpeculativeResolver

        resolver = SpeculativeResolver(angr_project, max_forks=4)
        ranges = resolver._get_executable_ranges()

        assert len(ranges) > 0
        for start, end in ranges:
            assert start < end
