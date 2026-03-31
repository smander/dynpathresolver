"""Tests for VtableResolver."""

import pytest


class TestVtableResolver:
    def test_init(self, angr_project):
        """Test resolver initialization."""
        from dynpathresolver.elf.vtable import VtableResolver

        resolver = VtableResolver(angr_project)

        assert resolver.project == angr_project
        assert len(resolver.vtable_cache) == 0

    def test_cache_vtable(self, angr_project):
        """Test caching a vtable address."""
        from dynpathresolver.elf.vtable import VtableResolver

        resolver = VtableResolver(angr_project)

        resolver.cache_vtable(0x600000, "TestClass")

        assert 0x600000 in resolver.vtable_cache
        assert resolver.vtable_cache[0x600000] == "TestClass"

    def test_is_potential_vtable_call(self, angr_project):
        """Test detection of potential vtable call pattern."""
        from dynpathresolver.elf.vtable import VtableResolver

        resolver = VtableResolver(angr_project)

        # Offset 0x8 is typical for second vtable entry
        assert resolver.is_potential_vtable_offset(0x0)
        assert resolver.is_potential_vtable_offset(0x8)
        assert resolver.is_potential_vtable_offset(0x10)
        assert not resolver.is_potential_vtable_offset(0x1000)

    def test_max_backtrack_depth(self, angr_project):
        """Test backtrack depth configuration."""
        from dynpathresolver.elf.vtable import VtableResolver

        resolver = VtableResolver(angr_project, max_backtrack_depth=500)

        assert resolver.max_backtrack_depth == 500
