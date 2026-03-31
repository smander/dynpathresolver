"""Tests for DynPathResolver exploration technique."""

import pytest


class TestDynPathResolver:
    def test_init(self):
        """Test technique initialization with defaults."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver()

        assert dpr.max_forks == 8
        assert dpr.preload_common is True
        assert dpr.library_paths == []
        assert dpr.output_dir is None

    def test_init_with_options(self):
        """Test technique initialization with custom options."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            max_forks=4,
            preload_common=False,
            library_paths=['/opt/libs'],
            output_dir='/tmp/output',
        )

        assert dpr.max_forks == 4
        assert dpr.preload_common is False
        assert dpr.library_paths == ['/opt/libs']
        assert dpr.output_dir == '/tmp/output'

    def test_setup_initializes_components(self, angr_project):
        """Test that setup initializes all components."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr.interceptor is not None
        assert dpr.resolver is not None
        assert dpr.preloader is not None
        assert dpr.vtable_resolver is not None
        assert dpr.cfg_patcher is not None

    def test_apply_to_simgr(self, angr_project):
        """Test applying technique to simulation manager."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        simgr.use_technique(dpr)

        assert dpr in simgr._techniques

    def test_complete_exports_results(self, angr_project, tmp_path):
        """Test that complete() exports results."""
        from dynpathresolver.core.technique import DynPathResolver

        output_dir = str(tmp_path / "output")
        dpr = DynPathResolver(preload_common=False, output_dir=output_dir)

        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)
        dpr.setup(simgr)

        # Record a resolution
        dpr.cfg_patcher.record_resolution(0x401000, 0x401100, 'test', {})

        # Trigger complete
        dpr.complete(simgr)

        assert (tmp_path / "output" / "discoveries.json").exists()
        assert (tmp_path / "output" / "discoveries.db").exists()
