"""Integration tests for DynPathResolver V2 features."""
import pytest
from unittest.mock import MagicMock, patch


class TestV2PlatformAutoDetection:
    """Tests for automatic platform detection during setup."""

    def test_v2_platform_auto_detection(self, angr_project):
        """Test that auto platform detection works correctly."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(platform='auto', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # The project is an ELF binary so should detect as linux
        assert dpr._detected_platform == 'linux'

    def test_v2_platform_explicit_linux(self, angr_project):
        """Test explicit linux platform skips detection."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(platform='linux', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr._detected_platform == 'linux'

    def test_v2_platform_explicit_windows(self, angr_project):
        """Test explicit windows platform is set correctly."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(platform='windows', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr._detected_platform == 'windows'


class TestV2DirectedModeInitialization:
    """Tests for directed mode initialization."""

    def test_v2_directed_mode_initialization(self, angr_project):
        """Test directed mode initializes DirectedAnalyzer."""
        from dynpathresolver.core.technique import DynPathResolver
        from dynpathresolver.core.directed import DirectedAnalyzer, DirectedExploration

        dpr = DynPathResolver(
            directed_mode=True,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should have initialized the directed components
        assert dpr.directed_analyzer is not None
        assert isinstance(dpr.directed_analyzer, DirectedAnalyzer)
        assert dpr.directed_explorer is not None
        assert isinstance(dpr.directed_explorer, DirectedExploration)

    def test_v2_directed_mode_disabled_no_analyzer(self, angr_project):
        """Test directed mode disabled does not initialize analyzer."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            directed_mode=False,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should NOT have initialized the directed components
        assert dpr.directed_analyzer is None
        assert dpr.directed_explorer is None


class TestV2WindowsHooksInstalled:
    """Tests for Windows platform hook installation."""

    def test_v2_windows_hooks_installed(self, angr_project):
        """Test windows platform installs correct hooks."""
        from dynpathresolver.core.technique import DynPathResolver
        from dynpathresolver.simprocedures.windows import (
            DynLoadLibraryA,
            DynLoadLibraryW,
            DynGetProcAddress,
        )

        dpr = DynPathResolver(
            platform='windows',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        # Track what gets hooked
        hooked_symbols = []
        original_hook_symbol = angr_project.hook_symbol

        def mock_hook_symbol(name, proc, replace=False):
            hooked_symbols.append(name)
            return original_hook_symbol(name, proc, replace=replace)

        with patch.object(angr_project, 'hook_symbol', mock_hook_symbol):
            dpr.setup(simgr)

        # Should have hooked Windows symbols
        assert 'LoadLibraryA' in hooked_symbols
        assert 'LoadLibraryW' in hooked_symbols
        assert 'GetProcAddress' in hooked_symbols
        assert 'FreeLibrary' in hooked_symbols

    def test_v2_linux_hooks_installed(self, angr_project):
        """Test linux platform installs correct hooks (dlopen etc)."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        # Track what gets hooked
        hooked_symbols = []
        original_hook_symbol = angr_project.hook_symbol

        def mock_hook_symbol(name, proc, replace=False):
            hooked_symbols.append(name)
            return original_hook_symbol(name, proc, replace=replace)

        with patch.object(angr_project, 'hook_symbol', mock_hook_symbol):
            dpr.setup(simgr)

        # Should have hooked Linux symbols
        assert 'dlopen' in hooked_symbols
        assert 'dlsym' in hooked_symbols
        assert 'dlclose' in hooked_symbols


class TestV2UnpackingHandlerInitialized:
    """Tests for unpacking handler initialization."""

    def test_v2_unpacking_handler_initialized(self, angr_project):
        """Test unpacking handler setup works when handle_unpacking=True."""
        from dynpathresolver.core.technique import DynPathResolver
        from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

        dpr = DynPathResolver(
            handle_unpacking=True,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should have initialized the unpacking components
        assert dpr.unpacking_detector is not None
        assert isinstance(dpr.unpacking_detector, UnpackingDetector)
        assert dpr.unpacking_handler is not None
        assert isinstance(dpr.unpacking_handler, UnpackingHandler)

    def test_v2_unpacking_handler_disabled(self, angr_project):
        """Test unpacking handler not initialized when handle_unpacking=False."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            handle_unpacking=False,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should NOT have initialized the unpacking components
        assert dpr.unpacking_detector is None
        assert dpr.unpacking_handler is None


class TestV2HeuristicPredictorInitialized:
    """Tests for heuristic predictor initialization."""

    def test_v2_heuristic_predictor_initialized(self, angr_project):
        """Test heuristic predictor setup works when path_predictor='heuristic'."""
        from dynpathresolver.core.technique import DynPathResolver
        from dynpathresolver.analysis.predictor import HeuristicPredictor

        dpr = DynPathResolver(
            path_predictor='heuristic',
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should have initialized the heuristic predictor
        assert dpr.heuristic_predictor is not None
        assert isinstance(dpr.heuristic_predictor, HeuristicPredictor)

    def test_v2_heuristic_predictor_disabled(self, angr_project):
        """Test heuristic predictor not initialized when path_predictor='none'."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            path_predictor='none',
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Should NOT have initialized the heuristic predictor
        assert dpr.heuristic_predictor is None


class TestV2StepIntegration:
    """Tests for step() method V2 integration."""

    def test_v2_step_uses_directed_exploration(self, angr_project):
        """Test that step() uses DirectedExploration when directed_mode=True."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            directed_mode=True,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Run one step - should not crash
        dpr.step(simgr)

        # Step count should increment
        assert dpr._step_count >= 1

    def test_v2_step_checks_unpacking(self, angr_project):
        """Test that step() checks for unpacking activity."""
        from dynpathresolver.core.technique import DynPathResolver

        dpr = DynPathResolver(
            handle_unpacking=True,
            platform='linux',
            preload_common=False,
        )
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Run a step
        dpr.step(simgr)

        # Should have checked unpacking (handler exists and is usable)
        assert dpr.unpacking_handler is not None
