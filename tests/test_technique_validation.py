"""Tests for DynPathResolver validation integration."""

import pytest


class TestValidationModeParameter:
    """Test the validation_mode parameter."""

    def test_validation_mode_parameter(self):
        """Test validation_mode parameter defaults to 'none'."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver()
        assert dpr.validation_mode == 'none'

    def test_validation_mode_custom_values(self):
        """Test validation_mode can be set to valid options."""
        from dynpathresolver import DynPathResolver

        # Test 'detect' mode
        dpr_detect = DynPathResolver(validation_mode='detect')
        assert dpr_detect.validation_mode == 'detect'

        # Test 'validate' mode
        dpr_validate = DynPathResolver(validation_mode='validate')
        assert dpr_validate.validation_mode == 'validate'

    def test_invalid_validation_mode_raises(self):
        """Test invalid validation_mode raises ValueError."""
        from dynpathresolver import DynPathResolver

        with pytest.raises(ValueError, match="Unknown validation_mode"):
            DynPathResolver(validation_mode='invalid')


class TestValidationModeNone:
    """Test validation_mode='none' behavior."""

    def test_validation_mode_none_no_detector(self):
        """Test that validation_mode='none' does not initialize detector."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver(validation_mode='none')

        # Before setup, all should be None
        assert dpr.guard_detector is None
        assert dpr.validator is None
        assert dpr.path_candidates == []
        assert dpr.validation_results == []

    def test_validation_mode_none_after_setup(self, angr_project):
        """Test that validation_mode='none' keeps detector/validator as None after setup."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver(validation_mode='none', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr.guard_detector is None
        assert dpr.validator is None


class TestValidationModeDetect:
    """Test validation_mode='detect' behavior."""

    def test_validation_mode_detect_has_detector(self, angr_project):
        """Test that validation_mode='detect' initializes detector but not validator."""
        from dynpathresolver import DynPathResolver
        from dynpathresolver.detection.guards import GuardDetector

        dpr = DynPathResolver(validation_mode='detect', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr.guard_detector is not None
        assert isinstance(dpr.guard_detector, GuardDetector)
        assert dpr.validator is None


class TestValidationModeValidate:
    """Test validation_mode='validate' behavior."""

    def test_validation_mode_validate_has_validator(self, angr_project):
        """Test that validation_mode='validate' initializes both detector and validator."""
        from dynpathresolver import DynPathResolver
        from dynpathresolver.detection.guards import GuardDetector
        from dynpathresolver.validation.validator import HybridValidator

        dpr = DynPathResolver(validation_mode='validate', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        assert dpr.guard_detector is not None
        assert isinstance(dpr.guard_detector, GuardDetector)
        assert dpr.validator is not None
        assert isinstance(dpr.validator, HybridValidator)


class TestPathCandidateRecording:
    """Test path candidate recording functionality."""

    def test_record_path_candidate(self, angr_project):
        """Test _record_path_candidate creates PathCandidate from state."""
        from dynpathresolver import DynPathResolver
        from dynpathresolver.validation.validator import PathCandidate

        dpr = DynPathResolver(validation_mode='validate', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Record a path candidate
        dpr._record_path_candidate(
            state=state,
            library='libtest.so',
            symbol='test_func',
            dlopen_addr=0x401000,
        )

        assert len(dpr.path_candidates) == 1
        candidate = dpr.path_candidates[0]
        assert isinstance(candidate, PathCandidate)
        assert candidate.library == 'libtest.so'
        assert candidate.symbol == 'test_func'
        assert candidate.dlopen_addr == 0x401000

    def test_record_path_candidate_disabled_when_mode_none(self, angr_project):
        """Test that recording does nothing when validation_mode='none'."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver(validation_mode='none', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Attempt to record a path candidate
        dpr._record_path_candidate(
            state=state,
            library='libtest.so',
            symbol='test_func',
            dlopen_addr=0x401000,
        )

        # Should not record in 'none' mode
        assert len(dpr.path_candidates) == 0


class TestRunValidation:
    """Test run_validation method."""

    def test_run_validation(self, angr_project):
        """Test run_validation processes all path candidates."""
        from dynpathresolver import DynPathResolver
        from dynpathresolver.validation.validator import PathCandidate, ValidationStatus

        dpr = DynPathResolver(validation_mode='validate', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Manually add a path candidate for testing
        candidate = PathCandidate(
            library='libtest.so',
            symbol=None,
            dlopen_addr=0x401000,
            path_constraints=[],
            input_variables=[],
        )
        dpr.path_candidates.append(candidate)

        # Run validation
        dpr.run_validation()

        # Should have validation results
        assert len(dpr.validation_results) == 1
        result = dpr.validation_results[0]
        assert result.library == 'libtest.so'
        # Status will be UNREACHABLE since binary won't actually dlopen this
        assert result.status in [
            ValidationStatus.VERIFIED,
            ValidationStatus.UNVERIFIED,
            ValidationStatus.UNREACHABLE,
            ValidationStatus.GUARDED,
        ]

    def test_run_validation_does_nothing_when_mode_none(self, angr_project):
        """Test run_validation does nothing when validation_mode='none'."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver(validation_mode='none', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        # Run validation should be a no-op
        dpr.run_validation()

        assert dpr.validation_results == []

    def test_get_validation_results(self, angr_project):
        """Test get_validation_results returns the results list."""
        from dynpathresolver import DynPathResolver

        dpr = DynPathResolver(validation_mode='validate', preload_common=False)
        state = angr_project.factory.entry_state()
        simgr = angr_project.factory.simgr(state)

        dpr.setup(simgr)

        results = dpr.get_validation_results()
        assert results is dpr.validation_results
