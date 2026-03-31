"""Tests for hybrid validator module."""

import pytest
from unittest.mock import MagicMock, patch, Mock
from dataclasses import is_dataclass
import subprocess
import tempfile
import os


def test_validation_status_enum():
    """Test ValidationStatus enum has expected values."""
    from dynpathresolver.validation.validator import ValidationStatus

    assert ValidationStatus.VERIFIED.value == 'verified'
    assert ValidationStatus.UNVERIFIED.value == 'unverified'
    assert ValidationStatus.UNREACHABLE.value == 'unreachable'
    assert ValidationStatus.GUARDED.value == 'guarded'
    assert ValidationStatus.FILE_EXISTS.value == 'file_exists'


def test_loading_method_enum():
    """Test LoadingMethod enum has expected values."""
    from dynpathresolver.validation.validator import LoadingMethod

    assert LoadingMethod.DLOPEN.value == 'dlopen'
    assert LoadingMethod.MEMFD_CREATE.value == 'memfd_create'
    assert LoadingMethod.MMAP_EXEC.value == 'mmap_exec'
    assert LoadingMethod.MANUAL_ELF.value == 'manual_elf'
    assert LoadingMethod.UNKNOWN.value == 'unknown'


def test_validation_result_dataclass():
    """Test ValidationResult dataclass has expected fields."""
    from dynpathresolver.validation.validator import ValidationResult, ValidationStatus
    from dynpathresolver.detection.guards import Guard, GuardType

    guard = Guard(
        addr=0x401000,
        guard_type=GuardType.ANTI_DEBUG,
        function_name='ptrace',
        bypass_value=0,
    )

    result = ValidationResult(
        library='/lib/libcrypto.so',
        symbol='EVP_Encrypt',
        status=ValidationStatus.VERIFIED,
        guards=[guard],
        concrete_inputs=b'\x00\x01\x02',
        error=None,
    )

    assert is_dataclass(result)
    assert result.library == '/lib/libcrypto.so'
    assert result.symbol == 'EVP_Encrypt'
    assert result.status == ValidationStatus.VERIFIED
    assert len(result.guards) == 1
    assert result.guards[0].function_name == 'ptrace'
    assert result.concrete_inputs == b'\x00\x01\x02'
    assert result.error is None


def test_validation_result_with_error():
    """Test ValidationResult can hold error information."""
    from dynpathresolver.validation.validator import ValidationResult, ValidationStatus

    result = ValidationResult(
        library='/lib/libssl.so',
        symbol=None,
        status=ValidationStatus.UNVERIFIED,
        guards=[],
        concrete_inputs=None,
        error='Constraints unsatisfiable',
    )

    assert result.status == ValidationStatus.UNVERIFIED
    assert result.error == 'Constraints unsatisfiable'
    assert result.concrete_inputs is None


def test_path_candidate_dataclass():
    """Test PathCandidate dataclass has expected fields."""
    from dynpathresolver.validation.validator import PathCandidate

    # Create mock claripy constraints
    mock_constraint = MagicMock()
    mock_var = MagicMock()

    candidate = PathCandidate(
        library='/lib/libcrypto.so',
        symbol='EVP_Decrypt',
        dlopen_addr=0x401234,
        path_constraints=[mock_constraint],
        input_variables=[mock_var],
    )

    assert is_dataclass(candidate)
    assert candidate.library == '/lib/libcrypto.so'
    assert candidate.symbol == 'EVP_Decrypt'
    assert candidate.dlopen_addr == 0x401234
    assert len(candidate.path_constraints) == 1
    assert len(candidate.input_variables) == 1


def test_path_candidate_without_symbol():
    """Test PathCandidate can have None symbol."""
    from dynpathresolver.validation.validator import PathCandidate

    candidate = PathCandidate(
        library='/lib/libplugin.so',
        symbol=None,
        dlopen_addr=0x402000,
        path_constraints=[],
        input_variables=[],
    )

    assert candidate.symbol is None
    assert candidate.library == '/lib/libplugin.so'


def test_hybrid_validator_init():
    """Test HybridValidator initializes with project and guard detector."""
    from dynpathresolver.validation.validator import HybridValidator
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    assert validator.project == mock_project
    assert validator.guard_detector == mock_detector


def test_generate_concrete_inputs_satisfiable():
    """Test generate_concrete_inputs with satisfiable constraints."""
    from dynpathresolver.validation.validator import HybridValidator, PathCandidate
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    # Create a mock solver that can be satisfied
    with patch('dynpathresolver.validation.validator.claripy') as mock_claripy:
        # Setup mock solver
        mock_solver = MagicMock()
        mock_solver.satisfiable.return_value = True

        # Mock input variable with concrete value
        mock_input_var = MagicMock()
        mock_input_var.length = 64  # 8 bytes
        mock_solver.eval.return_value = 0x4142434445464748  # 'ABCDEFGH' as int

        mock_claripy.Solver.return_value = mock_solver

        candidate = PathCandidate(
            library='/lib/test.so',
            symbol='test_func',
            dlopen_addr=0x401000,
            path_constraints=[MagicMock()],
            input_variables=[mock_input_var],
        )

        result = validator.generate_concrete_inputs(candidate)

        # Should return concrete bytes
        assert result is not None
        assert isinstance(result, bytes)


def test_generate_concrete_inputs_unsatisfiable():
    """Test generate_concrete_inputs with unsatisfiable constraints."""
    from dynpathresolver.validation.validator import HybridValidator, PathCandidate
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    with patch('dynpathresolver.validation.validator.claripy') as mock_claripy:
        # Setup mock solver that is not satisfiable
        mock_solver = MagicMock()
        mock_solver.satisfiable.return_value = False

        mock_claripy.Solver.return_value = mock_solver

        candidate = PathCandidate(
            library='/lib/impossible.so',
            symbol='never_called',
            dlopen_addr=0x401000,
            path_constraints=[MagicMock()],
            input_variables=[MagicMock()],
        )

        result = validator.generate_concrete_inputs(candidate)

        # Should return None for unsatisfiable constraints
        assert result is None


def test_generate_concrete_inputs_empty_constraints():
    """Test generate_concrete_inputs with empty constraints."""
    from dynpathresolver.validation.validator import HybridValidator, PathCandidate
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/test.so',
        symbol='test_func',
        dlopen_addr=0x401000,
        path_constraints=[],
        input_variables=[],
    )

    result = validator.generate_concrete_inputs(candidate)

    # With no constraints and no variables, should return empty bytes
    assert result == b''


def test_create_validation_harness():
    """Test create_validation_harness generates LD_PRELOAD and runner script."""
    from dynpathresolver.validation.validator import HybridValidator, PathCandidate
    from dynpathresolver.detection.guards import GuardDetector, Guard, GuardType, GuardPatcher

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/test.so',
        symbol='test_func',
        dlopen_addr=0x401000,
        path_constraints=[],
        input_variables=[],
    )

    guards = [
        Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0),
    ]

    with patch.object(GuardPatcher, 'generate_ld_preload') as mock_generate:
        mock_generate.return_value = '/* bypass code */'

        harness = validator.create_validation_harness(candidate, guards)

        # Should return harness configuration dict
        assert isinstance(harness, dict)
        assert 'ld_preload_source' in harness
        assert 'runner_script' in harness
        assert 'binary_path' in harness


def test_create_validation_harness_no_guards():
    """Test create_validation_harness with no guards to bypass."""
    from dynpathresolver.validation.validator import HybridValidator, PathCandidate
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/test.so',
        symbol='test_func',
        dlopen_addr=0x401000,
        path_constraints=[],
        input_variables=[],
    )

    harness = validator.create_validation_harness(candidate, [])

    # Should still create harness, just without LD_PRELOAD
    assert isinstance(harness, dict)
    assert harness.get('ld_preload_source') is None or harness.get('ld_preload_source') == ''


def test_validate_candidate_verified(tmp_path):
    """Test validate_candidate returns VERIFIED when dynamic execution confirms path."""
    from dynpathresolver.validation.validator import (
        HybridValidator, PathCandidate, ValidationStatus, LoadingMethod
    )
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)
    mock_detector.get_guards_on_path.return_value = []

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/test.so',
        symbol='test_func',
        dlopen_addr=0x401000,
        path_constraints=[],
        input_variables=[],
    )

    # Mock the internal methods to simulate successful validation
    with patch.object(validator, 'generate_concrete_inputs') as mock_gen, \
         patch.object(validator, 'create_validation_harness') as mock_harness, \
         patch.object(validator, '_run_dynamic_validation') as mock_run:

        mock_gen.return_value = b'\x00\x01\x02'
        mock_harness.return_value = {'binary_path': '/path/to/binary'}
        mock_run.return_value = (True, '/lib/test.so', LoadingMethod.DLOPEN)  # Path was reached

        result = validator.validate_candidate(candidate, timeout=5)

        assert result.status == ValidationStatus.VERIFIED
        assert result.library == '/lib/test.so'
        assert result.concrete_inputs == b'\x00\x01\x02'


def test_validate_candidate_unverified():
    """Test validate_candidate returns UNVERIFIED when constraints unsatisfiable."""
    from dynpathresolver.validation.validator import (
        HybridValidator, PathCandidate, ValidationStatus
    )
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/impossible.so',
        symbol=None,
        dlopen_addr=0x401000,
        path_constraints=[MagicMock()],
        input_variables=[MagicMock()],
    )

    with patch.object(validator, 'generate_concrete_inputs') as mock_gen:
        mock_gen.return_value = None  # Constraints not satisfiable

        result = validator.validate_candidate(candidate)

        assert result.status == ValidationStatus.UNVERIFIED
        assert result.concrete_inputs is None
        assert 'unsatisfiable' in result.error.lower() or 'could not generate' in result.error.lower()


def test_validate_candidate_unreachable():
    """Test validate_candidate returns UNREACHABLE when path not taken dynamically."""
    from dynpathresolver.validation.validator import (
        HybridValidator, PathCandidate, ValidationStatus, LoadingMethod
    )
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)
    mock_detector.get_guards_on_path.return_value = []

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/test.so',
        symbol='test_func',
        dlopen_addr=0x401000,
        path_constraints=[],
        input_variables=[],
    )

    with patch.object(validator, 'generate_concrete_inputs') as mock_gen, \
         patch.object(validator, 'create_validation_harness') as mock_harness, \
         patch.object(validator, '_run_dynamic_validation') as mock_run:

        mock_gen.return_value = b'\x00\x01\x02'
        mock_harness.return_value = {'binary_path': '/path/to/binary'}
        mock_run.return_value = (False, None, LoadingMethod.UNKNOWN)  # Path not reached

        result = validator.validate_candidate(candidate)

        assert result.status == ValidationStatus.UNREACHABLE
        assert result.concrete_inputs == b'\x00\x01\x02'


def test_validate_candidate_guarded():
    """Test validate_candidate returns GUARDED when guards detected on path."""
    from dynpathresolver.validation.validator import (
        HybridValidator, PathCandidate, ValidationStatus, LoadingMethod
    )
    from dynpathresolver.detection.guards import GuardDetector, Guard, GuardType

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)

    guard = Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0)
    mock_detector.get_guards_on_path.return_value = [guard]

    validator = HybridValidator(mock_project, mock_detector)

    candidate = PathCandidate(
        library='/lib/protected.so',
        symbol='secret_func',
        dlopen_addr=0x402000,
        path_constraints=[],
        input_variables=[],
    )

    with patch.object(validator, 'generate_concrete_inputs') as mock_gen, \
         patch.object(validator, 'create_validation_harness') as mock_harness, \
         patch.object(validator, '_run_dynamic_validation') as mock_run, \
         patch.object(validator, '_validate_library_exists') as mock_exists:

        mock_gen.return_value = b'\x00\x01\x02'
        mock_harness.return_value = {'binary_path': '/path/to/binary'}
        mock_run.return_value = (True, '/lib/protected.so', LoadingMethod.DLOPEN)
        mock_exists.return_value = True  # Library exists

        result = validator.validate_candidate(candidate)

        # Even if verified, should report GUARDED status with guards list
        assert result.status == ValidationStatus.GUARDED
        assert len(result.guards) == 1
        assert result.guards[0].function_name == 'ptrace'


def test_validate_all():
    """Test validate_all processes multiple candidates."""
    from dynpathresolver.validation.validator import (
        HybridValidator, PathCandidate, ValidationResult, ValidationStatus
    )
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)
    mock_detector.get_guards_on_path.return_value = []

    validator = HybridValidator(mock_project, mock_detector)

    candidates = [
        PathCandidate(
            library='/lib/lib1.so',
            symbol='func1',
            dlopen_addr=0x401000,
            path_constraints=[],
            input_variables=[],
        ),
        PathCandidate(
            library='/lib/lib2.so',
            symbol='func2',
            dlopen_addr=0x402000,
            path_constraints=[],
            input_variables=[],
        ),
    ]

    with patch.object(validator, 'validate_candidate') as mock_validate:
        mock_validate.side_effect = [
            ValidationResult(
                library='/lib/lib1.so',
                symbol='func1',
                status=ValidationStatus.VERIFIED,
                guards=[],
                concrete_inputs=b'\x00',
                error=None,
            ),
            ValidationResult(
                library='/lib/lib2.so',
                symbol='func2',
                status=ValidationStatus.UNVERIFIED,
                guards=[],
                concrete_inputs=None,
                error='Constraints unsatisfiable',
            ),
        ]

        results = validator.validate_all(candidates)

        assert len(results) == 2
        assert results[0].status == ValidationStatus.VERIFIED
        assert results[1].status == ValidationStatus.UNVERIFIED


def test_validate_all_empty_candidates():
    """Test validate_all with empty candidates list."""
    from dynpathresolver.validation.validator import HybridValidator
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    results = validator.validate_all([])

    assert results == []


def test_frida_validator_init():
    """Test FridaValidator initializes with binary path."""
    from dynpathresolver.validation.validator import FridaValidator

    validator = FridaValidator('/path/to/binary')

    assert validator.binary_path == '/path/to/binary'


def test_frida_validator_check_dlopen_called():
    """Test FridaValidator can check if dlopen was called."""
    from dynpathresolver.validation.validator import FridaValidator, LoadingMethod

    validator = FridaValidator('/path/to/binary')

    # Mock the comprehensive trace function
    with patch.object(validator, '_attach_and_trace_all') as mock_trace:
        mock_trace.return_value = {
            'dlopen_calls': ['/lib/test.so'],
            'mmap_exec_calls': [],
            'memfd_creates': [],
            'open_so_calls': [],
            'fopen_so_calls': [],
            'reached': True,
            'loading_method': LoadingMethod.DLOPEN,
        }

        result = validator.check_dlopen_called(
            inputs=b'\x00\x01\x02',
            expected_lib='/lib/test.so',
            timeout=5,
        )

        assert result is True


def test_frida_validator_dlopen_not_called():
    """Test FridaValidator returns False when dlopen not called."""
    from dynpathresolver.validation.validator import FridaValidator, LoadingMethod

    validator = FridaValidator('/path/to/binary')

    with patch.object(validator, '_attach_and_trace_all') as mock_trace:
        mock_trace.return_value = {
            'dlopen_calls': [],
            'mmap_exec_calls': [],
            'memfd_creates': [],
            'open_so_calls': [],
            'fopen_so_calls': [],
            'reached': False,
            'loading_method': LoadingMethod.UNKNOWN,
        }

        result = validator.check_dlopen_called(
            inputs=b'\x00\x01\x02',
            expected_lib='/lib/test.so',
            timeout=5,
        )

        assert result is False


def test_frida_validator_timeout():
    """Test FridaValidator handles timeout gracefully."""
    from dynpathresolver.validation.validator import FridaValidator

    validator = FridaValidator('/path/to/binary')

    with patch.object(validator, '_attach_and_trace_all') as mock_trace:
        mock_trace.side_effect = TimeoutError("Execution timed out")

        result = validator.check_dlopen_called(
            inputs=b'\x00\x01\x02',
            expected_lib='/lib/test.so',
            timeout=1,
        )

        # Should return False on timeout
        assert result is False


def test_run_dynamic_validation_subprocess():
    """Test _run_dynamic_validation uses subprocess correctly."""
    from dynpathresolver.validation.validator import HybridValidator, LoadingMethod
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'
    mock_detector = MagicMock(spec=GuardDetector)

    validator = HybridValidator(mock_project, mock_detector)

    harness = {
        'binary_path': '/path/to/binary',
        'ld_preload_path': None,
        'runner_script': None,
    }

    with patch('subprocess.run') as mock_run, \
         patch('os.path.exists') as mock_exists:

        # Mock binary exists
        mock_exists.return_value = True

        # Simulate successful execution that triggers dlopen
        # First call (ltrace) returns success with dlopen
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b''
        mock_result.stderr = b'dlopen("/lib/test.so", 2)\n'
        mock_run.return_value = mock_result

        reached, lib, method = validator._run_dynamic_validation(
            harness=harness,
            concrete_inputs=b'\x00\x01\x02',
            expected_lib='/lib/test.so',
            timeout=5,
        )

        # Should have called subprocess at least once (ltrace or LD_DEBUG fallback)
        assert mock_run.called
