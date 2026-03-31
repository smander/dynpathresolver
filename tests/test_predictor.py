"""Tests for heuristic path predictor."""
import pytest
from unittest.mock import MagicMock
import os
import tempfile


def test_string_fragment_assembler_init():
    """Test StringFragmentAssembler initialization."""
    from dynpathresolver.analysis.predictor import StringFragmentAssembler
    mock_project = MagicMock()
    assembler = StringFragmentAssembler(mock_project, 'linux')
    assert assembler.platform == 'linux'
    assert '.so' in assembler.suffixes[0]


def test_string_fragment_assembler_windows():
    """Test StringFragmentAssembler Windows suffix selection."""
    from dynpathresolver.analysis.predictor import StringFragmentAssembler
    mock_project = MagicMock()
    assembler = StringFragmentAssembler(mock_project, 'windows')
    assert '.dll' in assembler.suffixes[0].lower()


def test_find_candidate_names_basic():
    """Test finding candidate names from cached strings."""
    from dynpathresolver.analysis.predictor import StringFragmentAssembler
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    assembler = StringFragmentAssembler(mock_project, 'linux')
    assembler._cached_strings = {'payload', 'secret', 'libtest.so'}
    candidates = assembler.find_candidate_names()
    assert 'libtest.so' in candidates
    assert 'libpayload.so' in candidates


def test_environment_predictor_linux_paths():
    """Test EnvironmentPredictor initializes with Linux paths."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    predictor = EnvironmentPredictor('linux')
    assert any('/lib' in p or '/usr/lib' in p for p in predictor.search_paths)


def test_environment_predictor_windows_paths():
    """Test EnvironmentPredictor initializes with Windows paths."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    predictor = EnvironmentPredictor('windows')
    assert any('Windows' in p for p in predictor.search_paths)


def test_environment_predictor_extra_paths():
    """Test EnvironmentPredictor adds extra paths."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    predictor = EnvironmentPredictor('linux', extra_paths=['/custom/path'])
    assert '/custom/path' in predictor.search_paths


def test_environment_predictor_find_library():
    """Test finding a library in the filesystem."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    with tempfile.TemporaryDirectory() as tmpdir:
        test_lib = os.path.join(tmpdir, 'libtest.so')
        with open(test_lib, 'w') as f:
            f.write('test')
        predictor = EnvironmentPredictor('linux', extra_paths=[tmpdir])
        result = predictor.find_library('libtest.so')
        assert result == test_lib


def test_environment_predictor_find_library_not_found():
    """Test finding a library that doesn't exist."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    predictor = EnvironmentPredictor('linux', extra_paths=[])
    result = predictor.find_library('nonexistent_library_12345.so')
    assert result is None


def test_environment_predictor_find_all_matches():
    """Test finding multiple libraries."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test libraries
        lib1 = os.path.join(tmpdir, 'libfoo.so')
        lib2 = os.path.join(tmpdir, 'libbar.so')
        with open(lib1, 'w') as f:
            f.write('test')
        with open(lib2, 'w') as f:
            f.write('test')

        predictor = EnvironmentPredictor('linux', extra_paths=[tmpdir])
        candidates = {'libfoo.so', 'libbar.so', 'libnotexist.so'}
        matches = predictor.find_all_matches(candidates)

        assert 'libfoo.so' in matches
        assert 'libbar.so' in matches
        assert 'libnotexist.so' not in matches
        assert matches['libfoo.so'] == lib1


def test_pattern_predictor_init():
    """Test PatternPredictor initialization."""
    from dynpathresolver.analysis.predictor import PatternPredictor
    mock_project = MagicMock()
    predictor = PatternPredictor(mock_project)
    assert predictor.project == mock_project


def test_pattern_predictor_analyze_basic():
    """Test PatternPredictor analyze returns predictions."""
    from dynpathresolver.analysis.predictor import PatternPredictor
    mock_project = MagicMock()
    mock_project.filename = '/path/to/testbinary'
    mock_project.loader.all_objects = []
    predictor = PatternPredictor(mock_project)
    result = predictor.analyze()
    assert isinstance(result, set)
    # Should include binary name-based predictions
    assert 'libtestbinary.so' in result


def test_pattern_predictor_xor_detection():
    """Test PatternPredictor XOR pattern detection method."""
    from dynpathresolver.analysis.predictor import PatternPredictor
    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'

    # Create mock symbol with decrypt
    mock_sym = MagicMock()
    mock_sym.name = 'decrypt_data'
    mock_obj = MagicMock()
    mock_obj.symbols = [mock_sym]
    mock_project.loader.all_objects = [mock_obj]

    predictor = PatternPredictor(mock_project)

    # The new behavioral approach detects XOR patterns but doesn't
    # add static name lists - instead it marks paths as suspicious
    # when they are decrypted at runtime
    assert predictor._has_xor_patterns() is True


def test_pattern_predictor_network_detection():
    """Test PatternPredictor network pattern detection method."""
    from dynpathresolver.analysis.predictor import PatternPredictor
    mock_project = MagicMock()
    mock_project.filename = '/path/to/binary'

    # Create mock symbol with socket
    mock_sym = MagicMock()
    mock_sym.name = 'socket'
    mock_obj = MagicMock()
    mock_obj.symbols = [mock_sym]
    mock_project.loader.all_objects = [mock_obj]

    predictor = PatternPredictor(mock_project)

    # The new behavioral approach detects network patterns but doesn't
    # add static name lists - instead it marks paths as suspicious
    # when they are derived from network input
    assert predictor._has_network_patterns() is True


def test_heuristic_predictor_init():
    """Test HeuristicPredictor initialization."""
    from dynpathresolver.analysis.predictor import HeuristicPredictor
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    mock_project.filename = '/path/to/binary'
    predictor = HeuristicPredictor(mock_project, 'linux', [])
    assert predictor.project == mock_project


def test_heuristic_predictor_predict_returns_dict():
    """Test HeuristicPredictor predict returns a dictionary."""
    from dynpathresolver.analysis.predictor import HeuristicPredictor
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    mock_project.filename = '/path/to/binary'
    mock_project.loader.symbols = []
    predictor = HeuristicPredictor(mock_project, 'linux', [])
    result = predictor.predict()
    assert isinstance(result, dict)


def test_heuristic_predictor_with_real_library():
    """Test HeuristicPredictor resolves actual libraries."""
    from dynpathresolver.analysis.predictor import HeuristicPredictor
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test library
        test_lib = os.path.join(tmpdir, 'libtestmod.so')
        with open(test_lib, 'w') as f:
            f.write('test')

        mock_project = MagicMock()
        mock_project.loader.all_objects = []
        mock_project.filename = '/path/to/binary'

        predictor = HeuristicPredictor(mock_project, 'linux', [tmpdir])
        # Manually add a candidate that we know exists
        predictor.fragment_assembler._cached_strings = {'testmod'}

        result = predictor.predict()
        assert 'libtestmod.so' in result
        assert result['libtestmod.so'] == test_lib


def test_string_fragment_assembler_extract_caching():
    """Test that extract_all_strings caches results."""
    from dynpathresolver.analysis.predictor import StringFragmentAssembler
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    assembler = StringFragmentAssembler(mock_project, 'linux')

    # First call should set cache
    result1 = assembler.extract_all_strings()
    assembler._cached_strings = {'cached_value'}  # Modify cache

    # Second call should return cached value
    result2 = assembler.extract_all_strings()
    assert 'cached_value' in result2


def test_environment_predictor_deduplicates_paths():
    """Test that EnvironmentPredictor deduplicates paths."""
    from dynpathresolver.analysis.predictor import EnvironmentPredictor
    predictor = EnvironmentPredictor('linux', extra_paths=['/lib', '/lib', '/custom'])
    # Count occurrences of /lib
    lib_count = sum(1 for p in predictor.search_paths if p == '/lib')
    assert lib_count == 1


def test_pattern_predictor_no_filename():
    """Test PatternPredictor handles missing filename."""
    from dynpathresolver.analysis.predictor import PatternPredictor
    mock_project = MagicMock()
    mock_project.filename = None
    mock_project.loader.all_objects = []
    predictor = PatternPredictor(mock_project)
    result = predictor.analyze()
    assert isinstance(result, set)


# ============================================================================
# Tests for new behavioral analysis classes
# ============================================================================

def test_suspicious_indicator_enum():
    """Test SuspiciousIndicator enum values exist."""
    from dynpathresolver.analysis.predictor import SuspiciousIndicator
    assert SuspiciousIndicator.TEMP_DIRECTORY
    assert SuspiciousIndicator.MEMORY_BACKED
    assert SuspiciousIndicator.DECRYPTED_PATH
    assert SuspiciousIndicator.NETWORK_DERIVED


def test_suspicious_path_creation():
    """Test SuspiciousPath dataclass creation."""
    from dynpathresolver.analysis.predictor import SuspiciousPath, SuspiciousIndicator
    path = SuspiciousPath(
        path='/tmp/malware.so',
        indicators=[SuspiciousIndicator.TEMP_DIRECTORY],
        source='test'
    )
    assert path.path == '/tmp/malware.so'
    assert SuspiciousIndicator.TEMP_DIRECTORY in path.indicators
    assert path.is_suspicious() is True


def test_suspicious_path_not_suspicious():
    """Test SuspiciousPath with no indicators is not suspicious."""
    from dynpathresolver.analysis.predictor import SuspiciousPath
    path = SuspiciousPath(path='/usr/lib/libssl.so', indicators=[])
    assert path.is_suspicious() is False
    assert path.suspicion_score() == 0.0


def test_suspicious_path_suspicion_score():
    """Test SuspiciousPath suspicion score calculation."""
    from dynpathresolver.analysis.predictor import SuspiciousPath, SuspiciousIndicator
    path = SuspiciousPath(
        path='/proc/self/fd/5',
        indicators=[
            SuspiciousIndicator.MEMORY_BACKED,
            SuspiciousIndicator.DECRYPTED_PATH
        ]
    )
    score = path.suspicion_score()
    # Should have high score due to memory-backed (0.9) and decrypted (0.8)
    assert score > 0.7


def test_behavioral_pattern_analyzer_init():
    """Test BehavioralPatternAnalyzer initialization."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')
    assert analyzer.platform == 'linux'


def test_behavioral_pattern_analyzer_temp_directory():
    """Test detection of temp directory loading."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer, SuspiciousIndicator
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/tmp/payload.so')
    assert SuspiciousIndicator.TEMP_DIRECTORY in result.indicators


def test_behavioral_pattern_analyzer_memory_backed():
    """Test detection of memory-backed file loading."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer, SuspiciousIndicator
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/proc/self/fd/5')
    assert SuspiciousIndicator.MEMORY_BACKED in result.indicators


def test_behavioral_pattern_analyzer_hidden_directory():
    """Test detection of hidden directory loading."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer, SuspiciousIndicator
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/home/user/.hidden/libmalware.so')
    assert SuspiciousIndicator.HIDDEN_DIRECTORY in result.indicators


def test_behavioral_pattern_analyzer_path_traversal():
    """Test detection of path traversal."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer, SuspiciousIndicator
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/var/www/../../../etc/payload.so')
    assert SuspiciousIndicator.PATH_TRAVERSAL in result.indicators


def test_behavioral_pattern_analyzer_normal_path():
    """Test that normal system paths are not suspicious."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/usr/lib/x86_64-linux-gnu/libssl.so.1.1')
    assert not result.is_suspicious()


def test_behavioral_pattern_analyzer_context_decrypted():
    """Test context-based decryption indicator."""
    from dynpathresolver.analysis.predictor import BehavioralPatternAnalyzer, SuspiciousIndicator
    mock_project = MagicMock()
    analyzer = BehavioralPatternAnalyzer(mock_project, 'linux')

    result = analyzer.analyze_path('/usr/lib/normal.so', context={'decrypted': True})
    assert SuspiciousIndicator.DECRYPTED_PATH in result.indicators


def test_load_behavior_detector_init():
    """Test LoadBehaviorDetector initialization."""
    from dynpathresolver.analysis.predictor import LoadBehaviorDetector
    mock_project = MagicMock()
    detector = LoadBehaviorDetector(mock_project)
    assert detector.open_calls == {}
    assert detector.mmap_calls == []


def test_load_behavior_detector_record_open():
    """Test recording open syscalls."""
    from dynpathresolver.analysis.predictor import LoadBehaviorDetector
    mock_project = MagicMock()
    mock_state = MagicMock()
    mock_state.addr = 0x1000
    mock_state.history.depth = 5

    detector = LoadBehaviorDetector(mock_project)
    detector.record_open(mock_state, '/tmp/test.so', 0, 3)

    assert 3 in detector.open_calls
    assert detector.open_calls[3]['path'] == '/tmp/test.so'


def test_load_behavior_detector_record_mmap_with_exec():
    """Test detecting manual library load via mmap."""
    from dynpathresolver.analysis.predictor import LoadBehaviorDetector
    mock_project = MagicMock()
    mock_state = MagicMock()
    mock_state.addr = 0x1000
    mock_state.history.depth = 5

    detector = LoadBehaviorDetector(mock_project)

    # First record an open
    detector.record_open(mock_state, '/tmp/manual.so', 0, 5)

    # Then record mmap with PROT_EXEC
    PROT_EXEC = 0x4
    detector.record_mmap(mock_state, 0x7f000000, 4096, PROT_EXEC, 0, 5)

    # Should detect this as a manual library load
    loads = detector.get_detected_loads()
    assert len(loads) == 1
    assert loads[0].path == '/tmp/manual.so'


def test_heuristic_predictor_get_suspicious_discoveries():
    """Test HeuristicPredictor get_suspicious_discoveries method."""
    from dynpathresolver.analysis.predictor import HeuristicPredictor, SuspiciousPath, SuspiciousIndicator
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    mock_project.filename = '/path/to/binary'

    predictor = HeuristicPredictor(mock_project, 'linux', [])

    # Add some analyzed paths
    predictor.all_analyzed_paths = [
        SuspiciousPath('/tmp/bad.so', [SuspiciousIndicator.TEMP_DIRECTORY]),
        SuspiciousPath('/usr/lib/good.so', []),
    ]

    suspicious = predictor.get_suspicious_discoveries(min_score=0.1)
    assert len(suspicious) == 1
    assert suspicious[0].path == '/tmp/bad.so'


def test_heuristic_predictor_get_threat_summary():
    """Test HeuristicPredictor get_threat_summary method."""
    from dynpathresolver.analysis.predictor import HeuristicPredictor, SuspiciousPath, SuspiciousIndicator
    mock_project = MagicMock()
    mock_project.loader.all_objects = []
    mock_project.filename = '/path/to/binary'

    predictor = HeuristicPredictor(mock_project, 'linux', [])

    # Add analyzed paths
    predictor.all_analyzed_paths = [
        SuspiciousPath('/proc/self/fd/5', [SuspiciousIndicator.MEMORY_BACKED]),
        SuspiciousPath('/tmp/payload.so', [SuspiciousIndicator.TEMP_DIRECTORY]),
        SuspiciousPath('/usr/lib/libssl.so', []),
    ]

    summary = predictor.get_threat_summary()
    assert summary['total_paths'] == 3
    assert summary['suspicious_paths'] == 2
    assert 'MEMORY_BACKED' in summary['by_indicator']
    assert 'TEMP_DIRECTORY' in summary['by_indicator']
