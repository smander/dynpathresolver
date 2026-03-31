"""Tests for unpacking support module."""

import pytest
from unittest.mock import MagicMock, patch, call


def test_unpacking_detector_init():
    """Test UnpackingDetector initializes with project."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()
    detector = UnpackingDetector(mock_project)

    assert detector.project == mock_project
    assert detector._written_regions == []


def test_is_executable_region_in_executable_segment():
    """Test is_executable_region returns True for executable addresses."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock segment with executable flag
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)

    # Address within executable segment
    assert detector.is_executable_region(0x400500) is True


def test_is_executable_region_not_in_executable_segment():
    """Test is_executable_region returns False for non-executable addresses."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock segment without executable flag
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x600000
    mock_segment.max_addr = 0x601000
    mock_segment.is_executable = False

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)

    # Address within non-executable segment
    assert detector.is_executable_region(0x600500) is False


def test_is_executable_region_outside_all_segments():
    """Test is_executable_region returns False for addresses outside all segments."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)

    # Address outside all segments
    assert detector.is_executable_region(0x700000) is False


def test_record_write_to_executable():
    """Test record_write records writes to executable regions."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    mock_state = MagicMock()

    # Record write to executable region
    detector.record_write(mock_state, 0x400100, 64)

    assert len(detector._written_regions) == 1
    assert detector._written_regions[0] == (0x400100, 0x400100 + 64)


def test_record_write_to_non_executable():
    """Test record_write ignores writes to non-executable regions."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock non-executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x600000
    mock_segment.max_addr = 0x601000
    mock_segment.is_executable = False

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    mock_state = MagicMock()

    # Record write to non-executable region
    detector.record_write(mock_state, 0x600100, 64)

    # Should not record
    assert len(detector._written_regions) == 0


def test_get_unpacked_regions():
    """Test get_unpacked_regions returns recorded writes."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x410000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    mock_state = MagicMock()

    # Record multiple writes
    detector.record_write(mock_state, 0x400100, 64)
    detector.record_write(mock_state, 0x400200, 128)

    regions = detector.get_unpacked_regions()

    assert len(regions) == 2
    assert (0x400100, 0x400140) in regions  # 0x400100 + 64 = 0x400140
    assert (0x400200, 0x400280) in regions  # 0x400200 + 128 = 0x400280


def test_has_unpacking_activity_false():
    """Test has_unpacking_activity returns False when no writes detected."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()
    mock_project.loader.main_object.segments = []

    detector = UnpackingDetector(mock_project)

    assert detector.has_unpacking_activity() is False


def test_has_unpacking_activity_true():
    """Test has_unpacking_activity returns True when writes detected."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    mock_state = MagicMock()

    detector.record_write(mock_state, 0x400100, 64)

    assert detector.has_unpacking_activity() is True


def test_unpacking_handler_init():
    """Test UnpackingHandler initializes with project and detector."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()
    detector = UnpackingDetector(mock_project)

    handler = UnpackingHandler(mock_project, detector)

    assert handler.project == mock_project
    assert handler.detector == detector


def test_unpacking_handler_install_breakpoint():
    """Test UnpackingHandler installs memory write breakpoint."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()
    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)

    mock_state = MagicMock()

    # Install breakpoint
    handler.install_write_breakpoint(mock_state)

    # Verify inspect.b was called with correct parameters
    mock_state.inspect.b.assert_called_once()
    call_args = mock_state.inspect.b.call_args

    # First argument should be 'mem_write'
    assert call_args[0][0] == 'mem_write'

    # Should have when='after' and an action callback
    assert call_args[1].get('when') == 'after'
    assert 'action' in call_args[1]


def test_unpacking_handler_on_memory_write():
    """Test on_memory_write delegates to detector."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)

    mock_state = MagicMock()
    # Mock the inspect attributes for address and length
    mock_state.inspect.mem_write_address = MagicMock()
    mock_state.inspect.mem_write_length = MagicMock()

    # Mock solver to return concrete values
    mock_state.solver.eval.side_effect = [0x400100, 64]

    handler.on_memory_write(mock_state)

    # Should have recorded the write
    assert detector.has_unpacking_activity() is True


def test_unpacking_handler_should_rescan_false():
    """Test should_rescan returns False when no unpacking activity."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()
    mock_project.loader.main_object.segments = []

    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)

    assert handler.should_rescan() is False


def test_unpacking_handler_should_rescan_true():
    """Test should_rescan returns True after unpacking activity."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)
    mock_state = MagicMock()

    detector.record_write(mock_state, 0x400100, 64)

    assert handler.should_rescan() is True


def test_unpacking_handler_get_new_entry_points():
    """Test get_new_entry_points returns start addresses of unpacked regions."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x410000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)
    mock_state = MagicMock()

    # Record multiple writes
    detector.record_write(mock_state, 0x400100, 64)
    detector.record_write(mock_state, 0x400200, 128)

    entry_points = handler.get_new_entry_points()

    assert 0x400100 in entry_points
    assert 0x400200 in entry_points
    assert len(entry_points) == 2


def test_unpacking_handler_get_new_entry_points_empty():
    """Test get_new_entry_points returns empty list when no activity."""
    from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler

    mock_project = MagicMock()
    mock_project.loader.main_object.segments = []

    detector = UnpackingDetector(mock_project)
    handler = UnpackingHandler(mock_project, detector)

    entry_points = handler.get_new_entry_points()

    assert entry_points == []


def test_record_write_invalid_size():
    """Test that invalid write sizes are ignored."""
    from dynpathresolver.detection.unpacking import UnpackingDetector

    mock_project = MagicMock()

    # Create mock executable segment
    mock_segment = MagicMock()
    mock_segment.min_addr = 0x400000
    mock_segment.max_addr = 0x401000
    mock_segment.is_executable = True

    mock_project.loader.main_object.segments = [mock_segment]

    detector = UnpackingDetector(mock_project)
    mock_state = MagicMock()

    # Test with zero size - should be ignored
    detector.record_write(mock_state, 0x400100, 0)
    assert len(detector._written_regions) == 0

    # Test with negative size - should be ignored
    detector.record_write(mock_state, 0x400100, -1)
    assert len(detector._written_regions) == 0

    # Verify no regions are recorded
    assert detector.has_unpacking_activity() is False

    # Verify valid size still works
    detector.record_write(mock_state, 0x400100, 64)
    assert len(detector._written_regions) == 1
