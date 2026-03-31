"""Tests for platform detection."""
import pytest
from unittest.mock import MagicMock


def test_detect_linux_from_elf():
    """Test ELF binary detected as Linux."""
    from dynpathresolver.elf.platform import PlatformDetector
    mock_project = MagicMock()
    mock_obj = MagicMock()
    mock_obj.__class__.__name__ = 'ELF'
    mock_project.loader.main_object = mock_obj
    assert PlatformDetector.detect(mock_project) == 'linux'


def test_detect_windows_from_pe():
    """Test PE binary detected as Windows."""
    from dynpathresolver.elf.platform import PlatformDetector
    mock_project = MagicMock()
    mock_obj = MagicMock()
    mock_obj.__class__.__name__ = 'PE'
    mock_project.loader.main_object = mock_obj
    assert PlatformDetector.detect(mock_project) == 'windows'


def test_detect_windows_from_os_attribute():
    """Test Windows detected from os attribute."""
    from dynpathresolver.elf.platform import PlatformDetector
    mock_project = MagicMock()
    mock_obj = MagicMock()
    mock_obj.__class__.__name__ = 'Unknown'
    mock_obj.os = 'windows'
    mock_project.loader.main_object = mock_obj
    assert PlatformDetector.detect(mock_project) == 'windows'


def test_detect_defaults_to_linux():
    """Test unknown format defaults to Linux."""
    from dynpathresolver.elf.platform import PlatformDetector
    mock_project = MagicMock()
    mock_obj = MagicMock()
    mock_obj.__class__.__name__ = 'Unknown'
    mock_obj.os = None
    mock_project.loader.main_object = mock_obj
    assert PlatformDetector.detect(mock_project) == 'linux'
