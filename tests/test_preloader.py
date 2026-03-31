"""Tests for LibraryPreloader."""

import pytest
import os


class TestLibraryPreloader:
    def test_init(self, angr_project):
        """Test preloader initialization."""
        from dynpathresolver.elf.preloader import LibraryPreloader

        preloader = LibraryPreloader(angr_project)

        assert len(preloader.loaded_libs) == 0
        assert len(preloader.COMMON_LIBS) > 0

    def test_add_library_paths_directory(self, angr_project, tmp_path):
        """Test adding a directory of libraries."""
        from dynpathresolver.elf.preloader import LibraryPreloader

        preloader = LibraryPreloader(angr_project)

        # Create fake library files
        (tmp_path / "libfake.so").touch()
        (tmp_path / "libtest.so.1").touch()
        (tmp_path / "notalib.txt").touch()

        preloader.add_library_paths([str(tmp_path)])

        assert any("libfake.so" in p for p in preloader.pending_libs)
        assert any("libtest.so.1" in p for p in preloader.pending_libs)
        assert not any("notalib.txt" in p for p in preloader.pending_libs)

    def test_add_library_paths_single_file(self, angr_project, tmp_path):
        """Test adding a single library file."""
        from dynpathresolver.elf.preloader import LibraryPreloader

        preloader = LibraryPreloader(angr_project)

        lib_file = tmp_path / "libsingle.so"
        lib_file.touch()

        preloader.add_library_paths([str(lib_file)])

        assert str(lib_file) in preloader.pending_libs

    def test_scan_for_library_strings(self, angr_project):
        """Test scanning binary for library name strings."""
        from dynpathresolver.elf.preloader import LibraryPreloader

        preloader = LibraryPreloader(angr_project)

        # This may or may not find libraries depending on the test binary
        libs = preloader.scan_for_library_strings()

        assert isinstance(libs, set)

    def test_get_search_paths(self, angr_project):
        """Test getting library search paths."""
        from dynpathresolver.elf.preloader import LibraryPreloader

        preloader = LibraryPreloader(angr_project)
        paths = preloader.get_search_paths()

        assert len(paths) > 0
        # Should include standard paths
        assert any('/lib' in p or '/usr/lib' in p for p in paths)
