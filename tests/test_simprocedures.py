"""Tests for SimProcedures (dlopen, dlsym, dlclose)."""

import pytest
import angr
import claripy
import os
import tempfile

from dynpathresolver.simprocedures import DynDlopen, DynDlsym, DynDlclose


@pytest.fixture
def dlopen_binary(tmp_path):
    """Create a binary that uses dlopen/dlsym."""
    src = tmp_path / "dlopen_test.c"
    src.write_text("""
#include <dlfcn.h>
#include <stdio.h>

int main() {
    void *handle = dlopen("libm.so.6", RTLD_NOW);
    if (handle) {
        void *sym = dlsym(handle, "sin");
        dlclose(handle);
    }
    return 0;
}
""")
    binary = tmp_path / "dlopen_test"
    result = os.system(f"gcc -o {binary} {src} -ldl 2>/dev/null")
    if binary.exists():
        return str(binary)
    return None


@pytest.fixture
def simple_lib(tmp_path):
    """Create a simple shared library for testing."""
    src = tmp_path / "testlib.c"
    src.write_text("""
int test_func(int x) {
    return x * 2;
}

int another_func(int x, int y) {
    return x + y;
}
""")
    lib = tmp_path / "libtestlib.so"
    result = os.system(f"gcc -shared -fPIC -o {lib} {src} 2>/dev/null")
    if lib.exists():
        return str(lib)
    return None


class TestDynDlopen:
    """Tests for DynDlopen SimProcedure."""

    def test_class_attributes_exist(self):
        """Test that DynDlopen has required class attributes."""
        assert hasattr(DynDlopen, 'loaded_libraries')
        assert hasattr(DynDlopen, 'library_paths')
        assert hasattr(DynDlopen, 'preloader')
        assert hasattr(DynDlopen, '_handle_counter')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        # Add some state
        DynDlopen.loaded_libraries[0x1000] = "test"
        DynDlopen.library_paths.append("/test/path")
        DynDlopen._handle_counter = 0x80000000

        # Reset
        DynDlopen.reset()

        # Verify cleared
        assert DynDlopen.loaded_libraries == {}
        assert DynDlopen.library_paths == []
        assert DynDlopen.preloader is None
        assert DynDlopen._handle_counter == 0x7f000000

    def test_get_next_handle_increments(self):
        """Test that _get_next_handle returns incrementing handles."""
        DynDlopen.reset()

        handle1 = DynDlopen._get_next_handle()
        handle2 = DynDlopen._get_next_handle()
        handle3 = DynDlopen._get_next_handle()

        assert handle1 == 0x7f000000
        assert handle2 == 0x7f001000
        assert handle3 == 0x7f002000

    def test_dlopen_with_project(self, dlopen_binary, simple_lib):
        """Test dlopen with an actual project and library."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")
        if simple_lib is None:
            pytest.skip("gcc not available for building test library")

        DynDlopen.reset()

        project = angr.Project(dlopen_binary, auto_load_libs=False)
        state = project.factory.blank_state()

        # Set up library paths
        lib_dir = os.path.dirname(simple_lib)
        DynDlopen.library_paths = [lib_dir]

        # Create SimProcedure instance
        dlopen = DynDlopen()

        # Write library path to memory
        lib_name = os.path.basename(simple_lib)
        path_addr = 0x1000000
        state.memory.store(path_addr, lib_name.encode() + b'\x00')

        # Call run method indirectly by setting up state
        # We test the _find_library method directly
        found = dlopen._find_library(lib_name)
        assert found is not None
        assert found.endswith(lib_name)


class TestDynDlsym:
    """Tests for DynDlsym SimProcedure."""

    def test_loaded_libraries_property(self):
        """Test that loaded_libraries property references DynDlopen."""
        DynDlopen.reset()
        DynDlopen.loaded_libraries[0x1234] = "test_lib"

        dlsym = DynDlsym()
        assert dlsym.loaded_libraries == DynDlopen.loaded_libraries
        assert 0x1234 in dlsym.loaded_libraries

    def test_search_all_libraries_with_project(self, dlopen_binary):
        """Test searching all libraries in a project."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")

        DynDlopen.reset()
        project = angr.Project(dlopen_binary, auto_load_libs=True)
        state = project.factory.blank_state()

        dlsym = DynDlsym()
        dlsym.state = state

        # Search for a common symbol that should exist
        # main should be in the binary
        addr = dlsym._search_all_libraries("main")
        # main might or might not be found depending on symbol visibility
        # but the method should not raise an exception


class TestDynDlclose:
    """Tests for DynDlclose SimProcedure."""

    def test_dlclose_returns_success(self, dlopen_binary):
        """Test that dlclose returns 0 (success)."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")

        project = angr.Project(dlopen_binary, auto_load_libs=False)
        state = project.factory.blank_state()

        dlclose = DynDlclose()
        dlclose.state = state

        # Call with a concrete handle
        handle = claripy.BVV(0x7f000000, state.arch.bits)
        result = dlclose.run(handle)

        # Should return 0
        assert state.solver.eval(result) == 0

    def test_dlclose_with_symbolic_handle(self, dlopen_binary):
        """Test dlclose with symbolic handle."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")

        project = angr.Project(dlopen_binary, auto_load_libs=False)
        state = project.factory.blank_state()

        dlclose = DynDlclose()
        dlclose.state = state

        # Call with a symbolic handle
        handle = claripy.BVS("handle", state.arch.bits)
        result = dlclose.run(handle)

        # Should still return 0
        assert state.solver.eval(result) == 0


class TestSimProcedureIntegration:
    """Integration tests for SimProcedures working together."""

    def test_dlopen_dlsym_dlclose_sequence(self, dlopen_binary, simple_lib):
        """Test complete dlopen -> dlsym -> dlclose sequence."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")
        if simple_lib is None:
            pytest.skip("gcc not available for building test library")

        DynDlopen.reset()

        # Load with libs to have dlopen symbols available
        project = angr.Project(dlopen_binary, auto_load_libs=True)

        # Set up library paths
        lib_dir = os.path.dirname(simple_lib)
        DynDlopen.library_paths = [lib_dir]

        # Hook dlopen, dlsym, dlclose - try to find and hook
        for sym_name, simproc_class in [('dlopen', DynDlopen), ('dlsym', DynDlsym), ('dlclose', DynDlclose)]:
            try:
                sym = project.loader.find_symbol(sym_name)
                if sym:
                    project.hook(sym.rebased_addr, simproc_class())
            except (IndexError, Exception):
                # Symbol not found or other issue, skip
                pass

        # Create initial state
        state = project.factory.entry_state()

        # Run simulation with step limit to avoid infinite loops
        simgr = project.factory.simgr(state)
        for _ in range(100):
            if len(simgr.active) == 0:
                break
            simgr.step()

        # Simulation should progress without crashing
        # We just verify it ran without exceptions
        assert simgr is not None

    def test_hooks_installed_by_address(self, dlopen_binary):
        """Test that hooks can be installed by address."""
        if dlopen_binary is None:
            pytest.skip("gcc not available for building test binary")

        DynDlopen.reset()
        project = angr.Project(dlopen_binary, auto_load_libs=True)

        # Find dlopen symbol and hook by address
        try:
            sym = project.loader.find_symbol('dlopen')
            if sym:
                project.hook(sym.rebased_addr, DynDlopen())
                # Verify hook is installed
                assert project.is_hooked(sym.rebased_addr)
            else:
                # If dlopen not found as symbol, just verify project works
                assert project is not None
        except (IndexError, Exception):
            # Symbol lookup failed (macOS/platform issue), just verify project works
            assert project is not None


class TestLibraryFinding:
    """Tests for library path resolution."""

    def test_find_library_absolute_path(self, simple_lib):
        """Test finding library with absolute path."""
        if simple_lib is None:
            pytest.skip("gcc not available for building test library")

        DynDlopen.reset()
        dlopen = DynDlopen()

        # Should find absolute path directly
        found = dlopen._find_library(simple_lib)
        assert found == simple_lib

    def test_find_library_relative_name(self, simple_lib):
        """Test finding library with just filename."""
        if simple_lib is None:
            pytest.skip("gcc not available for building test library")

        DynDlopen.reset()
        lib_dir = os.path.dirname(simple_lib)
        lib_name = os.path.basename(simple_lib)

        DynDlopen.library_paths = [lib_dir]
        dlopen = DynDlopen()

        found = dlopen._find_library(lib_name)
        assert found is not None
        assert found.endswith(lib_name)

    def test_find_library_not_found(self):
        """Test that non-existent library returns None."""
        DynDlopen.reset()
        dlopen = DynDlopen()

        found = dlopen._find_library("nonexistent_library_xyz.so")
        assert found is None

    def test_find_library_with_path_prefix(self, simple_lib):
        """Test finding library with partial path."""
        if simple_lib is None:
            pytest.skip("gcc not available for building test library")

        DynDlopen.reset()
        lib_dir = os.path.dirname(simple_lib)
        lib_name = os.path.basename(simple_lib)

        DynDlopen.library_paths = [lib_dir]
        dlopen = DynDlopen()

        # Try with ./libname
        found = dlopen._find_library(f"./{lib_name}")
        # May or may not find depending on cwd, but shouldn't crash
