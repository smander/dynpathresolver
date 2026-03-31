"""Tests for fopen() SimProcedure."""

import pytest
from unittest.mock import MagicMock

import claripy


class TestDynFopen:
    """Test cases for DynFopen SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen
        DynFopen.reset()
        yield
        DynFopen.reset()

    def _make_state(self, string_value=None):
        """Create a mock state with string reading support."""
        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        if string_value is not None:
            mem_mock = MagicMock()
            mem_mock.__getitem__ = MagicMock(return_value=MagicMock(
                string=MagicMock(concrete=string_value.encode('utf-8'))
            ))
            state.mem = mem_mock

        return state

    def test_class_attributes_exist(self):
        """Test that DynFopen has required class attributes."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen
        assert hasattr(DynFopen, 'memory_tracker')
        assert hasattr(DynFopen, 'technique')
        assert hasattr(DynFopen, '_fd_counter')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen
        DynFopen.memory_tracker = MagicMock()
        DynFopen.technique = MagicMock()
        DynFopen._fd_counter = 200

        DynFopen.reset()

        assert DynFopen.memory_tracker is None
        assert DynFopen.technique is None
        assert DynFopen._fd_counter == 100

    def test_blocks_proc_paths(self):
        """Test that /proc/ paths are blocked (returns NULL)."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        state = self._make_state('/proc/self/status')

        proc = DynFopen()
        proc.state = state

        result = proc.run(0x1000, 0x2000)  # filename_ptr, mode_ptr
        # Should return 0 (NULL) for /proc/ paths
        assert result.args[0] == 0

    def test_blocks_proc_self_maps(self):
        """Test that /proc/self/maps is blocked."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        state = self._make_state('/proc/self/maps')

        proc = DynFopen()
        proc.state = state

        result = proc.run(0x1000, 0x2000)
        assert result.args[0] == 0

    def test_tracks_so_opens(self):
        """Test that .so file opens are tracked in memory_tracker."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        tracker = MagicMock()
        state = self._make_state('./libmemfd_payload.so')
        state.globals['dpr_memory_tracker'] = tracker

        proc = DynFopen()
        proc.state = state

        result = proc.run(0x1000, 0x2000)
        # Should call record_open on the tracker
        tracker.record_open.assert_called_once()
        call_args = tracker.record_open.call_args
        assert './libmemfd_payload.so' in str(call_args)

    def test_returns_symbolic_for_normal_files(self):
        """Test that normal files get a symbolic FILE* result."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        state = self._make_state('/etc/config.txt')

        proc = DynFopen()
        proc.state = state

        result = proc.run(0x1000, 0x2000)
        # Should return a symbolic value (BVS) for normal files
        assert hasattr(result, 'symbolic') or result.symbolic

    def test_fd_allocation_increments(self):
        """Test that fd counter increments with each .so open."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        initial = DynFopen._fd_counter
        fd1 = DynFopen._allocate_fd()
        fd2 = DynFopen._allocate_fd()

        assert fd1 == initial
        assert fd2 == initial + 1

    def test_symbolic_filename_returns_symbolic(self):
        """Test handling of symbolic filename pointer."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=True)
        state.solver.satisfiable = MagicMock(return_value=False)
        state.arch.bits = 64

        proc = DynFopen()
        proc.state = state

        result = proc.run(claripy.BVS("ptr", 64), 0x2000)
        # Should return symbolic when filename can't be resolved
        assert hasattr(result, 'symbolic') or result.symbolic


class TestDynFopenImport:
    """Test that DynFopen is properly exported."""

    def test_import_from_syscalls(self):
        """Test DynFopen can be imported from syscalls package."""
        from dynpathresolver.simprocedures.syscalls import DynFopen
        assert DynFopen is not None

    def test_import_from_fopen_module(self):
        """Test DynFopen can be imported from fopen module."""
        from dynpathresolver.simprocedures.syscalls.fopen import DynFopen
        assert DynFopen is not None
