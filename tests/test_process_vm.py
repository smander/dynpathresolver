"""Tests for process_vm_readv/writev syscall SimProcedures."""

import pytest
from unittest.mock import MagicMock


class TestDynProcessVmReadv:
    """Test cases for DynProcessVmReadv SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmReadv
        DynProcessVmReadv.reset()
        yield
        DynProcessVmReadv.reset()

    def test_basic_readv(self):
        """Test basic process_vm_readv operation."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmReadv

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        proc = DynProcessVmReadv()
        proc.state = state

        # Read from pid 1234
        result = proc.run(1234, 0, 1, 0, 1, 0)

        # Should return symbolic result
        assert result is not None


class TestDynProcessVmWritev:
    """Test cases for DynProcessVmWritev SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmWritev
        DynProcessVmWritev.reset()
        yield
        DynProcessVmWritev.reset()

    def test_basic_writev(self):
        """Test basic process_vm_writev operation."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmWritev

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        proc = DynProcessVmWritev()
        proc.state = state

        # Write to pid 1234 (code injection)
        result = proc.run(1234, 0, 1, 0, 1, 0)

        # Should return symbolic result
        assert result is not None

    def test_writev_technique_notification(self):
        """Test that process_vm_writev notifies technique."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmWritev

        technique = MagicMock()
        technique._record_process_vm_op = MagicMock()
        technique._record_code_injection = MagicMock()

        DynProcessVmWritev.technique = technique

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        proc = DynProcessVmWritev()
        proc.state = state

        # Write to another process
        proc.run(1234, 0, 1, 0, 1, 0)

        # Technique should be notified
        technique._record_process_vm_op.assert_called_once()

    def test_writev_with_iovecs(self):
        """Test extracting iovec addresses from process_vm_writev."""
        from dynpathresolver.simprocedures.syscalls.process_vm import DynProcessVmWritev

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        # Mock memory for iovecs
        # iovec: { void *iov_base; size_t iov_len; }
        def mem_side_effect(addr):
            mock_mem = MagicMock()
            if addr == 0x1000:  # First iovec base
                mock_mem.uint64_t.concrete = 0x7f0000001000
            elif addr == 0x1008:  # First iovec len
                mock_mem.uint64_t.concrete = 0x1000
            else:
                mock_mem.uint64_t.concrete = 0
            return mock_mem

        state.mem.__getitem__ = MagicMock(side_effect=mem_side_effect)

        proc = DynProcessVmWritev()
        proc.state = state

        # Extract iovecs
        iovecs = proc._extract_iovecs(0x1000, 1)

        assert len(iovecs) == 1
        assert iovecs[0] == (0x7f0000001000, 0x1000)
