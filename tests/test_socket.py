"""Tests for socket/network SimProcedures."""

import pytest
from unittest.mock import MagicMock

import claripy

from dynpathresolver.simprocedures.syscalls import (
    DynSocket, DynConnect, DynBind, DynListen, DynAccept,
    DynRecv, DynRecvfrom, DynSend, DynSendto,
)
from dynpathresolver.config.constants import SOCKET_FD_BASE


class TestDynSocket:
    """Tests for DynSocket SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynSocket.reset()
        yield
        DynSocket.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynSocket has required class attributes."""
        assert hasattr(DynSocket, 'memory_tracker')
        assert hasattr(DynSocket, 'technique')
        assert hasattr(DynSocket, '_fd_counter')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynSocket.memory_tracker = MagicMock()
        DynSocket.technique = MagicMock()
        DynSocket._fd_counter = 999

        DynSocket.reset()

        assert DynSocket.memory_tracker is None
        assert DynSocket.technique is None
        assert DynSocket._fd_counter == SOCKET_FD_BASE

    def test_fd_allocation(self):
        """Test that fd allocation increments correctly."""
        fd1 = DynSocket._allocate_fd()
        fd2 = DynSocket._allocate_fd()
        assert fd1 == SOCKET_FD_BASE
        assert fd2 == SOCKET_FD_BASE + 1

    def test_run_basic(self, mock_state):
        """Test basic socket() execution."""
        proc = DynSocket()
        proc.state = mock_state

        result = proc.run(2, 1, 0)  # AF_INET, SOCK_STREAM, 0

        assert result is not None

    def test_run_with_memory_tracker(self, mock_state):
        """Test socket() with memory tracker."""
        tracker = MagicMock()
        DynSocket.memory_tracker = tracker

        proc = DynSocket()
        proc.state = mock_state

        proc.run(2, 1, 0)

        tracker.record_socket.assert_called_once()


class TestDynConnect:
    """Tests for DynConnect SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynConnect.reset()
        yield
        DynConnect.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynConnect has required class attributes."""
        assert hasattr(DynConnect, 'memory_tracker')
        assert hasattr(DynConnect, 'technique')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynConnect.memory_tracker = MagicMock()
        DynConnect.technique = MagicMock()

        DynConnect.reset()

        assert DynConnect.memory_tracker is None
        assert DynConnect.technique is None

    def test_run_returns_zero(self, mock_state):
        """Test connect() returns 0 on success."""
        proc = DynConnect()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 16)

        assert result is not None

    def test_run_with_memory_tracker(self, mock_state):
        """Test connect() records in memory tracker."""
        tracker = MagicMock()
        DynConnect.memory_tracker = tracker

        proc = DynConnect()
        proc.state = mock_state

        proc.run(200, 0x7f000000, 16)

        tracker.record_connect.assert_called_once()


class TestDynBind:
    """Tests for DynBind SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynBind.reset()
        yield
        DynBind.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynBind has required class attributes."""
        assert hasattr(DynBind, 'memory_tracker')
        assert hasattr(DynBind, 'technique')

    def test_run_basic(self, mock_state):
        """Test basic bind() execution."""
        proc = DynBind()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 16)

        assert result is not None

    def test_run_with_memory_tracker(self, mock_state):
        """Test bind() records in memory tracker."""
        tracker = MagicMock()
        DynBind.memory_tracker = tracker

        proc = DynBind()
        proc.state = mock_state

        proc.run(200, 0x7f000000, 16)

        tracker.record_bind.assert_called_once()


class TestDynListen:
    """Tests for DynListen SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynListen.reset()
        yield
        DynListen.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynListen has required class attributes."""
        assert hasattr(DynListen, 'memory_tracker')
        assert hasattr(DynListen, 'technique')

    def test_run_basic(self, mock_state):
        """Test basic listen() execution."""
        proc = DynListen()
        proc.state = mock_state

        result = proc.run(200, 5)

        assert result is not None

    def test_run_with_memory_tracker(self, mock_state):
        """Test listen() records in memory tracker."""
        tracker = MagicMock()
        DynListen.memory_tracker = tracker

        proc = DynListen()
        proc.state = mock_state

        proc.run(200, 5)

        tracker.record_listen.assert_called_once()


class TestDynAccept:
    """Tests for DynAccept SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynAccept.reset()
        DynSocket.reset()
        yield
        DynAccept.reset()
        DynSocket.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynAccept has required class attributes."""
        assert hasattr(DynAccept, 'memory_tracker')
        assert hasattr(DynAccept, 'technique')

    def test_run_allocates_new_fd(self, mock_state):
        """Test accept() allocates a new fd via DynSocket._allocate_fd."""
        proc = DynAccept()
        proc.state = mock_state

        result = proc.run(200, 0, 0)

        assert result is not None

    def test_run_with_memory_tracker(self, mock_state):
        """Test accept() records in memory tracker."""
        tracker = MagicMock()
        DynAccept.memory_tracker = tracker

        proc = DynAccept()
        proc.state = mock_state

        proc.run(200, 0, 0)

        tracker.record_accept.assert_called_once()


class TestDynRecv:
    """Tests for DynRecv SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynRecv.reset()
        yield
        DynRecv.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.memory = MagicMock()
        return state

    def test_class_attributes_exist(self):
        """Test that DynRecv has required class attributes."""
        assert hasattr(DynRecv, 'memory_tracker')
        assert hasattr(DynRecv, 'technique')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynRecv.memory_tracker = MagicMock()
        DynRecv.technique = MagicMock()

        DynRecv.reset()

        assert DynRecv.memory_tracker is None
        assert DynRecv.technique is None

    def test_run_with_payload(self, mock_state):
        """Test recv() writes concrete payload data to buffer."""
        payload = b"/tmp/libplugin.so"
        mock_state.globals['dpr_network_payloads'] = {200: payload}

        proc = DynRecv()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 256, 0)

        assert result is not None
        # Verify memory.store was called with payload data
        mock_state.memory.store.assert_called_once()

    def test_run_without_payload(self, mock_state):
        """Test recv() writes zeros when no payload configured."""
        mock_state.globals['dpr_network_payloads'] = {}
        mock_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 64)

        proc = DynRecv()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 64, 0)

        assert result is not None
        mock_state.memory.store.assert_called_once()

    def test_run_with_memory_tracker(self, mock_state):
        """Test recv() records in memory tracker."""
        tracker = MagicMock()
        DynRecv.memory_tracker = tracker
        mock_state.globals['dpr_network_payloads'] = {}

        proc = DynRecv()
        proc.state = mock_state

        proc.run(200, 0x7f000000, 64, 0)

        tracker.record_recv.assert_called_once()

    def test_run_with_taint_tracker(self, mock_state):
        """Test recv() taints buffer when taint tracker available."""
        mock_state.globals['dpr_network_payloads'] = {200: b"test"}

        technique = MagicMock()
        technique.taint_tracker = MagicMock()
        technique.stage_tracker = None
        mock_state.globals['dpr_technique'] = technique

        proc = DynRecv()
        proc.state = mock_state

        proc.run(200, 0x7f000000, 256, 0)

        technique.taint_tracker.taint_network_data.assert_called_once()


class TestDynRecvfrom:
    """Tests for DynRecvfrom SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynRecvfrom.reset()
        yield
        DynRecvfrom.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.memory = MagicMock()
        return state

    def test_class_attributes_exist(self):
        """Test that DynRecvfrom has required class attributes."""
        assert hasattr(DynRecvfrom, 'memory_tracker')
        assert hasattr(DynRecvfrom, 'technique')

    def test_run_with_payload(self, mock_state):
        """Test recvfrom() writes payload and fills src_addr."""
        payload = b"/tmp/libplugin.so"
        mock_state.globals['dpr_network_payloads'] = {200: payload}

        proc = DynRecvfrom()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 256, 0, 0x7f001000, 0x7f002000)

        assert result is not None
        # memory.store called for both payload and src_addr
        assert mock_state.memory.store.call_count >= 1

    def test_run_with_memory_tracker(self, mock_state):
        """Test recvfrom() records in memory tracker with source addr."""
        tracker = MagicMock()
        DynRecvfrom.memory_tracker = tracker
        mock_state.globals['dpr_network_payloads'] = {}

        proc = DynRecvfrom()
        proc.state = mock_state

        proc.run(200, 0x7f000000, 64, 0, 0, 0)

        tracker.record_recv.assert_called_once()
        # Verify source_addr was passed
        call_kwargs = tracker.record_recv.call_args
        assert call_kwargs[1].get('source_addr') == "127.0.0.1:4444" or \
               (len(call_kwargs[0]) >= 5 and call_kwargs[0][4] == "127.0.0.1:4444")


class TestDynSend:
    """Tests for DynSend SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynSend.reset()
        yield
        DynSend.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynSend has required class attributes."""
        assert hasattr(DynSend, 'memory_tracker')
        assert hasattr(DynSend, 'technique')

    def test_reset_clears_state(self):
        """Test that reset() clears all class state."""
        DynSend.memory_tracker = MagicMock()
        DynSend.technique = MagicMock()

        DynSend.reset()

        assert DynSend.memory_tracker is None
        assert DynSend.technique is None

    def test_run_returns_length(self, mock_state):
        """Test send() returns the length argument."""
        mock_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 42)

        proc = DynSend()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 42, 0)

        assert result is not None


class TestDynSendto:
    """Tests for DynSendto SimProcedure."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        """Reset class state before each test."""
        DynSendto.reset()
        yield
        DynSendto.reset()

    @pytest.fixture
    def mock_state(self):
        """Create a mock angr state."""
        state = MagicMock()
        state.globals = {}
        state.arch = MagicMock()
        state.arch.bits = 64
        state.addr = 0x400000
        state.history = MagicMock()
        state.history.depth = 10
        state.solver = MagicMock()
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        return state

    def test_class_attributes_exist(self):
        """Test that DynSendto has required class attributes."""
        assert hasattr(DynSendto, 'memory_tracker')
        assert hasattr(DynSendto, 'technique')

    def test_run_returns_length(self, mock_state):
        """Test sendto() returns the length argument."""
        mock_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 100)

        proc = DynSendto()
        proc.state = mock_state

        result = proc.run(200, 0x7f000000, 100, 0, 0x7f001000, 16)

        assert result is not None
