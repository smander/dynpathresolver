"""Tests for clone() and clone3() syscall SimProcedures."""

import pytest
from unittest.mock import MagicMock


class TestDynClone:
    """Test cases for DynClone SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone
        DynClone.reset()
        yield
        DynClone.reset()

    def test_basic_clone(self):
        """Test basic clone operation."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynClone()
        proc.state = state

        # Basic clone with no special flags
        result = proc.run(0, 0, 0, 0, 0)

        # Should return child PID
        assert result is not None

    def test_clone_vm(self):
        """Test clone with CLONE_VM (memory sharing)."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone, CLONE_VM
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)
        DynClone.process_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 5

        proc = DynClone()
        proc.state = state

        # Clone with CLONE_VM
        result = proc.run(CLONE_VM, 0x7fff0000, 0, 0, 0)

        # Tracker should record memory-sharing clone
        assert tracker.total_clones == 1
        vm_clones = tracker.get_memory_sharing_clones()
        assert len(vm_clones) == 1
        assert vm_clones[0].shares_memory

    def test_clone_thread(self):
        """Test clone with CLONE_THREAD (thread creation)."""
        from dynpathresolver.simprocedures.syscalls.clone import (
            DynClone, CLONE_VM, CLONE_THREAD
        )
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)
        DynClone.process_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 3

        proc = DynClone()
        proc.state = state

        # Clone as thread (CLONE_VM | CLONE_THREAD)
        result = proc.run(CLONE_VM | CLONE_THREAD, 0x7fff0000, 0, 0, 0)

        clones = tracker.cloned_processes
        assert len(clones) == 1
        assert clones[0].is_thread
        assert clones[0].shares_memory

    def test_clone_technique_notification(self):
        """Test clone notifies technique about CLONE_VM."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone, CLONE_VM

        technique = MagicMock()
        technique._record_clone_vm = MagicMock()

        DynClone.technique = technique

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        proc = DynClone()
        proc.state = state

        # Clone with CLONE_VM
        proc.run(CLONE_VM, 0, 0, 0, 0)

        # Technique should be notified
        technique._record_clone_vm.assert_called_once()

    def test_clone_pid_allocation(self):
        """Test that clone allocates unique PIDs."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone

        # Test the internal PID allocation directly
        initial_pid = DynClone._next_pid

        pid1 = DynClone._allocate_pid()
        pid2 = DynClone._allocate_pid()
        pid3 = DynClone._allocate_pid()

        # PIDs should be sequential and unique
        assert pid1 == initial_pid
        assert pid2 == initial_pid + 1
        assert pid3 == initial_pid + 2
        assert pid1 != pid2
        assert pid2 != pid3


class TestDynClone3:
    """Test cases for DynClone3 SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone3
        DynClone3.reset()
        yield
        DynClone3.reset()

    def test_basic_clone3(self):
        """Test basic clone3 operation."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone3

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64

        # Mock clone_args structure read
        def mem_side_effect(addr):
            mock_mem = MagicMock()
            mock_mem.uint64_t.concrete = 0  # flags = 0
            return mock_mem

        state.mem.__getitem__ = MagicMock(side_effect=mem_side_effect)

        proc = DynClone3()
        proc.state = state

        result = proc.run(0x1000, 88)  # clone_args ptr and size

        assert result is not None

    def test_clone3_with_clone_vm(self):
        """Test clone3 with CLONE_VM flag."""
        from dynpathresolver.simprocedures.syscalls.clone import DynClone3, CLONE_VM
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)
        DynClone3.process_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.arch.bits = 64
        state.addr = 0x400000
        state.history.depth = 3

        # Mock clone_args structure with CLONE_VM
        def mem_side_effect(addr):
            mock_mem = MagicMock()
            if addr == 0x1000:  # flags at offset 0
                mock_mem.uint64_t.concrete = CLONE_VM
            elif addr == 0x1028:  # stack at offset 40
                mock_mem.uint64_t.concrete = 0x7fff0000
            else:
                mock_mem.uint64_t.concrete = 0
            return mock_mem

        state.mem.__getitem__ = MagicMock(side_effect=mem_side_effect)

        proc = DynClone3()
        proc.state = state

        result = proc.run(0x1000, 88)

        # Should record CLONE_VM
        assert tracker.total_clones == 1
        vm_clones = tracker.get_memory_sharing_clones()
        assert len(vm_clones) == 1


class TestClonedProcess:
    """Test ClonedProcess dataclass."""

    def test_shares_memory(self):
        """Test shares_memory property."""
        from dynpathresolver.tracking.process_tracker import ClonedProcess
        from dynpathresolver.simprocedures.syscalls.clone import CLONE_VM

        # With CLONE_VM
        proc1 = ClonedProcess(flags=CLONE_VM)
        assert proc1.shares_memory

        # Without CLONE_VM
        proc2 = ClonedProcess(flags=0)
        assert not proc2.shares_memory

    def test_is_thread(self):
        """Test is_thread property."""
        from dynpathresolver.tracking.process_tracker import ClonedProcess
        from dynpathresolver.simprocedures.syscalls.clone import CLONE_VM, CLONE_THREAD

        # Thread (CLONE_THREAD)
        proc1 = ClonedProcess(flags=CLONE_VM | CLONE_THREAD)
        assert proc1.is_thread

        # Not a thread
        proc2 = ClonedProcess(flags=CLONE_VM)
        assert not proc2.is_thread


class TestProcessTrackerClone:
    """Test ProcessExecutionTracker clone recording."""

    def test_record_clone(self):
        """Test recording clone."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker
        from dynpathresolver.simprocedures.syscalls.clone import CLONE_VM

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 3

        process = tracker.record_clone(
            state,
            flags=CLONE_VM,
            stack=0x7fff0000,
            clone_type="clone",
        )

        assert tracker.total_clones == 1
        assert process.flags == CLONE_VM
        assert process.stack_addr == 0x7fff0000
        assert process.shares_memory

    def test_get_memory_sharing_clones(self):
        """Test filtering memory-sharing clones."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker
        from dynpathresolver.simprocedures.syscalls.clone import CLONE_VM

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        # Clone with CLONE_VM
        tracker.record_clone(state, flags=CLONE_VM)
        # Clone without CLONE_VM (fork-like)
        tracker.record_clone(state, flags=0)

        vm_clones = tracker.get_memory_sharing_clones()

        assert len(vm_clones) == 1
        assert vm_clones[0].shares_memory
