"""Tests for init/fini tracking."""

import pytest
from unittest.mock import MagicMock


class TestInitFiniTracker:
    """Test InitFiniTracker class."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker

        project = MagicMock()
        tracker = InitFiniTracker(project)

        assert len(tracker.init_functions) == 0
        assert len(tracker.fini_functions) == 0
        assert len(tracker.executions) == 0

    def test_is_init_function_unknown(self):
        """Test checking unknown address."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker

        project = MagicMock()
        tracker = InitFiniTracker(project)

        assert not tracker.is_init_function(0x401000)

    def test_get_init_function_unknown(self):
        """Test getting unknown init function."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker

        project = MagicMock()
        tracker = InitFiniTracker(project)

        result = tracker.get_init_function(0x401000)
        assert result is None

    def test_record_execution_unknown(self):
        """Test recording execution of unknown address."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker

        project = MagicMock()
        tracker = InitFiniTracker(project)

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1

        result = tracker.record_execution(state, 0x401000)
        assert result is None

    def test_record_execution_known(self):
        """Test recording execution of known init function."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker, InitFunction

        project = MagicMock()
        tracker = InitFiniTracker(project)

        # Add known init function
        init_func = InitFunction(
            addr=0x401000,
            section='.init_array',
            library='libtest.so',
            index=0,
        )
        tracker.init_functions.append(init_func)
        tracker._addr_to_init[0x401000] = init_func

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 5

        result = tracker.record_execution(state, 0x401000)

        assert result is not None
        assert result.function_addr == 0x401000
        assert result.section == '.init_array'
        assert init_func.executed
        assert init_func.executed_at_step == 5

    def test_get_init_functions_filtered(self):
        """Test getting init functions filtered by library."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker, InitFunction

        project = MagicMock()
        tracker = InitFiniTracker(project)

        # Add init functions from different libraries
        tracker.init_functions.append(InitFunction(
            addr=0x401000, section='.init', library='liba.so'
        ))
        tracker.init_functions.append(InitFunction(
            addr=0x402000, section='.init_array', library='libb.so'
        ))
        tracker.init_functions.append(InitFunction(
            addr=0x403000, section='.init_array', library='liba.so'
        ))

        # Filter by library
        liba_funcs = tracker.get_init_functions('liba.so')
        assert len(liba_funcs) == 2

        libb_funcs = tracker.get_init_functions('libb.so')
        assert len(libb_funcs) == 1

        all_funcs = tracker.get_init_functions()
        assert len(all_funcs) == 3

    def test_get_unexecuted_inits(self):
        """Test getting unexecuted init functions."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker, InitFunction

        project = MagicMock()
        tracker = InitFiniTracker(project)

        # Add init functions
        func1 = InitFunction(addr=0x401000, section='.init', library='lib.so')
        func2 = InitFunction(addr=0x402000, section='.init_array', library='lib.so')
        func3 = InitFunction(addr=0x403000, section='.init_array', library='lib.so')

        tracker.init_functions = [func1, func2, func3]
        tracker._addr_to_init = {
            0x401000: func1,
            0x402000: func2,
            0x403000: func3,
        }

        # Execute one
        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1
        tracker.record_execution(state, 0x401000)

        # Get unexecuted
        unexecuted = tracker.get_unexecuted_inits()
        assert len(unexecuted) == 2
        assert func1 not in unexecuted
        assert func2 in unexecuted
        assert func3 in unexecuted

    def test_get_statistics(self):
        """Test getting statistics."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker, InitFunction

        project = MagicMock()
        tracker = InitFiniTracker(project)

        # Add functions
        func1 = InitFunction(addr=0x401000, section='.init', library='lib.so')
        func2 = InitFunction(addr=0x402000, section='.init_array', library='lib.so')
        fini1 = InitFunction(addr=0x403000, section='.fini', library='lib.so')

        tracker.init_functions = [func1, func2]
        tracker.fini_functions = [fini1]
        tracker._addr_to_init = {
            0x401000: func1,
            0x402000: func2,
            0x403000: fini1,
        }

        # Execute one init
        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1
        tracker.record_execution(state, 0x401000)

        stats = tracker.get_statistics()
        assert stats['total_init_functions'] == 2
        assert stats['total_fini_functions'] == 1
        assert stats['executed_inits'] == 1
        assert stats['executed_finis'] == 0
        assert stats['total_executions'] == 1

    def test_reset(self):
        """Test resetting tracker."""
        from dynpathresolver.tracking.init_tracker import InitFiniTracker, InitFunction

        project = MagicMock()
        tracker = InitFiniTracker(project)

        # Add and execute function
        func1 = InitFunction(addr=0x401000, section='.init', library='lib.so')
        tracker.init_functions = [func1]
        tracker._addr_to_init = {0x401000: func1}

        state = MagicMock()
        state.addr = 0x400000
        state.history.depth = 1
        tracker.record_execution(state, 0x401000)

        assert func1.executed

        tracker.reset()

        # Functions should still exist but be marked unexecuted
        assert len(tracker.init_functions) == 1
        assert not tracker.init_functions[0].executed
        assert len(tracker.executions) == 0


class TestInitFunction:
    """Test InitFunction dataclass."""

    def test_init_function_creation(self):
        """Test creating InitFunction."""
        from dynpathresolver.tracking.init_tracker import InitFunction

        func = InitFunction(
            addr=0x401000,
            section='.init_array',
            library='libtest.so',
            index=2,
        )

        assert func.addr == 0x401000
        assert func.section == '.init_array'
        assert func.library == 'libtest.so'
        assert func.index == 2
        assert not func.executed
        assert func.executed_at_step is None

    def test_init_function_sections(self):
        """Test different section types."""
        from dynpathresolver.tracking.init_tracker import InitFunction

        # Test all section types
        sections = ['.init', '.fini', '.init_array', '.fini_array', '.preinit_array']

        for section in sections:
            func = InitFunction(
                addr=0x401000,
                section=section,
                library='lib.so',
            )
            assert func.section == section


class TestInitExecution:
    """Test InitExecution dataclass."""

    def test_init_execution_creation(self):
        """Test creating InitExecution."""
        from dynpathresolver.tracking.init_tracker import InitExecution

        execution = InitExecution(
            function_addr=0x401000,
            section='.init_array',
            library='libtest.so',
            state_addr=0x400000,
            step=10,
        )

        assert execution.function_addr == 0x401000
        assert execution.section == '.init_array'
        assert execution.library == 'libtest.so'
        assert execution.state_addr == 0x400000
        assert execution.step == 10
