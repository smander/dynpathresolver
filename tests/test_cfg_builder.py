"""Tests for CompleteCFGBuilder."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import tempfile
import os


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_edge_types_exist(self):
        """Test all edge types are defined."""
        from dynpathresolver.core.cfg_builder import EdgeType

        assert EdgeType.DIRECT_JUMP
        assert EdgeType.DIRECT_CALL
        assert EdgeType.CONDITIONAL_TRUE
        assert EdgeType.CONDITIONAL_FALSE
        assert EdgeType.INDIRECT_JUMP
        assert EdgeType.INDIRECT_CALL
        assert EdgeType.RETURN
        assert EdgeType.FALLTHROUGH
        assert EdgeType.SYSCALL
        assert EdgeType.DYNAMIC_LOAD
        assert EdgeType.VTABLE_CALL
        assert EdgeType.PLT_STUB


class TestRegisterState:
    """Tests for RegisterState dataclass."""

    def test_creation_defaults(self):
        """Test RegisterState with default values."""
        from dynpathresolver.core.cfg_builder import RegisterState

        state = RegisterState()
        assert state.registers == {}
        assert state.flags == {}
        assert state.symbolic_regs == []
        assert state.arch == "unknown"

    def test_creation_with_values(self):
        """Test RegisterState with explicit values."""
        from dynpathresolver.core.cfg_builder import RegisterState

        state = RegisterState(
            registers={'rax': 0x1234, 'rbx': 0x5678},
            flags={'zf': True, 'cf': False},
            arch='AMD64',
        )
        assert state.registers['rax'] == 0x1234
        assert state.registers['rbx'] == 0x5678
        assert state.flags['zf'] is True
        assert state.flags['cf'] is False

    def test_to_dict(self):
        """Test RegisterState serialization."""
        from dynpathresolver.core.cfg_builder import RegisterState

        state = RegisterState(
            registers={'rax': 0x1234},
            flags={'zf': True},
            arch='AMD64',
            pc=0x401000,
            sp=0x7fff0000,
        )
        d = state.to_dict()

        assert 'registers' in d
        assert 'flags' in d
        assert 'arch' in d
        assert d['registers']['rax'] == '0x1234'
        assert d['flags']['zf'] is True
        assert d['pc'] == '0x401000'

    def test_from_state_mock_x86(self):
        """Test RegisterState.from_state with mock angr x86_64 state."""
        from dynpathresolver.core.cfg_builder import RegisterState

        # Create mock state for x86_64
        mock_state = MagicMock()
        mock_state.arch.name = 'AMD64'
        mock_state.solver.symbolic.return_value = False
        mock_state.solver.eval.return_value = 0x1234

        # Mock register access
        mock_reg = MagicMock()
        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'rip', 'rflags']:
            setattr(mock_state.regs, reg, mock_reg)

        reg_state = RegisterState.from_state(mock_state)
        assert reg_state.arch == 'AMD64'
        assert reg_state.registers.get('rax') == 0x1234

    def test_from_state_mock_arm64(self):
        """Test RegisterState.from_state with mock angr ARM64 state."""
        from dynpathresolver.core.cfg_builder import RegisterState

        # Create mock state for ARM64
        mock_state = MagicMock()
        mock_state.arch.name = 'AARCH64'
        mock_state.solver.symbolic.return_value = False
        mock_state.solver.eval.return_value = 0x5678

        # Mock register access for ARM64
        mock_reg = MagicMock()
        for i in range(31):
            setattr(mock_state.regs, f'x{i}', mock_reg)
        mock_state.regs.sp = mock_reg
        mock_state.regs.pc = mock_reg
        mock_state.regs.lr = mock_reg

        reg_state = RegisterState.from_state(mock_state)
        assert reg_state.arch == 'AARCH64'
        assert reg_state.registers.get('x0') == 0x5678
        assert reg_state.pc == 0x5678


class TestInstruction:
    """Tests for Instruction dataclass."""

    def test_creation(self):
        """Test Instruction creation."""
        from dynpathresolver.core.cfg_builder import Instruction

        instr = Instruction(
            addr=0x401000,
            size=5,
            mnemonic='mov',
            op_str='rax, rbx',
            bytes=b'\x48\x89\xd8',
        )

        assert instr.addr == 0x401000
        assert instr.size == 5
        assert instr.mnemonic == 'mov'
        assert instr.op_str == 'rax, rbx'

    def test_str(self):
        """Test Instruction string representation."""
        from dynpathresolver.core.cfg_builder import Instruction

        instr = Instruction(
            addr=0x401000,
            size=3,
            mnemonic='nop',
            op_str='',
            bytes=b'\x90',
        )

        assert '0x401000' in str(instr)
        assert 'nop' in str(instr)


class TestCompleteCFGNode:
    """Tests for CompleteCFGNode dataclass."""

    def test_creation_defaults(self):
        """Test CompleteCFGNode with defaults."""
        from dynpathresolver.core.cfg_builder import CompleteCFGNode

        node = CompleteCFGNode(addr=0x401000, size=10)

        assert node.addr == 0x401000
        assert node.size == 10
        assert node.instructions == []
        assert node.exit_states == []
        assert node.is_entry is False

    def test_creation_with_values(self):
        """Test CompleteCFGNode with all values."""
        from dynpathresolver.core.cfg_builder import CompleteCFGNode, Instruction

        instr = Instruction(0x401000, 3, 'nop', '', b'\x90')
        node = CompleteCFGNode(
            addr=0x401000,
            size=10,
            instructions=[instr],
            function_addr=0x401000,
            function_name='main',
            is_entry=True,
        )

        assert node.function_name == 'main'
        assert len(node.instructions) == 1
        assert node.is_entry is True

    def test_to_dict(self):
        """Test CompleteCFGNode serialization."""
        from dynpathresolver.core.cfg_builder import CompleteCFGNode

        node = CompleteCFGNode(
            addr=0x401000,
            size=10,
            function_name='main',
            is_entry=True,
        )

        d = node.to_dict()
        assert d['addr'] == 0x401000
        assert d['function_name'] == 'main'
        assert d['is_entry'] is True


class TestCompleteCFGEdge:
    """Tests for CompleteCFGEdge dataclass."""

    def test_creation(self):
        """Test CompleteCFGEdge creation."""
        from dynpathresolver.core.cfg_builder import CompleteCFGEdge, EdgeType

        edge = CompleteCFGEdge(
            src_addr=0x401000,
            dst_addr=0x401010,
            edge_type=EdgeType.DIRECT_JUMP,
        )

        assert edge.src_addr == 0x401000
        assert edge.dst_addr == 0x401010
        assert edge.edge_type == EdgeType.DIRECT_JUMP
        assert edge.confidence == 1.0

    def test_creation_dynamic(self):
        """Test CompleteCFGEdge for dynamic edge."""
        from dynpathresolver.core.cfg_builder import CompleteCFGEdge, EdgeType

        edge = CompleteCFGEdge(
            src_addr=0x401000,
            dst_addr=0x7fff00000000,
            edge_type=EdgeType.DYNAMIC_LOAD,
            library_loaded='libplugin.so',
            resolution_method='DynPathResolver',
        )

        assert edge.edge_type == EdgeType.DYNAMIC_LOAD
        assert edge.library_loaded == 'libplugin.so'

    def test_to_dict(self):
        """Test CompleteCFGEdge serialization."""
        from dynpathresolver.core.cfg_builder import CompleteCFGEdge, EdgeType

        edge = CompleteCFGEdge(
            src_addr=0x401000,
            dst_addr=0x401010,
            edge_type=EdgeType.CONDITIONAL_TRUE,
            condition='ZF == 1',
        )

        d = edge.to_dict()
        assert d['src_addr'] == 0x401000
        assert d['edge_type'] == 'CONDITIONAL_TRUE'
        assert d['condition'] == 'ZF == 1'


class TestCompleteCFG:
    """Tests for CompleteCFG dataclass."""

    def test_creation_empty(self):
        """Test empty CompleteCFG."""
        from dynpathresolver.core.cfg_builder import CompleteCFG

        cfg = CompleteCFG()

        assert cfg.nodes == {}
        assert cfg.edges == []
        assert cfg.total_basic_blocks == 0

    def test_add_node(self):
        """Test adding nodes to CFG."""
        from dynpathresolver.core.cfg_builder import CompleteCFG, CompleteCFGNode

        cfg = CompleteCFG()
        node = CompleteCFGNode(addr=0x401000, size=10)

        cfg.add_node(node)

        assert 0x401000 in cfg.nodes
        assert cfg.total_basic_blocks == 1

    def test_add_edge(self):
        """Test adding edges to CFG."""
        from dynpathresolver.core.cfg_builder import CompleteCFG, CompleteCFGEdge, EdgeType

        cfg = CompleteCFG()
        edge = CompleteCFGEdge(0x401000, 0x401010, EdgeType.DIRECT_JUMP)

        cfg.add_edge(edge)

        assert len(cfg.edges) == 1
        assert cfg.static_edges == 1
        assert cfg.dynamic_edges == 0

    def test_add_dynamic_edge(self):
        """Test adding dynamic edge to CFG."""
        from dynpathresolver.core.cfg_builder import CompleteCFG, CompleteCFGEdge, EdgeType

        cfg = CompleteCFG()
        edge = CompleteCFGEdge(0x401000, 0x7fff00000000, EdgeType.DYNAMIC_LOAD)

        cfg.add_edge(edge)

        assert cfg.static_edges == 0
        assert cfg.dynamic_edges == 1

    def test_get_successors(self):
        """Test getting successor nodes."""
        from dynpathresolver.core.cfg_builder import CompleteCFG, CompleteCFGEdge, EdgeType

        cfg = CompleteCFG()
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401010, EdgeType.DIRECT_JUMP))
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401020, EdgeType.CONDITIONAL_TRUE))

        succs = cfg.get_successors(0x401000)
        assert len(succs) == 2
        assert 0x401010 in succs
        assert 0x401020 in succs

    def test_get_predecessors(self):
        """Test getting predecessor nodes."""
        from dynpathresolver.core.cfg_builder import CompleteCFG, CompleteCFGEdge, EdgeType

        cfg = CompleteCFG()
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401020, EdgeType.DIRECT_JUMP))
        cfg.add_edge(CompleteCFGEdge(0x401010, 0x401020, EdgeType.DIRECT_JUMP))

        preds = cfg.get_predecessors(0x401020)
        assert len(preds) == 2
        assert 0x401000 in preds
        assert 0x401010 in preds

    def test_to_dict(self):
        """Test CFG serialization."""
        from dynpathresolver.core.cfg_builder import (
            CompleteCFG, CompleteCFGNode, CompleteCFGEdge, EdgeType
        )

        cfg = CompleteCFG()
        cfg.add_node(CompleteCFGNode(addr=0x401000, size=10))
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401010, EdgeType.DIRECT_JUMP))

        d = cfg.to_dict()
        assert 'nodes' in d
        assert 'edges' in d
        assert 'statistics' in d
        assert d['statistics']['total_basic_blocks'] == 1

    def test_export_json(self):
        """Test exporting CFG to JSON."""
        from dynpathresolver.core.cfg_builder import (
            CompleteCFG, CompleteCFGNode, CompleteCFGEdge, EdgeType
        )

        cfg = CompleteCFG()
        cfg.add_node(CompleteCFGNode(addr=0x401000, size=10))
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401010, EdgeType.DIRECT_JUMP))

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            cfg.export_json(f.name)
            assert os.path.exists(f.name)
            # Read and verify
            import json
            with open(f.name) as rf:
                data = json.load(rf)
                assert 'nodes' in data
            os.unlink(f.name)

    def test_export_dot(self):
        """Test exporting CFG to DOT format."""
        from dynpathresolver.core.cfg_builder import (
            CompleteCFG, CompleteCFGNode, CompleteCFGEdge, EdgeType
        )

        cfg = CompleteCFG()
        cfg.add_node(CompleteCFGNode(addr=0x401000, size=10, function_name='main'))
        cfg.add_node(CompleteCFGNode(addr=0x401010, size=5))
        cfg.add_edge(CompleteCFGEdge(0x401000, 0x401010, EdgeType.DIRECT_JUMP))

        with tempfile.NamedTemporaryFile(suffix='.dot', delete=False) as f:
            cfg.export_dot(f.name)
            assert os.path.exists(f.name)
            # Read and verify
            with open(f.name) as rf:
                content = rf.read()
                assert 'digraph CFG' in content
                assert 'node_401000' in content
            os.unlink(f.name)


class TestCompleteCFGBuilder:
    """Tests for CompleteCFGBuilder class."""

    def test_initialization(self):
        """Test CompleteCFGBuilder initialization."""
        from dynpathresolver.core.cfg_builder import CompleteCFGBuilder

        mock_project = MagicMock()

        builder = CompleteCFGBuilder(
            project=mock_project,
            context_sensitivity_level=2,
            keep_state=True,
        )

        assert builder.project == mock_project
        assert builder.context_sensitivity_level == 2
        assert builder.keep_state is True

    def test_initialization_with_library_paths(self):
        """Test CompleteCFGBuilder with library paths."""
        from dynpathresolver.core.cfg_builder import CompleteCFGBuilder

        mock_project = MagicMock()

        builder = CompleteCFGBuilder(
            project=mock_project,
            library_paths=['/lib', '/usr/lib'],
        )

        assert builder.library_paths == ['/lib', '/usr/lib']

    def test_jumpkind_to_edge_type(self):
        """Test conversion of angr jumpkinds to EdgeType."""
        from dynpathresolver.core.cfg_builder import CompleteCFGBuilder, EdgeType

        mock_project = MagicMock()
        builder = CompleteCFGBuilder(mock_project)

        assert builder._jumpkind_to_edge_type('Ijk_Boring') == EdgeType.FALLTHROUGH
        assert builder._jumpkind_to_edge_type('Ijk_Call') == EdgeType.DIRECT_CALL
        assert builder._jumpkind_to_edge_type('Ijk_Ret') == EdgeType.RETURN
        assert builder._jumpkind_to_edge_type('Ijk_Sys_syscall') == EdgeType.SYSCALL
        assert builder._jumpkind_to_edge_type('Unknown') == EdgeType.DIRECT_JUMP


class TestImports:
    """Test that all exports are importable."""

    def test_import_from_core(self):
        """Test importing from dynpathresolver.core."""
        from dynpathresolver.core import (
            CompleteCFGBuilder,
            CompleteCFG,
            CompleteCFGNode,
            CompleteCFGEdge,
            RegisterState,
            EdgeType,
        )

        assert CompleteCFGBuilder is not None
        assert CompleteCFG is not None
        assert EdgeType is not None

    def test_import_from_root(self):
        """Test importing from dynpathresolver."""
        from dynpathresolver import (
            CompleteCFGBuilder,
            CompleteCFG,
            CompleteCFGNode,
            CompleteCFGEdge,
            RegisterState,
            EdgeType,
        )

        assert CompleteCFGBuilder is not None
        assert CompleteCFG is not None
        assert EdgeType is not None
