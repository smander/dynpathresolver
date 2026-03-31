"""Tests for extended dynamic loading SimProcedures."""

import pytest


class TestDlmopen:
    """Tests for dlmopen SimProcedure."""

    def test_dlmopen_imports(self):
        """Test that DynDlmopen can be imported."""
        from dynpathresolver.simprocedures.dlmopen import DynDlmopen, LM_ID_BASE, LM_ID_NEWLM
        assert DynDlmopen is not None
        assert LM_ID_BASE == 0
        assert LM_ID_NEWLM == -1

    def test_dlmopen_has_namespaces(self):
        """Test that DynDlmopen tracks namespaces."""
        from dynpathresolver.simprocedures.dlmopen import DynDlmopen
        assert hasattr(DynDlmopen, 'namespaces')
        assert isinstance(DynDlmopen.namespaces, dict)

    def test_dlmopen_create_namespace(self):
        """Test namespace creation."""
        from unittest.mock import MagicMock
        from dynpathresolver.simprocedures.dlmopen import DynDlmopen, LM_ID_BASE
        DynDlmopen.reset()

        # _create_namespace is an instance method that uses state.globals
        proc = DynDlmopen()
        state = MagicMock()
        state.globals = {}
        proc.state = state

        ns_id = proc._create_namespace()
        assert ns_id > 0
        namespaces = state.globals.get('dpr_dlmopen_namespaces', DynDlmopen.namespaces)
        assert ns_id in namespaces

    def test_dlmopen_get_namespace(self):
        """Test getting namespace for a handle."""
        from dynpathresolver.simprocedures.dlmopen import DynDlmopen, LM_ID_BASE
        DynDlmopen.reset()

        # Add handle to base namespace
        test_handle = 0x1000
        DynDlmopen.namespaces[LM_ID_BASE].append(test_handle)

        assert DynDlmopen.get_namespace(test_handle) == LM_ID_BASE
        assert DynDlmopen.get_namespace(0xDEAD) is None

    def test_dlmopen_reset(self):
        """Test reset clears state."""
        from unittest.mock import MagicMock
        from dynpathresolver.simprocedures.dlmopen import DynDlmopen, LM_ID_BASE

        # _create_namespace is an instance method that uses state.globals
        proc = DynDlmopen()
        state = MagicMock()
        state.globals = {}
        proc.state = state

        proc._create_namespace()
        proc._create_namespace()

        DynDlmopen.reset()
        assert len(DynDlmopen.namespaces) == 1
        assert LM_ID_BASE in DynDlmopen.namespaces


class TestDlerror:
    """Tests for dlerror SimProcedure."""

    def test_dlerror_imports(self):
        """Test that DynDlerror can be imported."""
        from dynpathresolver.simprocedures.dlerror import DynDlerror, DlError
        assert DynDlerror is not None
        assert DlError is not None

    def test_dlerror_set_get_error(self):
        """Test setting and getting errors."""
        from dynpathresolver.simprocedures.dlerror import DlError
        DlError.reset()

        assert DlError.get_error() is None

        DlError.set_error("test error")
        assert DlError.has_error()
        assert DlError.get_error() == "test error"
        assert not DlError.has_error()  # Should be cleared after get

    def test_dlerror_reset(self):
        """Test reset clears error state."""
        from dynpathresolver.simprocedures.dlerror import DlError
        DlError.set_error("test error")
        DlError.reset()
        assert not DlError.has_error()


class TestDlvsym:
    """Tests for dlvsym SimProcedure."""

    def test_dlvsym_imports(self):
        """Test that DynDlvsym can be imported."""
        from dynpathresolver.simprocedures.dlvsym import DynDlvsym
        assert DynDlvsym is not None

    def test_dlvsym_has_resolved_symbols(self):
        """Test that DynDlvsym tracks versioned symbol resolutions."""
        from dynpathresolver.simprocedures.dlvsym import DynDlvsym
        assert hasattr(DynDlvsym, 'resolved_versioned_symbols')
        assert isinstance(DynDlvsym.resolved_versioned_symbols, dict)

    def test_dlvsym_reset(self):
        """Test reset clears state."""
        from dynpathresolver.simprocedures.dlvsym import DynDlvsym
        DynDlvsym.resolved_versioned_symbols[(0x1000, "test", "1.0")] = 0x2000
        DynDlvsym.reset()
        assert len(DynDlvsym.resolved_versioned_symbols) == 0


class TestDladdr:
    """Tests for dladdr SimProcedure."""

    def test_dladdr_imports(self):
        """Test that DynDladdr can be imported."""
        from dynpathresolver.simprocedures.dladdr import DynDladdr, DlInfoOffsets
        assert DynDladdr is not None
        assert DlInfoOffsets is not None

    def test_dlinfo_offsets_64bit(self):
        """Test Dl_info offsets for 64-bit."""
        from dynpathresolver.simprocedures.dladdr import DlInfoOffsets
        offsets = DlInfoOffsets.get_offsets(64)
        assert offsets['dli_fname'] == 0
        assert offsets['dli_fbase'] == 8
        assert offsets['dli_sname'] == 16
        assert offsets['dli_saddr'] == 24

    def test_dlinfo_offsets_32bit(self):
        """Test Dl_info offsets for 32-bit."""
        from dynpathresolver.simprocedures.dladdr import DlInfoOffsets
        offsets = DlInfoOffsets.get_offsets(32)
        assert offsets['dli_fname'] == 0
        assert offsets['dli_fbase'] == 4
        assert offsets['dli_sname'] == 8
        assert offsets['dli_saddr'] == 12

    def test_dladdr_reset(self):
        """Test reset clears state."""
        from dynpathresolver.simprocedures.dladdr import DynDladdr
        DynDladdr._string_cache["test"] = 0x1000
        DynDladdr.reset()
        assert len(DynDladdr._string_cache) == 0


class TestDlinfo:
    """Tests for dlinfo SimProcedure."""

    def test_dlinfo_imports(self):
        """Test that DynDlinfo can be imported."""
        from dynpathresolver.simprocedures.dlinfo import (
            DynDlinfo,
            RTLD_DI_LMID,
            RTLD_DI_LINKMAP,
            RTLD_DI_ORIGIN,
        )
        assert DynDlinfo is not None
        assert RTLD_DI_LMID == 1
        assert RTLD_DI_LINKMAP == 2
        assert RTLD_DI_ORIGIN == 6

    def test_dlinfo_has_link_maps(self):
        """Test that DynDlinfo tracks link maps."""
        from dynpathresolver.simprocedures.dlinfo import DynDlinfo
        assert hasattr(DynDlinfo, '_link_maps')
        assert isinstance(DynDlinfo._link_maps, dict)

    def test_dlinfo_reset(self):
        """Test reset clears state."""
        from dynpathresolver.simprocedures.dlinfo import DynDlinfo
        DynDlinfo._link_maps[0x1000] = {'addr': 0x2000}
        DynDlinfo.reset()
        assert len(DynDlinfo._link_maps) == 0


class TestTLS:
    """Tests for TLS support."""

    def test_tls_imports(self):
        """Test that TLS support can be imported."""
        from dynpathresolver.simprocedures.tls import (
            TLSManager,
            DynTlsGetAddr,
            DynTlsDescResolver,
        )
        assert TLSManager is not None
        assert DynTlsGetAddr is not None
        assert DynTlsDescResolver is not None

    def test_tls_manager_register_module(self):
        """Test registering a TLS module."""
        from dynpathresolver.simprocedures.tls import TLSManager
        TLSManager.reset()

        # Create a mock library object
        class MockLib:
            tls_block_size = 0x100

        module_id = TLSManager.register_module(MockLib())
        assert module_id > 0
        assert module_id in TLSManager._tls_blocks

    def test_tls_manager_get_address(self):
        """Test getting TLS address."""
        from dynpathresolver.simprocedures.tls import TLSManager
        TLSManager.reset()

        class MockLib:
            tls_block_size = 0x100

        module_id = TLSManager.register_module(MockLib())
        addr = TLSManager.get_address(module_id, 0x10)
        assert addr is not None
        assert addr > 0

    def test_tls_manager_get_address_unknown_module(self):
        """Test getting TLS address for unknown module."""
        from dynpathresolver.simprocedures.tls import TLSManager
        TLSManager.reset()

        addr = TLSManager.get_address(999, 0)
        assert addr is None

    def test_tls_manager_reset(self):
        """Test reset clears TLS state."""
        from dynpathresolver.simprocedures.tls import TLSManager
        TLSManager._tls_blocks[1] = (0x1000, 0x100)
        TLSManager.reset()
        assert len(TLSManager._tls_blocks) == 0


class TestRelocation:
    """Tests for relocation processing."""

    def test_relocation_imports(self):
        """Test that relocation module can be imported."""
        from dynpathresolver.elf.relocation import (
            X86_64_Reloc,
            X86_Reloc,
            GOTEntry,
            PLTEntry,
            RelocationEntry,
            GOTTracker,
            RelocationProcessor,
            LazyBindingSimulator,
        )
        assert X86_64_Reloc is not None
        assert X86_Reloc is not None
        assert GOTEntry is not None
        assert PLTEntry is not None

    def test_x86_64_reloc_values(self):
        """Test x86_64 relocation type values."""
        from dynpathresolver.elf.relocation import X86_64_Reloc
        assert X86_64_Reloc.R_X86_64_NONE == 0
        assert X86_64_Reloc.R_X86_64_64 == 1
        assert X86_64_Reloc.R_X86_64_GLOB_DAT == 6
        assert X86_64_Reloc.R_X86_64_JUMP_SLOT == 7
        assert X86_64_Reloc.R_X86_64_RELATIVE == 8

    def test_x86_reloc_values(self):
        """Test x86 relocation type values."""
        from dynpathresolver.elf.relocation import X86_Reloc
        assert X86_Reloc.R_386_NONE == 0
        assert X86_Reloc.R_386_32 == 1
        assert X86_Reloc.R_386_GLOB_DAT == 6
        assert X86_Reloc.R_386_JMP_SLOT == 7
        assert X86_Reloc.R_386_RELATIVE == 8

    def test_got_entry_dataclass(self):
        """Test GOTEntry dataclass."""
        from dynpathresolver.elf.relocation import GOTEntry
        entry = GOTEntry(
            address=0x1000,
            symbol_name="test_func",
            resolved_addr=0x2000,
            is_lazy=True,
        )
        assert entry.address == 0x1000
        assert entry.symbol_name == "test_func"
        assert entry.resolved_addr == 0x2000
        assert entry.is_lazy is True

    def test_plt_entry_dataclass(self):
        """Test PLTEntry dataclass."""
        from dynpathresolver.elf.relocation import PLTEntry
        entry = PLTEntry(
            address=0x1000,
            got_entry=0x2000,
            symbol_name="test_func",
            is_bound=False,
        )
        assert entry.address == 0x1000
        assert entry.got_entry == 0x2000
        assert entry.is_bound is False

    def test_relocation_entry_dataclass(self):
        """Test RelocationEntry dataclass."""
        from dynpathresolver.elf.relocation import RelocationEntry
        entry = RelocationEntry(
            offset=0x1000,
            type=7,  # JUMP_SLOT
            symbol_name="test_func",
            addend=0,
            resolved=False,
        )
        assert entry.offset == 0x1000
        assert entry.type == 7
        assert entry.resolved is False


class TestSimproceduersModule:
    """Tests for the simprocedures module __init__."""

    def test_all_exports(self):
        """Test that all SimProcedures are exported."""
        from dynpathresolver.simprocedures import (
            DynDlopen,
            DynDlsym,
            DynDlclose,
            DynDlmopen,
            DynDlvsym,
            DynDladdr,
            DynDlinfo,
            DynDlerror,
            DlError,
            DynTlsGetAddr,
            DynTlsDescResolver,
            TLSManager,
        )
        assert DynDlopen is not None
        assert DynDlsym is not None
        assert DynDlclose is not None
        assert DynDlmopen is not None
        assert DynDlvsym is not None
        assert DynDladdr is not None
        assert DynDlinfo is not None
        assert DynDlerror is not None
        assert DlError is not None
        assert DynTlsGetAddr is not None
        assert DynTlsDescResolver is not None
        assert TLSManager is not None


class TestTechniqueHooksExtended:
    """Tests for technique.py hooking extended SimProcedures."""

    def test_technique_imports_extended(self):
        """Test that technique imports all extended SimProcedures."""
        from dynpathresolver.core.technique import (
            DynDlmopen,
            DynDlvsym,
            DynDladdr,
            DynDlinfo,
            DynDlerror,
            DynTlsGetAddr,
            DynTlsDescResolver,
        )
        assert DynDlmopen is not None
        assert DynDlvsym is not None
        assert DynDladdr is not None
        assert DynDlinfo is not None
        assert DynDlerror is not None
        assert DynTlsGetAddr is not None
        assert DynTlsDescResolver is not None

    def test_technique_imports_relocation(self):
        """Test that technique imports relocation processing."""
        from dynpathresolver.core.technique import (
            RelocationProcessor,
            GOTTracker,
            LazyBindingSimulator,
        )
        assert RelocationProcessor is not None
        assert GOTTracker is not None
        assert LazyBindingSimulator is not None

    def test_technique_has_relocation_components(self):
        """Test that DynPathResolver has relocation components."""
        from dynpathresolver.core.technique import DynPathResolver
        tech = DynPathResolver()
        assert hasattr(tech, 'relocation_processor')
        assert hasattr(tech, 'got_tracker')
        assert hasattr(tech, 'lazy_binding_sim')
