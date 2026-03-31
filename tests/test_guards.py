"""Tests for guard detection module."""

import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass


def test_guard_type_enum():
    """Test GuardType enum has expected values."""
    from dynpathresolver.detection.guards import GuardType

    assert GuardType.ANTI_DEBUG.value == 'anti_debug'
    assert GuardType.VM_DETECTION.value == 'vm_detection'
    assert GuardType.TIMING_CHECK.value == 'timing_check'
    assert GuardType.ENVIRONMENT_CHECK.value == 'environment_check'


def test_guard_dataclass():
    """Test Guard dataclass has expected fields."""
    from dynpathresolver.detection.guards import Guard, GuardType

    guard = Guard(
        addr=0x401000,
        guard_type=GuardType.ANTI_DEBUG,
        function_name='ptrace',
        bypass_value=0,
    )

    assert guard.addr == 0x401000
    assert guard.guard_type == GuardType.ANTI_DEBUG
    assert guard.function_name == 'ptrace'
    assert guard.bypass_value == 0


def test_guard_detector_init():
    """Test GuardDetector initializes with project."""
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    detector = GuardDetector(mock_project)

    assert detector.project == mock_project


def test_detect_anti_debug_ptrace():
    """Test detection of ptrace anti-debug calls."""
    from dynpathresolver.detection.guards import GuardDetector, GuardType

    mock_project = MagicMock()

    # Mock CFG with a function that calls ptrace
    mock_cfg = MagicMock()

    # Create mock function
    mock_func = MagicMock()
    mock_func.name = 'ptrace'
    mock_func.addr = 0x401000

    # Mock functions using MagicMock
    mock_functions = MagicMock()
    mock_functions.values.return_value = [mock_func]
    mock_functions.__getitem__ = MagicMock(return_value=mock_func)
    mock_cfg.functions = mock_functions

    # Mock project.analyses.CFGFast
    mock_project.analyses.CFGFast.return_value = mock_cfg

    # Mock find_symbol to return a symbol for ptrace
    mock_sym = MagicMock()
    mock_sym.rebased_addr = 0x401000
    mock_sym.name = 'ptrace'
    mock_project.loader.find_symbol.return_value = mock_sym

    detector = GuardDetector(mock_project)
    guards = detector._find_anti_debug_calls()

    # Should find ptrace as anti-debug guard
    ptrace_guards = [g for g in guards if g.function_name == 'ptrace']
    assert len(ptrace_guards) >= 1
    assert ptrace_guards[0].guard_type == GuardType.ANTI_DEBUG
    # ptrace returns 0 on success when bypassed
    assert ptrace_guards[0].bypass_value == 0


def test_detect_vm_cpuid():
    """Test detection of cpuid VM detection instructions."""
    from dynpathresolver.detection.guards import GuardDetector, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG
    mock_cfg = MagicMock()

    # Create mock basic block with cpuid instruction
    mock_block = MagicMock()

    # Create mock instruction
    mock_insn = MagicMock()
    mock_insn.mnemonic = 'cpuid'
    mock_insn.address = 0x402000

    mock_block.capstone.insns = [mock_insn]
    mock_block.addr = 0x402000

    # Mock function containing the block
    mock_func = MagicMock()
    mock_func.blocks = [mock_block]
    mock_func.addr = 0x402000

    # Mock functions using MagicMock
    mock_functions = MagicMock()
    mock_functions.values.return_value = [mock_func]
    mock_cfg.functions = mock_functions

    mock_project.analyses.CFGFast.return_value = mock_cfg

    detector = GuardDetector(mock_project)
    guards = detector._find_vm_detection()

    # Should find cpuid as VM detection
    cpuid_guards = [g for g in guards if g.function_name == 'cpuid']
    assert len(cpuid_guards) >= 1
    assert cpuid_guards[0].guard_type == GuardType.VM_DETECTION


def test_detect_timing_checks():
    """Test detection of timing check calls."""
    from dynpathresolver.detection.guards import GuardDetector, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG
    mock_cfg = MagicMock()

    # Create mock function for gettimeofday
    mock_func = MagicMock()
    mock_func.name = 'gettimeofday'
    mock_func.addr = 0x403000

    # Mock functions using MagicMock
    mock_functions = MagicMock()
    mock_functions.values.return_value = [mock_func]
    mock_cfg.functions = mock_functions

    mock_project.analyses.CFGFast.return_value = mock_cfg

    # Mock find_symbol
    mock_sym = MagicMock()
    mock_sym.rebased_addr = 0x403000
    mock_sym.name = 'gettimeofday'
    mock_project.loader.find_symbol.return_value = mock_sym

    detector = GuardDetector(mock_project)
    guards = detector._find_timing_checks()

    # Should find gettimeofday as timing check
    timing_guards = [g for g in guards if g.function_name == 'gettimeofday']
    assert len(timing_guards) >= 1
    assert timing_guards[0].guard_type == GuardType.TIMING_CHECK


def test_detect_guards_comprehensive():
    """Test detect_guards returns all guard types."""
    from dynpathresolver.detection.guards import GuardDetector, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG with empty functions
    mock_cfg = MagicMock()
    mock_functions = MagicMock()
    mock_functions.values.return_value = []
    mock_cfg.functions = mock_functions

    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_project.loader.find_symbol.return_value = None

    detector = GuardDetector(mock_project)

    # Patch internal methods to return known guards
    with patch.object(detector, '_find_anti_debug_calls') as mock_anti_debug, \
         patch.object(detector, '_find_vm_detection') as mock_vm, \
         patch.object(detector, '_find_timing_checks') as mock_timing, \
         patch.object(detector, '_find_environment_checks') as mock_env:

        from dynpathresolver.detection.guards import Guard

        mock_anti_debug.return_value = [
            Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0)
        ]
        mock_vm.return_value = [
            Guard(0x402000, GuardType.VM_DETECTION, 'cpuid', 0)
        ]
        mock_timing.return_value = [
            Guard(0x403000, GuardType.TIMING_CHECK, 'rdtsc', 0)
        ]
        mock_env.return_value = [
            Guard(0x404000, GuardType.ENVIRONMENT_CHECK, 'getenv', 0)
        ]

        guards = detector.detect_guards()

        assert len(guards) == 4
        guard_types = {g.guard_type for g in guards}
        assert GuardType.ANTI_DEBUG in guard_types
        assert GuardType.VM_DETECTION in guard_types
        assert GuardType.TIMING_CHECK in guard_types
        assert GuardType.ENVIRONMENT_CHECK in guard_types


def test_guard_patcher_init():
    """Test GuardPatcher initializes with project."""
    from dynpathresolver.detection.guards import GuardPatcher

    mock_project = MagicMock()
    patcher = GuardPatcher(mock_project)

    assert patcher.project == mock_project


def test_guard_patcher_generate_patch():
    """Test GuardPatcher generates correct patch bytes."""
    from dynpathresolver.detection.guards import GuardPatcher, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'
    mock_project.arch.bytes = 8

    patcher = GuardPatcher(mock_project)

    guard = Guard(
        addr=0x401000,
        guard_type=GuardType.ANTI_DEBUG,
        function_name='ptrace',
        bypass_value=0,
    )

    patch_bytes = patcher.generate_patch(guard)

    # Should return bytes that set return value to bypass_value
    assert isinstance(patch_bytes, bytes)
    assert len(patch_bytes) > 0


def test_guard_patcher_ld_preload():
    """Test GuardPatcher generates LD_PRELOAD C code."""
    from dynpathresolver.detection.guards import GuardPatcher, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    patcher = GuardPatcher(mock_project)

    guards = [
        Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0),
        Guard(0x402000, GuardType.TIMING_CHECK, 'gettimeofday', 0),
    ]

    c_code = patcher.generate_ld_preload(guards)

    # Should contain function definitions for each guard
    assert 'ptrace' in c_code
    assert 'gettimeofday' in c_code
    # Should be valid C code with includes
    assert '#include' in c_code or '#define' in c_code


def test_guard_patcher_apply_patches(tmp_path):
    """Test GuardPatcher applies patches to binary."""
    from dynpathresolver.detection.guards import GuardPatcher, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'
    mock_project.arch.bytes = 8

    patcher = GuardPatcher(mock_project)

    # Create a minimal ELF binary with proper headers
    # ELF64 header + one PT_LOAD segment covering address 0x1000 at file offset 0x1000
    import struct

    elf_header = bytearray(64)
    elf_header[0:4] = b'\x7fELF'  # Magic
    elf_header[4] = 2  # 64-bit
    elf_header[5] = 1  # Little endian
    elf_header[6] = 1  # ELF version
    struct.pack_into('<H', elf_header, 16, 2)  # e_type = ET_EXEC
    struct.pack_into('<H', elf_header, 18, 0x3e)  # e_machine = x86_64
    struct.pack_into('<Q', elf_header, 32, 64)  # e_phoff = 64 (right after header)
    struct.pack_into('<H', elf_header, 52, 64)  # e_ehsize
    struct.pack_into('<H', elf_header, 54, 56)  # e_phentsize
    struct.pack_into('<H', elf_header, 56, 1)  # e_phnum = 1

    # Program header (PT_LOAD)
    ph = bytearray(56)
    struct.pack_into('<I', ph, 0, 1)  # p_type = PT_LOAD
    struct.pack_into('<Q', ph, 8, 0x1000)  # p_offset (file offset)
    struct.pack_into('<Q', ph, 16, 0x1000)  # p_vaddr (virtual address)
    struct.pack_into('<Q', ph, 32, 0x1000)  # p_filesz
    struct.pack_into('<Q', ph, 40, 0x1000)  # p_memsz

    # Combine header + program header + padding + data
    binary_data = elf_header + ph + (b'\x00' * (0x1000 - 64 - 56)) + (b'\x00' * 0x1000)

    input_binary = tmp_path / "input_binary"
    input_binary.write_bytes(binary_data)

    output_binary = tmp_path / "output_binary"

    # Guard at virtual address 0x1100 (in the PT_LOAD segment)
    guards = [
        Guard(0x1100, GuardType.ANTI_DEBUG, 'ptrace', 0),
    ]

    result = patcher.apply_patches(str(input_binary), guards, str(output_binary))

    # Should create output file
    assert output_binary.exists()
    assert result is True


def test_get_guards_on_path():
    """Test identifying guards on a specific execution path."""
    from dynpathresolver.detection.guards import GuardDetector, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG
    mock_cfg = MagicMock()
    mock_functions = MagicMock()
    mock_functions.values.return_value = []
    mock_cfg.functions = mock_functions
    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_project.loader.find_symbol.return_value = None

    detector = GuardDetector(mock_project)

    # Set up known guards
    detector._guards = [
        Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0),
        Guard(0x402000, GuardType.VM_DETECTION, 'cpuid', 0),
        Guard(0x403000, GuardType.TIMING_CHECK, 'rdtsc', 0),
    ]

    # Test with a list of addresses directly (new supported input type)
    path_addrs = [0x400000, 0x401000, 0x401100, 0x403000, 0x404000]

    guards_on_path = detector.get_guards_on_path(path_addrs)

    # Should only return guards that are on the path
    assert len(guards_on_path) == 2
    addrs_on_path = {g.addr for g in guards_on_path}
    assert 0x401000 in addrs_on_path
    assert 0x403000 in addrs_on_path
    assert 0x402000 not in addrs_on_path


def test_get_guards_on_path_with_state_history():
    """Test identifying guards using angr state with history."""
    from dynpathresolver.detection.guards import GuardDetector, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG
    mock_cfg = MagicMock()
    mock_functions = MagicMock()
    mock_functions.values.return_value = []
    mock_cfg.functions = mock_functions
    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_project.loader.find_symbol.return_value = None

    detector = GuardDetector(mock_project)

    # Set up known guards
    detector._guards = [
        Guard(0x401000, GuardType.ANTI_DEBUG, 'ptrace', 0),
        Guard(0x402000, GuardType.VM_DETECTION, 'cpuid', 0),
    ]

    # Create a simple object that has history.bbl_addrs but no path_constraints
    class MockState:
        class History:
            bbl_addrs = [0x400000, 0x401000, 0x401100]
        history = History()

    mock_state = MockState()

    # Explicitly remove path_constraints if it exists (from MagicMock)
    del_attrs = ['path_constraints']
    for attr in del_attrs:
        if hasattr(mock_state, attr):
            delattr(mock_state, attr)

    guards_on_path = detector.get_guards_on_path(mock_state)

    # Should find the guard at 0x401000
    assert len(guards_on_path) == 1
    assert guards_on_path[0].addr == 0x401000


def test_detect_environment_checks():
    """Test detection of environment variable checks."""
    from dynpathresolver.detection.guards import GuardDetector, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'AMD64'

    # Mock CFG
    mock_cfg = MagicMock()

    # Create mock function for getenv
    mock_func = MagicMock()
    mock_func.name = 'getenv'
    mock_func.addr = 0x404000

    # Mock functions using MagicMock
    mock_functions = MagicMock()
    mock_functions.values.return_value = [mock_func]
    mock_cfg.functions = mock_functions

    mock_project.analyses.CFGFast.return_value = mock_cfg

    # Mock find_symbol
    mock_sym = MagicMock()
    mock_sym.rebased_addr = 0x404000
    mock_sym.name = 'getenv'
    mock_project.loader.find_symbol.return_value = mock_sym

    detector = GuardDetector(mock_project)
    guards = detector._find_environment_checks()

    # Should find getenv as environment check
    env_guards = [g for g in guards if g.function_name == 'getenv']
    assert len(env_guards) >= 1
    assert env_guards[0].guard_type == GuardType.ENVIRONMENT_CHECK


def test_guard_detector_caches_cfg():
    """Test that GuardDetector caches CFG analysis."""
    from dynpathresolver.detection.guards import GuardDetector

    mock_project = MagicMock()
    mock_cfg = MagicMock()
    mock_functions = MagicMock()
    mock_functions.values.return_value = []
    mock_cfg.functions = mock_functions

    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_project.loader.find_symbol.return_value = None

    detector = GuardDetector(mock_project)

    # Call detect_guards twice
    detector.detect_guards()
    detector.detect_guards()

    # CFGFast should only be called once (cached)
    assert mock_project.analyses.CFGFast.call_count == 1


def test_guard_patcher_generate_patch_x86():
    """Test patch generation for x86 (32-bit) architecture."""
    from dynpathresolver.detection.guards import GuardPatcher, Guard, GuardType

    mock_project = MagicMock()
    mock_project.arch.name = 'X86'
    mock_project.arch.bytes = 4

    patcher = GuardPatcher(mock_project)

    guard = Guard(
        addr=0x401000,
        guard_type=GuardType.ANTI_DEBUG,
        function_name='ptrace',
        bypass_value=0,
    )

    patch_bytes = patcher.generate_patch(guard)

    # Should return bytes for x86 (mov eax, imm; ret)
    assert isinstance(patch_bytes, bytes)
    assert len(patch_bytes) > 0
