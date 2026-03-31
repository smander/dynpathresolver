"""Guard detection module for anti-analysis protection bypassing."""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.enums import GuardType

log = logging.getLogger(__name__)


@dataclass
class Guard:
    """Represents a detected anti-analysis guard."""

    addr: int
    guard_type: GuardType
    function_name: str
    bypass_value: int


# Known anti-debug function names (Linux and Windows)
ANTI_DEBUG_FUNCTIONS = {
    'ptrace': 0,          # Return 0 to indicate success (no debugger)
    'IsDebuggerPresent': 0,  # Return 0 (false) to bypass
    'NtQueryInformationProcess': 0,
    'CheckRemoteDebuggerPresent': 0,
}

# Known timing check function names
TIMING_FUNCTIONS = {
    'gettimeofday': 0,
    'clock_gettime': 0,
    'time': 0,
    'QueryPerformanceCounter': 1,  # Return 1 (success)
    'GetTickCount': 0,
    'GetTickCount64': 0,
}

# Known environment check function names
ENVIRONMENT_FUNCTIONS = {
    'getenv': 0,  # Return NULL (0) to indicate variable not set
}

# VM detection strings to search for
VM_STRINGS = [
    'VMware',
    'VBox',
    'VBOX',
    'Virtual',
    'QEMU',
    'Xen',
    'Hyper-V',
    'parallels',
]


class GuardDetector:
    """Detects anti-analysis guards in binaries."""

    def __init__(self, project: "angr.Project"):
        """
        Initialize the guard detector.

        Args:
            project: The angr project to analyze
        """
        self.project = project
        self._cfg = None
        self._guards: list[Guard] = []

    def _get_cfg(self):
        """Get or create CFG analysis (cached)."""
        if self._cfg is None:
            self._cfg = self.project.analyses.CFGFast()
        return self._cfg

    def detect_guards(self) -> list[Guard]:
        """
        Scan binary for all guard patterns.

        Returns:
            List of detected Guard objects
        """
        guards = []

        # Find all types of guards
        guards.extend(self._find_anti_debug_calls())
        guards.extend(self._find_vm_detection())
        guards.extend(self._find_timing_checks())
        guards.extend(self._find_environment_checks())

        self._guards = guards
        return guards

    def _find_anti_debug_calls(self) -> list[Guard]:
        """
        Find ptrace, IsDebuggerPresent, and other anti-debug calls.

        Returns:
            List of Guard objects for anti-debug functions
        """
        guards = []

        for func_name, bypass_value in ANTI_DEBUG_FUNCTIONS.items():
            # Try to find the symbol
            try:
                sym = self.project.loader.find_symbol(func_name)
                if sym is not None:
                    guard = Guard(
                        addr=sym.rebased_addr,
                        guard_type=GuardType.ANTI_DEBUG,
                        function_name=func_name,
                        bypass_value=bypass_value,
                    )
                    guards.append(guard)
                    log.info(f"Found anti-debug guard: {func_name} at 0x{sym.rebased_addr:x}")
            except (IndexError, KeyError) as e:
                log.debug(f"Error looking up symbol {func_name}: {e}")

        return guards

    def _find_vm_detection(self) -> list[Guard]:
        """
        Find cpuid instructions and MAC address checks for VM detection.

        Returns:
            List of Guard objects for VM detection
        """
        guards = []
        cfg = self._get_cfg()

        # Search for cpuid instructions in code
        arch_name = getattr(self.project.arch, 'name', '')
        if arch_name in ('AMD64', 'X86'):
            for func in cfg.functions.values():
                try:
                    for block in func.blocks:
                        try:
                            for insn in block.capstone.insns:
                                if insn.mnemonic == 'cpuid':
                                    guard = Guard(
                                        addr=insn.address,
                                        guard_type=GuardType.VM_DETECTION,
                                        function_name='cpuid',
                                        bypass_value=0,  # Will need custom handling
                                    )
                                    guards.append(guard)
                                    log.info(f"Found VM detection: cpuid at 0x{insn.address:x}")
                        except Exception as e:
                            log.debug(f"Error analyzing block: {e}")
                except Exception as e:
                    log.debug(f"Error analyzing function: {e}")

        return guards

    def _find_timing_checks(self) -> list[Guard]:
        """
        Find rdtsc instructions and timing function calls.

        Returns:
            List of Guard objects for timing checks
        """
        guards = []
        cfg = self._get_cfg()

        # Find timing function calls
        for func_name, bypass_value in TIMING_FUNCTIONS.items():
            try:
                sym = self.project.loader.find_symbol(func_name)
                if sym is not None:
                    guard = Guard(
                        addr=sym.rebased_addr,
                        guard_type=GuardType.TIMING_CHECK,
                        function_name=func_name,
                        bypass_value=bypass_value,
                    )
                    guards.append(guard)
                    log.info(f"Found timing check: {func_name} at 0x{sym.rebased_addr:x}")
            except (IndexError, KeyError) as e:
                log.debug(f"Error looking up symbol {func_name}: {e}")

        # Search for rdtsc instructions
        arch_name = getattr(self.project.arch, 'name', '')
        if arch_name in ('AMD64', 'X86'):
            for func in cfg.functions.values():
                try:
                    for block in func.blocks:
                        try:
                            for insn in block.capstone.insns:
                                if insn.mnemonic == 'rdtsc':
                                    guard = Guard(
                                        addr=insn.address,
                                        guard_type=GuardType.TIMING_CHECK,
                                        function_name='rdtsc',
                                        bypass_value=0,
                                    )
                                    guards.append(guard)
                                    log.info(f"Found timing check: rdtsc at 0x{insn.address:x}")
                        except Exception as e:
                            log.debug(f"Error analyzing block: {e}")
                except Exception as e:
                    log.debug(f"Error analyzing function: {e}")

        return guards

    def _find_environment_checks(self) -> list[Guard]:
        """
        Find getenv calls for sandbox detection.

        Returns:
            List of Guard objects for environment checks
        """
        guards = []

        for func_name, bypass_value in ENVIRONMENT_FUNCTIONS.items():
            try:
                sym = self.project.loader.find_symbol(func_name)
                if sym is not None:
                    guard = Guard(
                        addr=sym.rebased_addr,
                        guard_type=GuardType.ENVIRONMENT_CHECK,
                        function_name=func_name,
                        bypass_value=bypass_value,
                    )
                    guards.append(guard)
                    log.info(f"Found environment check: {func_name} at 0x{sym.rebased_addr:x}")
            except (IndexError, KeyError) as e:
                log.debug(f"Error looking up symbol {func_name}: {e}")

        return guards

    def get_guards_on_path(self, path_candidate) -> list[Guard]:
        """
        Identify which guards are on a specific execution path.

        Args:
            path_candidate: PathCandidate object or angr state with execution history

        Returns:
            List of guards that are on the given path
        """
        if not self._guards:
            self.detect_guards()

        # Get addresses from path - handle different input types
        path_addrs = set()

        # Try PathCandidate (has path_constraints which may contain states)
        if hasattr(path_candidate, 'path_constraints'):
            # PathCandidate - constraints don't have addresses, but we can
            # check if the dlopen address is near any guards
            dlopen_addr = getattr(path_candidate, 'dlopen_addr', 0)
            if dlopen_addr:
                # Use CFG to find guards reachable from entry to dlopen
                path_addrs = self._get_reachable_addrs(dlopen_addr)

        # Try angr state with history
        elif hasattr(path_candidate, 'history'):
            try:
                path_addrs = set(path_candidate.history.bbl_addrs)
            except (AttributeError, TypeError):
                pass

        # Try list of addresses directly
        elif isinstance(path_candidate, (list, set)):
            path_addrs = set(path_candidate)

        if not path_addrs:
            log.debug("Could not extract path addresses")
            return []

        guards_on_path = []
        for guard in self._guards:
            if guard.addr in path_addrs:
                guards_on_path.append(guard)

        return guards_on_path

    def _get_reachable_addrs(self, target_addr: int) -> set[int]:
        """Get all basic block addresses reachable on path to target."""
        addrs = set()
        if self._cfg is None:
            return addrs

        try:
            # Find node containing target
            target_node = self._cfg.model.get_any_node(target_addr)
            if not target_node:
                return addrs

            # BFS from entry to find all paths to target
            entry_node = self._cfg.model.get_any_node(self.project.entry)
            if not entry_node:
                return addrs

            # Simple reachability - get all nodes that can reach target
            import networkx as nx
            graph = self._cfg.graph

            # Reverse graph to find nodes that can reach target
            try:
                ancestors = nx.ancestors(graph, target_node)
                for node in ancestors:
                    if hasattr(node, 'addr'):
                        addrs.add(node.addr)
                addrs.add(target_addr)
            except nx.NetworkXError:
                pass

        except Exception as e:
            log.debug(f"Could not compute reachable addresses: {e}")

        return addrs


class GuardPatcher:
    """Generates patches to bypass anti-analysis guards."""

    def __init__(self, project: "angr.Project"):
        """
        Initialize the guard patcher.

        Args:
            project: The angr project
        """
        self.project = project

    def generate_patch(self, guard: Guard) -> bytes:
        """
        Generate patch bytes to bypass a guard.

        Args:
            guard: The guard to patch

        Returns:
            Bytes to write at the guard address to bypass it
        """
        arch_name = getattr(self.project.arch, 'name', 'AMD64')
        arch_bytes = getattr(self.project.arch, 'bytes', 8)

        bypass_value = guard.bypass_value

        if arch_name == 'AMD64':
            # x86-64: mov eax, imm32; ret
            # b8 XX XX XX XX c3
            patch = bytes([0xb8]) + bypass_value.to_bytes(4, 'little') + bytes([0xc3])
        elif arch_name == 'X86':
            # x86: mov eax, imm32; ret
            # b8 XX XX XX XX c3
            patch = bytes([0xb8]) + bypass_value.to_bytes(4, 'little') + bytes([0xc3])
        else:
            # Generic: just return the bypass value bytes
            patch = bypass_value.to_bytes(arch_bytes, 'little')

        return patch

    def generate_ld_preload(self, guards: list[Guard]) -> str:
        """
        Generate C code for LD_PRELOAD bypass library.

        Args:
            guards: List of guards to bypass

        Returns:
            C source code for the LD_PRELOAD library
        """
        lines = [
            '#define _GNU_SOURCE',
            '#include <stdio.h>',
            '#include <stdlib.h>',
            '#include <sys/types.h>',
            '#include <unistd.h>',
            '',
            '/* Auto-generated LD_PRELOAD bypass library */',
            '',
        ]

        # Generate function overrides for each guard
        for guard in guards:
            func_name = guard.function_name
            bypass_value = guard.bypass_value

            if func_name == 'ptrace':
                lines.extend([
                    '#include <sys/ptrace.h>',
                    '',
                    'long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {',
                    f'    return {bypass_value};  /* Bypass anti-debug */',
                    '}',
                    '',
                ])
            elif func_name == 'IsDebuggerPresent':
                lines.extend([
                    '/* Windows API - for Wine/cross-platform */',
                    'int IsDebuggerPresent(void) {',
                    f'    return {bypass_value};  /* Bypass debugger detection */',
                    '}',
                    '',
                ])
            elif func_name == 'gettimeofday':
                lines.extend([
                    '#include <sys/time.h>',
                    '',
                    'static struct timeval last_time = {0, 0};',
                    '',
                    'int gettimeofday(struct timeval *tv, void *tz) {',
                    '    /* Return consistent time to bypass timing checks */',
                    '    if (last_time.tv_sec == 0) {',
                    '        last_time.tv_sec = 1000000;',
                    '        last_time.tv_usec = 0;',
                    '    }',
                    '    last_time.tv_usec += 1000;  /* Small increment */',
                    '    if (tv) *tv = last_time;',
                    f'    return {bypass_value};',
                    '}',
                    '',
                ])
            elif func_name == 'getenv':
                lines.extend([
                    '/* Sandbox environment variable check bypass */',
                    '/* Note: This overrides ALL getenv calls */',
                    'char *getenv(const char *name) {',
                    '    /* Return NULL for sandbox indicators */',
                    '    static const char *sandbox_vars[] = {',
                    '        "SANDBOX", "ANALYSIS", "MALWARE", "CUCKOO",',
                    '        "VBOX", "VMWARE", NULL',
                    '    };',
                    '    for (int i = 0; sandbox_vars[i]; i++) {',
                    '        if (strstr(name, sandbox_vars[i])) return NULL;',
                    '    }',
                    '    /* Call real getenv for other variables */',
                    '    extern char *__libc_getenv(const char *);',
                    '    return __libc_getenv(name);',
                    '}',
                    '',
                ])
            else:
                # Generic bypass
                lines.extend([
                    f'/* Bypass for {func_name} */',
                    f'long {func_name}(void) {{',
                    f'    return {bypass_value};',
                    '}',
                    '',
                ])

        return '\n'.join(lines)

    def apply_patches(
        self,
        binary_path: str,
        guards: list[Guard],
        output_path: str,
    ) -> bool:
        """
        Create a patched binary with guards bypassed.

        Args:
            binary_path: Path to input binary
            guards: List of guards to patch
            output_path: Path for patched binary

        Returns:
            True if patching succeeded, False otherwise
        """
        try:
            # Read the original binary
            with open(binary_path, 'rb') as f:
                binary_data = bytearray(f.read())

            # Parse ELF to get VA -> file offset mapping
            va_to_offset = self._build_va_to_offset_map(binary_data)

            # Apply patches
            patched_count = 0
            for guard in guards:
                patch_bytes = self.generate_patch(guard)

                # Convert virtual address to file offset
                file_offset = self._va_to_file_offset(guard.addr, va_to_offset)

                if file_offset is None:
                    log.warning(f"Could not map VA 0x{guard.addr:x} to file offset for {guard.function_name}")
                    continue

                # Only patch if within file bounds
                if file_offset + len(patch_bytes) <= len(binary_data):
                    binary_data[file_offset:file_offset + len(patch_bytes)] = patch_bytes
                    log.info(f"Patched guard {guard.function_name} at VA 0x{guard.addr:x} (file offset 0x{file_offset:x})")
                    patched_count += 1
                else:
                    log.warning(f"Guard {guard.function_name} at file offset 0x{file_offset:x} outside file bounds")

            if patched_count == 0:
                log.warning("No guards were patched")
                return False

            # Write patched binary
            with open(output_path, 'wb') as f:
                f.write(binary_data)

            return True

        except Exception as e:
            log.error(f"Failed to apply patches: {e}")
            return False

    def _build_va_to_offset_map(self, binary_data: bytes) -> list[tuple[int, int, int, int]]:
        """
        Build a mapping from virtual addresses to file offsets by parsing ELF program headers.

        Returns:
            List of (vaddr_start, vaddr_end, file_offset, file_size) tuples
        """
        import struct

        segments = []

        # Check ELF magic
        if binary_data[:4] != b'\x7fELF':
            log.warning("Not an ELF file")
            return segments

        # Determine 32 or 64 bit
        is_64bit = binary_data[4] == 2

        if is_64bit:
            # 64-bit ELF header
            e_phoff = struct.unpack('<Q', binary_data[32:40])[0]
            e_phentsize = struct.unpack('<H', binary_data[54:56])[0]
            e_phnum = struct.unpack('<H', binary_data[56:58])[0]

            # Parse program headers
            for i in range(e_phnum):
                ph_offset = e_phoff + i * e_phentsize
                p_type = struct.unpack('<I', binary_data[ph_offset:ph_offset+4])[0]

                # PT_LOAD = 1
                if p_type == 1:
                    p_offset = struct.unpack('<Q', binary_data[ph_offset+8:ph_offset+16])[0]
                    p_vaddr = struct.unpack('<Q', binary_data[ph_offset+16:ph_offset+24])[0]
                    p_filesz = struct.unpack('<Q', binary_data[ph_offset+32:ph_offset+40])[0]
                    p_memsz = struct.unpack('<Q', binary_data[ph_offset+40:ph_offset+48])[0]

                    segments.append((p_vaddr, p_vaddr + p_memsz, p_offset, p_filesz))
        else:
            # 32-bit ELF header
            e_phoff = struct.unpack('<I', binary_data[28:32])[0]
            e_phentsize = struct.unpack('<H', binary_data[42:44])[0]
            e_phnum = struct.unpack('<H', binary_data[44:46])[0]

            # Parse program headers
            for i in range(e_phnum):
                ph_offset = e_phoff + i * e_phentsize
                p_type = struct.unpack('<I', binary_data[ph_offset:ph_offset+4])[0]

                # PT_LOAD = 1
                if p_type == 1:
                    p_offset = struct.unpack('<I', binary_data[ph_offset+4:ph_offset+8])[0]
                    p_vaddr = struct.unpack('<I', binary_data[ph_offset+8:ph_offset+12])[0]
                    p_filesz = struct.unpack('<I', binary_data[ph_offset+16:ph_offset+20])[0]
                    p_memsz = struct.unpack('<I', binary_data[ph_offset+20:ph_offset+24])[0]

                    segments.append((p_vaddr, p_vaddr + p_memsz, p_offset, p_filesz))

        return segments

    def _va_to_file_offset(self, va: int, segments: list[tuple[int, int, int, int]]) -> int | None:
        """
        Convert a virtual address to a file offset.

        Args:
            va: Virtual address
            segments: List of (vaddr_start, vaddr_end, file_offset, file_size) tuples

        Returns:
            File offset, or None if VA not in any segment
        """
        for vaddr_start, vaddr_end, file_offset, file_size in segments:
            if vaddr_start <= va < vaddr_end:
                offset_in_segment = va - vaddr_start
                if offset_in_segment < file_size:
                    return file_offset + offset_in_segment
        return None
