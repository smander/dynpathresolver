"""Behavioral analysis for library loading patterns.

This module provides classes for detecting suspicious loading behavior:
- BehavioralPatternAnalyzer: Analyze library loading behavior patterns
- SymbolicPathTracker: Track how library paths are constructed symbolically
- LoadBehaviorDetector: Detect library loading behavior from syscalls/API calls
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr
    import claripy
    from dynpathresolver.analysis.pattern_predictor import SuspiciousPath

log = logging.getLogger(__name__)


# Forward reference to avoid circular import at module level.
# SuspiciousIndicator and SuspiciousPath are defined in pattern_predictor.py,
# which imports from this module. We use lazy imports in methods that need them.

def _get_suspicious_types():
    """Lazy import of SuspiciousIndicator and SuspiciousPath to avoid circular imports."""
    from dynpathresolver.analysis.pattern_predictor import SuspiciousIndicator, SuspiciousPath
    return SuspiciousIndicator, SuspiciousPath


class BehavioralPatternAnalyzer:
    """
    Analyze library loading behavior patterns instead of relying on static names.

    This class detects suspicious loading patterns regardless of what the library
    is named. Malware can call their payload 'libgraphics.so' or 'update.dll',
    but the loading behavior (from /tmp, decrypted path, etc.) reveals intent.
    """

    # Suspicious directory patterns (platform-agnostic regex)
    SUSPICIOUS_DIR_PATTERNS = [
        # Temp directories
        r'^/tmp/',
        r'^/var/tmp/',
        r'^/dev/shm/',
        r'^/run/user/\d+/',
        r'^%TEMP%',
        r'^%TMP%',
        r'^C:\\Windows\\Temp\\',
        r'^C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\',

        # Hidden directories (Unix)
        r'/\.[^/]+/',  # /.hidden/

        # User-writable locations
        r'^/home/[^/]+/\.',  # Hidden in home
        r'^/home/[^/]+/Downloads/',
        r'^C:\\Users\\[^\\]+\\Downloads\\',

        # World-writable
        r'^/var/www/',
        r'^/srv/',
    ]

    # Memory-backed file patterns
    MEMORY_BACKED_PATTERNS = [
        r'^/proc/self/fd/\d+$',
        r'^/proc/\d+/fd/\d+$',
        r'^/dev/fd/\d+$',
        r'^/memfd:',
    ]

    # Random/hex name patterns (suspicious naming)
    RANDOM_NAME_PATTERNS = [
        r'/[a-f0-9]{16,}\.so',      # Long hex names
        r'/[a-f0-9]{8}-[a-f0-9]{4}',  # UUID-like
        r'/[A-Za-z0-9]{32,}\.(so|dll)',  # Long random alphanumeric
        r'/\d{10,}\.(so|dll)',      # Timestamp-like names
    ]

    def __init__(self, project: "angr.Project", platform: str):
        self.project = project
        self.platform = platform
        self._compiled_suspicious = [re.compile(p, re.IGNORECASE)
                                      for p in self.SUSPICIOUS_DIR_PATTERNS]
        self._compiled_memory = [re.compile(p) for p in self.MEMORY_BACKED_PATTERNS]
        self._compiled_random = [re.compile(p, re.IGNORECASE)
                                  for p in self.RANDOM_NAME_PATTERNS]

    def analyze_path(self, path: str, context: dict[str, str | bool | int] | None = None) -> SuspiciousPath:
        """
        Analyze a library path for suspicious indicators.

        Args:
            path: The library path to analyze
            context: Optional context (e.g., how path was discovered)

        Returns:
            SuspiciousPath with detected indicators
        """
        SuspiciousIndicator, SuspiciousPath = _get_suspicious_types()

        indicators = []
        ctx = context or {}

        # Check for memory-backed files (highest suspicion)
        for pattern in self._compiled_memory:
            if pattern.search(path):
                indicators.append(SuspiciousIndicator.MEMORY_BACKED)
                break

        # Check for suspicious directories
        for pattern in self._compiled_suspicious:
            if pattern.search(path):
                if '/tmp' in path.lower() or 'temp' in path.lower():
                    indicators.append(SuspiciousIndicator.TEMP_DIRECTORY)
                elif '/.' in path or '\\.' in path:
                    indicators.append(SuspiciousIndicator.HIDDEN_DIRECTORY)
                elif 'download' in path.lower():
                    indicators.append(SuspiciousIndicator.USER_WRITABLE)
                else:
                    indicators.append(SuspiciousIndicator.WORLD_WRITABLE)
                break

        # Check for path traversal
        if '..' in path:
            indicators.append(SuspiciousIndicator.PATH_TRAVERSAL)

        # Check for random/hex naming
        for pattern in self._compiled_random:
            if pattern.search(path):
                indicators.append(SuspiciousIndicator.RANDOM_NAME)
                break

        # Context-based indicators
        if ctx.get('decrypted'):
            indicators.append(SuspiciousIndicator.DECRYPTED_PATH)
        if ctx.get('from_network'):
            indicators.append(SuspiciousIndicator.NETWORK_DERIVED)
        if ctx.get('env_dependent'):
            indicators.append(SuspiciousIndicator.ENVIRONMENT_DEPENDENT)
        if ctx.get('computed'):
            indicators.append(SuspiciousIndicator.COMPUTED_AT_RUNTIME)
        if ctx.get('conditional'):
            indicators.append(SuspiciousIndicator.CONDITIONAL_LOAD)

        return SuspiciousPath(
            path=path,
            indicators=indicators,
            source=ctx.get('source', 'unknown'),
            context=ctx,
        )

    def is_path_suspicious(self, path: str) -> bool:
        """Quick check if a path has any suspicious characteristics."""
        result = self.analyze_path(path)
        return result.is_suspicious()


class SymbolicPathTracker:
    """
    Track how library paths are constructed symbolically.

    Instead of guessing names, this tracks the actual path construction
    through symbolic execution - catching any name the malware uses.
    """

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.tracked_paths: list[SuspiciousPath] = []
        self.string_operations: list[dict[str, str | int]] = []
        self.decryption_sites: set[int] = set()

    def track_string_operation(self, state: "angr.SimState",
                                op_type: str, result_addr: int) -> None:
        """
        Track string manipulation that might be building a path.

        Args:
            state: Current angr state
            op_type: Type of operation (strcpy, strcat, sprintf, etc.)
            result_addr: Address where result is stored
        """
        self.string_operations.append({
            'type': op_type,
            'addr': state.addr,
            'result': result_addr,
            'step': state.history.depth,
        })

    def track_decryption(self, state: "angr.SimState",
                          output_addr: int, key_info: dict | None = None) -> None:
        """
        Track potential decryption operation.

        Args:
            state: Current angr state
            output_addr: Address where decrypted data is written
            key_info: Optional info about decryption key
        """
        self.decryption_sites.add(state.addr)
        log.debug(f"Decryption tracked at 0x{state.addr:x}, output to 0x{output_addr:x}")

    def extract_path_from_state(self, state: "angr.SimState",
                                 path_addr: int) -> tuple[str | None, dict[str, bool]]:
        """
        Extract a concrete path from symbolic state.

        Returns:
            Tuple of (path_string, context_dict)
        """
        context = {
            'computed': len(self.string_operations) > 0,
            'decrypted': any(op['addr'] in self.decryption_sites
                           for op in self.string_operations),
        }

        try:
            # Try to concretize the path
            path_expr = state.memory.load(path_addr, 256)

            if state.solver.symbolic(path_expr):
                # Path is symbolic - try to get a concrete solution
                try:
                    concrete = state.solver.eval(path_expr, cast_to=bytes)
                    path_str = concrete.split(b'\x00')[0].decode('utf-8', errors='ignore')
                    context['was_symbolic'] = True
                except Exception:
                    return None, context
            else:
                # Path is concrete
                concrete = state.solver.eval(path_expr, cast_to=bytes)
                path_str = concrete.split(b'\x00')[0].decode('utf-8', errors='ignore')

            return path_str, context

        except Exception as e:
            log.debug(f"Failed to extract path from 0x{path_addr:x}: {e}")
            return None, context


class LoadBehaviorDetector:
    """
    Detect library loading behavior patterns from syscalls and API calls.

    This works regardless of library names by monitoring the actual
    loading mechanism (open + mmap, memfd_create, etc.)
    """

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.open_calls: dict[int, dict[str, str | int]] = {}  # fd -> {path, flags, addr}
        self.mmap_calls: list[dict[str, int]] = []
        self.memfd_creates: list[dict[str, str | int]] = []
        self.detected_loads: list[SuspiciousPath] = []

    def record_open(self, state: "angr.SimState", path: str,
                     flags: int, fd: int) -> None:
        """Record an open() syscall."""
        self.open_calls[fd] = {
            'path': path,
            'flags': flags,
            'addr': state.addr,
            'step': state.history.depth,
        }

    def record_mmap(self, state: "angr.SimState", addr: int, length: int,
                     prot: int, flags: int, fd: int) -> None:
        """Record an mmap() syscall and correlate with open()."""
        SuspiciousIndicator, SuspiciousPath = _get_suspicious_types()

        PROT_EXEC = 0x4

        mmap_info = {
            'addr': addr,
            'length': length,
            'prot': prot,
            'flags': flags,
            'fd': fd,
            'state_addr': state.addr,
        }
        self.mmap_calls.append(mmap_info)

        # If mmap with PROT_EXEC and we have a matching open(), this is library loading
        if prot & PROT_EXEC and fd in self.open_calls:
            open_info = self.open_calls[fd]
            path = open_info['path']

            # This is a manually loaded library
            suspicious = SuspiciousPath(
                path=path,
                indicators=[SuspiciousIndicator.COMPUTED_AT_RUNTIME],
                source='manual_elf_load',
                context={
                    'open_addr': open_info['addr'],
                    'mmap_addr': state.addr,
                    'prot': prot,
                }
            )
            self.detected_loads.append(suspicious)
            log.info(f"Detected manual library load: {path}")

    def record_memfd_create(self, state: "angr.SimState",
                             name: str, fd: int) -> None:
        """Record a memfd_create() syscall."""
        self.memfd_creates.append({
            'name': name,
            'fd': fd,
            'addr': state.addr,
        })
        log.debug(f"memfd_create detected: name={name}, fd={fd}")

    def check_memfd_dlopen(self, state: "angr.SimState", path: str) -> SuspiciousPath | None:
        """Check if a dlopen path refers to a memfd."""
        SuspiciousIndicator, SuspiciousPath = _get_suspicious_types()

        # Pattern: /proc/self/fd/N where N matches a memfd fd
        match = re.match(r'/proc/self/fd/(\d+)', path)
        if match:
            fd = int(match.group(1))
            for memfd in self.memfd_creates:
                if memfd['fd'] == fd:
                    return SuspiciousPath(
                        path=path,
                        indicators=[SuspiciousIndicator.MEMORY_BACKED],
                        source='memfd_dlopen',
                        context={
                            'memfd_name': memfd['name'],
                            'memfd_create_addr': memfd['addr'],
                        }
                    )
        return None

    def get_detected_loads(self) -> list[SuspiciousPath]:
        """Return all detected library loads."""
        return self.detected_loads.copy()
