"""Pattern-based predictor using behavioral analysis.

This module provides classes for detecting suspicious library loading patterns:
- SuspiciousIndicator: Categories of suspicious behavior
- SuspiciousPath: A potentially suspicious library path with indicators
- PatternPredictor: Enhanced pattern-based predictor using behavioral analysis
- EnvironmentPredictor: Search filesystem for libraries based on environment
"""

import logging
import os
import re
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.constants import LINUX_LIB_PATHS, WINDOWS_LIB_PATHS
from dynpathresolver.config.enums import SuspiciousIndicator
from dynpathresolver.analysis.behavior_analyzer import (
    BehavioralPatternAnalyzer,
    LoadBehaviorDetector,
    SymbolicPathTracker,
)

log = logging.getLogger(__name__)


@dataclass
class SuspiciousPath:
    """A potentially suspicious library path with indicators."""
    path: str
    indicators: list[SuspiciousIndicator] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    source: str = ""  # How it was discovered
    context: dict = field(default_factory=dict)  # Additional metadata

    def is_suspicious(self) -> bool:
        """Return True if path has any suspicious indicators."""
        return len(self.indicators) > 0

    def suspicion_score(self) -> float:
        """Calculate overall suspicion score based on indicators."""
        weights = {
            SuspiciousIndicator.MEMORY_BACKED: 0.9,
            SuspiciousIndicator.DECRYPTED_PATH: 0.8,
            SuspiciousIndicator.TEMP_DIRECTORY: 0.7,
            SuspiciousIndicator.HIDDEN_DIRECTORY: 0.7,
            SuspiciousIndicator.PATH_TRAVERSAL: 0.6,
            SuspiciousIndicator.RANDOM_NAME: 0.5,
            SuspiciousIndicator.CONDITIONAL_LOAD: 0.5,
            SuspiciousIndicator.NETWORK_DERIVED: 0.8,
            SuspiciousIndicator.COMPUTED_AT_RUNTIME: 0.4,
            SuspiciousIndicator.ENVIRONMENT_DEPENDENT: 0.3,
            SuspiciousIndicator.WORLD_WRITABLE: 0.4,
            SuspiciousIndicator.USER_WRITABLE: 0.3,
        }
        if not self.indicators:
            return 0.0
        total = sum(weights.get(ind, 0.3) for ind in self.indicators)
        return min(1.0, total / len(self.indicators) + 0.1 * len(self.indicators))


class EnvironmentPredictor:
    """Search filesystem for libraries based on environment configuration."""

    LINUX_PATHS = LINUX_LIB_PATHS
    WINDOWS_PATHS = WINDOWS_LIB_PATHS

    def __init__(self, platform: str, extra_paths: list[str] | None = None):
        self.platform = platform
        self.search_paths: list[str] = []

        # Set base paths for platform
        if platform == 'windows':
            self.search_paths.extend(self.WINDOWS_PATHS)
        else:
            self.search_paths.extend(self.LINUX_PATHS)

        # Add extra paths
        if extra_paths:
            self.search_paths.extend(extra_paths)

        # Add LD_LIBRARY_PATH entries (Linux)
        if platform != 'windows':
            ld_path = os.environ.get('LD_LIBRARY_PATH', '')
            if ld_path:
                self.search_paths.extend(ld_path.split(':'))

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for p in self.search_paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
        self.search_paths = unique_paths

    def find_library(self, name: str) -> str | None:
        """
        Search all paths for a library file.

        Args:
            name: Library filename to find

        Returns:
            Full path if found, None otherwise
        """
        for search_path in self.search_paths:
            full_path = os.path.join(search_path, name)
            if os.path.isfile(full_path):
                return full_path
        return None

    def find_all_matches(self, candidates: set[str]) -> dict[str, str]:
        """
        Find all candidates that exist on the filesystem.

        Args:
            candidates: Set of library names to search for

        Returns:
            Dict mapping name to resolved full path
        """
        matches = {}
        for name in candidates:
            path = self.find_library(name)
            if path:
                matches[name] = path
                log.debug(f"Found library candidate: {name} -> {path}")
        return matches


class PatternPredictor:
    """
    Enhanced pattern-based predictor using behavioral analysis.

    This replaces the old static name list approach with detection based on:
    1. Path characteristics (location, naming patterns)
    2. Loading behavior (how the library is loaded)
    3. Path construction (decryption, string assembly)

    NOTE: The old COMMON_PAYLOADS, NETWORK_LIBS, REMOTE_LIBS lists are kept
    only for backwards compatibility but are no longer the primary detection.
    """

    # Legacy lists - kept for backwards compatibility only
    # These are NOT the primary detection mechanism
    _LEGACY_COMMON_PAYLOADS = [
        'libpayload.so', 'payload.dll',
        'libsecret.so', 'secret.dll',
        'libhidden.so', 'hidden.dll',
    ]

    def __init__(self, project: "angr.Project", platform: str = 'linux'):
        self.project = project
        self.platform = platform

        # Initialize behavioral analyzers
        self.behavior_analyzer = BehavioralPatternAnalyzer(project, platform)
        self.path_tracker = SymbolicPathTracker(project)
        self.load_detector = LoadBehaviorDetector(project)

        # Track all discovered paths with their analysis
        self.analyzed_paths: list[SuspiciousPath] = []

    def analyze(self) -> set[str]:
        """
        Analyze binary patterns to predict likely library names.

        This method now focuses on behavioral patterns rather than static names.

        Returns:
            Set of predicted library names/paths
        """
        predictions = set()

        # 1. Extract strings that look like library paths
        string_candidates = self._extract_library_strings()

        # 2. Analyze each candidate for suspicious patterns
        for path in string_candidates:
            analysis = self.behavior_analyzer.analyze_path(path, {
                'source': 'string_extraction'
            })
            self.analyzed_paths.append(analysis)

            # Include all library-looking strings, flag suspicious ones
            predictions.add(path)
            if analysis.is_suspicious():
                log.debug(f"Suspicious path detected: {path} - {analysis.indicators}")

        # 3. Add any paths detected through load behavior
        for load in self.load_detector.get_detected_loads():
            predictions.add(load.path)
            self.analyzed_paths.append(load)

        # 4. Binary name-based prediction (low priority)
        if hasattr(self.project, 'filename') and self.project.filename:
            binary_name = os.path.basename(self.project.filename)
            name_base = os.path.splitext(binary_name)[0]
            predictions.add(f"lib{name_base}.so")
            predictions.add(f"{name_base}.dll")

        return predictions

    def _extract_library_strings(self) -> set[str]:
        """Extract strings that look like library paths from binary."""
        candidates = set()

        # Library file patterns
        lib_patterns = [
            re.compile(r'[./\\][\w\-_.]+\.so(\.\d+)*', re.IGNORECASE),
            re.compile(r'[./\\][\w\-_.]+\.dll', re.IGNORECASE),
            re.compile(r'/proc/self/fd/\d+'),
            re.compile(r'/memfd:[\w]+'),
        ]

        for obj in self.project.loader.all_objects:
            if not hasattr(obj, 'memory'):
                continue

            try:
                # Extract strings from binary
                strings = self._extract_strings_from_object(obj)

                for s in strings:
                    for pattern in lib_patterns:
                        if pattern.search(s):
                            candidates.add(s)
                            break
            except Exception as e:
                log.debug(f"Error extracting strings from {obj}: {e}")

        return candidates

    def _extract_strings_from_object(self, obj) -> set[str]:
        """Extract printable strings from a loader object."""
        strings = set()
        printable = set(string.printable.encode('ascii'))
        min_length = 4

        try:
            mem = obj.memory
            if hasattr(mem, 'load'):
                for section in getattr(obj, 'sections', []):
                    try:
                        data = mem.load(section.min_addr - obj.min_addr,
                                       min(section.memsize, 1024 * 1024))
                        self._extract_from_bytes(data, strings, min_length, printable)
                    except Exception:
                        continue
        except Exception:
            pass

        return strings

    def _extract_from_bytes(self, data: bytes, strings: set[str],
                            min_length: int, printable: set[int]) -> None:
        """Extract printable ASCII strings from byte data."""
        current = []
        for byte in data:
            if byte in printable and byte not in (0, 10, 13):
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.add(''.join(current))
                current = []
        if len(current) >= min_length:
            strings.add(''.join(current))

    def analyze_dlopen_call(self, state: "angr.SimState",
                            path: str) -> SuspiciousPath:
        """
        Analyze a specific dlopen call with full context.

        This is called when we intercept an actual dlopen/LoadLibrary call.

        Args:
            state: The angr state at the dlopen call
            path: The resolved library path

        Returns:
            SuspiciousPath analysis
        """
        context = {
            'source': 'dlopen_intercept',
            'call_addr': state.addr,
            'was_symbolic': state.solver.symbolic(state.memory.load(
                state.regs.rdi if hasattr(state.regs, 'rdi') else 0, 8
            )) if hasattr(state, 'solver') else False,
        }

        # Check if this path came through decryption
        if state.addr in self.path_tracker.decryption_sites:
            context['decrypted'] = True

        # Check for memfd pattern
        memfd_result = self.load_detector.check_memfd_dlopen(state, path)
        if memfd_result:
            return memfd_result

        # Full analysis
        return self.behavior_analyzer.analyze_path(path, context)

    def get_suspicious_paths(self, min_score: float = 0.5) -> list[SuspiciousPath]:
        """
        Get all paths with suspicion score above threshold.

        Args:
            min_score: Minimum suspicion score (0.0 to 1.0)

        Returns:
            List of SuspiciousPath objects above threshold
        """
        return [p for p in self.analyzed_paths
                if p.suspicion_score() >= min_score]

    def get_high_confidence_threats(self) -> list[SuspiciousPath]:
        """Get paths with high-confidence threat indicators."""
        high_threat_indicators = {
            SuspiciousIndicator.MEMORY_BACKED,
            SuspiciousIndicator.DECRYPTED_PATH,
            SuspiciousIndicator.NETWORK_DERIVED,
        }

        return [p for p in self.analyzed_paths
                if any(ind in high_threat_indicators for ind in p.indicators)]

    # Legacy compatibility method
    def _has_xor_patterns(self) -> bool:
        """Check if binary contains XOR-based obfuscation patterns."""
        try:
            for obj in self.project.loader.all_objects:
                if hasattr(obj, 'symbols'):
                    for sym in obj.symbols:
                        name = sym.name.lower() if sym.name else ''
                        if any(p in name for p in ['crypt', 'xor', 'decode', 'decrypt']):
                            return True
        except Exception:
            pass
        return False

    # Legacy compatibility method
    def _has_network_patterns(self) -> bool:
        """Check if binary contains network-related patterns."""
        try:
            network_indicators = [
                'socket', 'connect', 'recv', 'send',
                'http', 'https', 'curl', 'download',
                'WSAStartup', 'InternetOpen',
            ]
            for obj in self.project.loader.all_objects:
                if hasattr(obj, 'symbols'):
                    for sym in obj.symbols:
                        name = sym.name.lower() if sym.name else ''
                        if any(p.lower() in name for p in network_indicators):
                            return True
        except Exception:
            pass
        return False
