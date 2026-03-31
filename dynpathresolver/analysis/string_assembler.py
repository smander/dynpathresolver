"""String fragment assembler for library discovery.

This module provides the StringFragmentAssembler class that finds potential
library names from string fragments in binary memory.
"""

import logging
import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class StringFragmentAssembler:
    """Find potential library names from string fragments in binary memory."""

    PREFIXES = ['lib', 'mod_', 'plugin_', '']
    SUFFIXES_LINUX = ['.so', '.so.1', '.so.6', '.so.0']
    SUFFIXES_WINDOWS = ['.dll', '.DLL', '.sys']

    def __init__(self, project: "angr.Project", platform: str):
        self.project = project
        self.platform = platform
        self.suffixes = self.SUFFIXES_WINDOWS if platform == 'windows' else self.SUFFIXES_LINUX
        self._cached_strings: set[str] | None = None

    def extract_all_strings(self, min_length: int = 3) -> set[str]:
        """
        Scan binary memory for printable ASCII sequences.

        Args:
            min_length: Minimum string length to extract

        Returns:
            Set of extracted strings
        """
        if self._cached_strings is not None:
            return self._cached_strings

        strings = set()
        printable = set(string.printable.encode('ascii'))

        for obj in self.project.loader.all_objects:
            if not hasattr(obj, 'memory'):
                continue

            try:
                # Get memory as bytes
                mem = obj.memory
                if hasattr(mem, 'load'):
                    # angr memory object - try to read in chunks
                    for section in getattr(obj, 'sections', []):
                        try:
                            data = mem.load(section.min_addr - obj.min_addr, section.memsize)
                            self._extract_from_bytes(data, strings, min_length, printable)
                        except Exception:
                            continue
                elif hasattr(mem, '__iter__'):
                    # Direct bytes-like object
                    self._extract_from_bytes(bytes(mem), strings, min_length, printable)
            except Exception as e:
                log.debug(f"Error extracting strings from {obj}: {e}")
                continue

        self._cached_strings = strings
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

    def find_candidate_names(self) -> set[str]:
        """
        Find candidate library names from extracted strings.

        Returns:
            Set of potential library names (e.g., libpayload.so, module.dll)
        """
        candidates = set()
        all_strings = self.extract_all_strings()

        # Find strings that already look like library names
        for s in all_strings:
            for suffix in self.suffixes:
                if s.endswith(suffix):
                    candidates.add(s)
                    break

        # Assemble candidates from fragments: prefix + fragment + suffix
        for fragment in all_strings:
            # Skip overly long fragments or fragments with path separators
            if len(fragment) > 32 or '/' in fragment or '\\' in fragment:
                continue
            # Skip fragments that already have extensions
            if any(fragment.endswith(s) for s in self.suffixes):
                continue
            # Skip non-alphanumeric fragments
            if not fragment.replace('_', '').replace('-', '').isalnum():
                continue

            for prefix in self.PREFIXES:
                for suffix in self.suffixes:
                    # Only add the primary suffix for each platform to avoid explosion
                    if suffix in (self.suffixes[0],):
                        candidates.add(f"{prefix}{fragment}{suffix}")

        return candidates
