"""Library preloader for speculative library loading."""

import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr


class LibraryPreloader:
    """Speculatively loads libraries before execution reaches dlopen calls."""

    COMMON_LIBS = [
        'libc.so.6',
        'libdl.so.2',
        'libpthread.so.0',
        'libm.so.6',
        'librt.so.1',
        'libcrypto.so',
        'libssl.so',
    ]

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.loaded_libs: set[str] = set()
        self.pending_libs: set[str] = set()

    def add_library_paths(self, paths: list[str]) -> None:
        """Add libraries from paths (files or directories)."""
        for path in paths:
            if os.path.isdir(path):
                for filename in os.listdir(path):
                    if self._is_library_file(filename):
                        self.pending_libs.add(os.path.join(path, filename))
            elif os.path.isfile(path):
                self.pending_libs.add(path)

    def _is_library_file(self, filename: str) -> bool:
        """Check if a filename looks like a shared library."""
        return filename.endswith('.so') or '.so.' in filename

    def scan_for_library_strings(self) -> set[str]:
        """Scan binary for library name strings in .rodata/.data sections."""
        libs: set[str] = set()
        main_obj = self.project.loader.main_object

        if not hasattr(main_obj, 'sections'):
            return libs

        for section in main_obj.sections:
            if section.name not in ['.rodata', '.data']:
                continue

            try:
                data = self.project.loader.memory.load(
                    section.vaddr, section.memsize
                )
                # Match lib*.so* patterns
                matches = re.findall(rb'[\w./]*lib\w+\.so[\d.]*', data)
                libs.update(m.decode('utf-8', errors='ignore') for m in matches)
            except Exception:
                continue

        return libs

    def get_search_paths(self) -> list[str]:
        """Get library search paths in order of preference."""
        paths = []

        # LD_LIBRARY_PATH
        ld_path = os.environ.get('LD_LIBRARY_PATH', '')
        if ld_path:
            paths.extend(ld_path.split(':'))

        # Standard paths
        paths.extend([
            '/lib',
            '/lib64',
            '/usr/lib',
            '/usr/lib64',
            '/usr/local/lib',
        ])

        # Directory of main binary
        main_path = self.project.loader.main_object.binary
        if main_path:
            paths.append(os.path.dirname(main_path))

        return [p for p in paths if os.path.isdir(p)]

    def find_library(self, lib_name: str) -> str | None:
        """Find a library by name in search paths."""
        for search_path in self.get_search_paths():
            full_path = os.path.join(search_path, lib_name)
            if os.path.isfile(full_path):
                return full_path
        return None

    def load_common_libs(self) -> None:
        """Add common libraries to pending list."""
        for lib in self.COMMON_LIBS:
            found = self.find_library(lib)
            if found:
                self.pending_libs.add(found)

    def scan_and_load_string_refs(self) -> None:
        """Scan binary for library references and add to pending."""
        for lib_ref in self.scan_for_library_strings():
            lib_name = os.path.basename(lib_ref)
            found = self.find_library(lib_name)
            if found:
                self.pending_libs.add(found)
