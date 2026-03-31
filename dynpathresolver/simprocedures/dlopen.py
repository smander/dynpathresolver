"""
SimProcedure for dlopen() that actually loads libraries into the analysis.

This replaces angr's default dlopen SimProcedure to:
1. Extract the library path from the symbolic state
2. Find and load the library using CLE
3. Map the library into the state's memory
4. Return a handle that can be used with dlsym
"""

import os
import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import DEFAULT_HANDLE_BASE, PAGE_SIZE, PAGE_ALIGNMENT_GAP

if TYPE_CHECKING:
    from ..preloader import LibraryPreloader

log = logging.getLogger(__name__)


class DynDlopen(angr.SimProcedure):
    """
    SimProcedure for dlopen that loads libraries into the analysis state.

    This procedure:
    1. Reads the library path from the first argument
    2. Searches for the library in configured paths
    3. Loads the library using CLE
    4. Maps the library into memory
    5. Returns a handle (the library's base address)
    6. Records path candidate for hybrid validation
    """

    # Class-level storage for loaded libraries (shared across instances)
    # Maps handle -> library object
    loaded_libraries: dict[int, "angr.cle.Backend"] = {}

    # Library search paths (set by DynPathResolver)
    library_paths: list[str] = []

    # Reference to preloader (set by DynPathResolver)
    preloader: "LibraryPreloader | None" = None

    # Reference to DynPathResolver technique for validation recording
    technique: "object | None" = None

    # Counter for generating unique handles
    _handle_counter: int = DEFAULT_HANDLE_BASE

    def _get_technique(self):
        """Get technique from state globals (falls back to class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_preloader(self):
        """Get preloader from state globals (falls back to class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_preloader', self.__class__.preloader)
        return self.__class__.preloader

    def _get_library_paths(self):
        """Get library paths from state globals (falls back to class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_library_paths', self.__class__.library_paths)
        return self.__class__.library_paths

    def _get_loaded_libraries(self):
        """Get loaded libraries from state globals (falls back to class attr)."""
        if self.state is not None:
            return self.state.globals.get('dpr_loaded_libraries', self.__class__.loaded_libraries)
        return self.__class__.loaded_libraries

    def run(self, path_ptr, flags):
        """
        Simulate dlopen(path, flags).

        Args:
            path_ptr: Pointer to library path string
            flags: dlopen flags (RTLD_NOW, RTLD_LAZY, etc.)

        Returns:
            Handle to loaded library, or NULL (0) on failure
        """
        # Try to concretize the path
        lib_path = self._get_library_path(path_ptr)

        if lib_path is None:
            log.warning("dlopen: Could not resolve library path (symbolic)")
            # Return symbolic handle - caller may need to handle this
            return claripy.BVS("dlopen_handle", self.state.arch.bits)

        log.info(f"dlopen: Opening library '{lib_path}'")

        # Find the actual library file
        resolved_path = self._find_library(lib_path)

        if resolved_path is None:
            log.warning(f"dlopen: Library not found: {lib_path}")
            return claripy.BVV(0, self.state.arch.bits)  # NULL

        # Load the library
        handle = self._load_library(resolved_path)

        if handle is None:
            log.warning(f"dlopen: Failed to load library: {resolved_path}")
            return claripy.BVV(0, self.state.arch.bits)  # NULL

        log.info(f"dlopen: Loaded '{resolved_path}' at handle 0x{handle:x}")

        # Record path candidate for validation if technique is available
        self._record_for_validation(resolved_path, handle)

        return claripy.BVV(handle, self.state.arch.bits)

    def _get_library_path(self, path_ptr) -> str | None:
        """Extract library path string from memory."""
        if self.state.solver.symbolic(path_ptr):
            # Try to get a concrete value
            if self.state.solver.satisfiable():
                path_ptr = self.state.solver.eval(path_ptr)
            else:
                return None

        # Read null-terminated string
        try:
            path_bytes = self.state.mem[path_ptr].string.concrete
            if isinstance(path_bytes, bytes):
                return path_bytes.decode('utf-8', errors='ignore')
            return str(path_bytes)
        except Exception as e:
            log.debug(f"dlopen: Error reading path string: {e}")
            return None

    def _find_library(self, lib_path: str) -> str | None:
        """Find the library file in search paths."""
        # Handle /proc/self/fd/N paths (fileless loading via memfd_create)
        if '/proc/self/fd/' in lib_path:
            resolved = self._resolve_procfd_path(lib_path)
            if resolved:
                return resolved

        # If it's an absolute path, check if it exists
        if os.path.isabs(lib_path):
            if os.path.isfile(lib_path):
                return lib_path
            # Try just the filename in search paths
            lib_path = os.path.basename(lib_path)

        # Get search paths from state globals (with class-level fallback)
        search_paths = list(self._get_library_paths())

        # Add preloader paths if available
        preloader = self._get_preloader()
        if preloader:
            search_paths.extend(preloader.get_search_paths())

        # Add current directory
        search_paths.append(".")

        # Search for the library
        for search_dir in search_paths:
            full_path = os.path.join(search_dir, lib_path)
            if os.path.isfile(full_path):
                return os.path.abspath(full_path)

            # Also check without path components
            basename = os.path.basename(lib_path)
            full_path = os.path.join(search_dir, basename)
            if os.path.isfile(full_path):
                return os.path.abspath(full_path)

        # Check preloader's pending libs
        if preloader:
            for pending_lib in preloader.pending_libs:
                if lib_path in pending_lib or os.path.basename(pending_lib) == os.path.basename(lib_path):
                    if os.path.isfile(pending_lib):
                        return pending_lib

        return None

    def _resolve_procfd_path(self, lib_path: str) -> str | None:
        """Resolve /proc/self/fd/N to actual library file via memfd correlation."""
        technique = self._get_technique()
        if not technique or not hasattr(technique, 'memory_tracker') or not technique.memory_tracker:
            return None
        tracker = technique.memory_tracker

        try:
            fd = int(lib_path.rsplit('/', 1)[-1])
        except (ValueError, IndexError):
            return None

        # If this fd is a memfd, find the most recently opened .so file
        if fd in tracker.memfd_files:
            so_files = [
                of for of in tracker.open_files.values()
                if '.so' in of.path and not of.path.startswith('/proc/')
            ]
            if so_files:
                latest = max(so_files, key=lambda f: f.step)
                search_paths = list(self._get_library_paths())
                for d in search_paths:
                    candidate = os.path.join(d, os.path.basename(latest.path))
                    if os.path.isfile(candidate):
                        log.info(f"Resolved memfd path {lib_path} -> {candidate}")
                        return os.path.abspath(candidate)
        return None

    def _load_library(self, lib_path: str) -> int | None:
        """Load a library into the project and state."""
        try:
            # Check if already loaded (read from state globals with fallback)
            loaded_libraries = self._get_loaded_libraries()
            for handle, lib in loaded_libraries.items():
                if hasattr(lib, 'binary') and lib.binary == lib_path:
                    log.debug(f"dlopen: Library already loaded: {lib_path}")
                    return handle

            # Load the library using CLE
            project = self.state.project

            # Find a suitable base address
            base_addr = self._find_base_address()

            # Load the library object
            # dynamic_load can return a list of objects or a single object
            loaded = project.loader.dynamic_load(lib_path)

            if loaded is None:
                log.warning(f"dlopen: CLE failed to load: {lib_path}")
                return None

            # Handle both list and single object returns
            if isinstance(loaded, list):
                if len(loaded) == 0:
                    log.warning(f"dlopen: CLE returned empty list for: {lib_path}")
                    return None
                lib = loaded[0]  # Primary library is first
            else:
                lib = loaded

            # Generate handle (use library's mapped base)
            handle = getattr(lib, 'mapped_base', 0)
            if handle == 0:
                handle = self._get_next_handle()

            # Store in our tracking (update state globals and class-level)
            loaded_libraries[handle] = lib
            DynDlopen.loaded_libraries[handle] = lib

            # Mark as loaded in preloader
            preloader = self._get_preloader()
            if preloader:
                preloader.loaded_libs.add(lib_path)

            log.info(f"dlopen: Successfully loaded {lib_path} at 0x{handle:x}")
            return handle

        except Exception as e:
            log.error(f"dlopen: Exception loading {lib_path}: {e}")
            return None

    def _find_base_address(self) -> int:
        """Find a suitable base address for loading a new library."""
        # Find the highest mapped address
        max_addr = 0
        for obj in self.state.project.loader.all_objects:
            if hasattr(obj, 'max_addr') and obj.max_addr > max_addr:
                max_addr = obj.max_addr

        # Align to page boundary and add some space
        base = ((max_addr + PAGE_ALIGNMENT_GAP) // PAGE_SIZE) * PAGE_SIZE
        return base

    @classmethod
    def _get_next_handle(cls) -> int:
        """Generate a unique handle."""
        handle = cls._handle_counter
        cls._handle_counter += PAGE_SIZE
        return handle

    def _record_for_validation(self, lib_path: str, handle: int | None = None) -> None:
        """Record this dlopen call for hybrid validation with full state."""
        technique = self._get_technique()
        if technique is None:
            return

        # Record detailed library load event with full register state
        try:
            from ..core.library_load_event import LibraryLoadEvent

            # Get flags argument if available
            flags = 0
            try:
                if len(self.arguments) > 1:
                    flags_arg = self.arguments[1]
                    if not self.state.solver.symbolic(flags_arg):
                        flags = self.state.solver.eval(flags_arg)
            except Exception:
                pass

            event = LibraryLoadEvent.from_dlopen(
                state=self.state,
                library_path=lib_path,
                handle=handle,
                flags=flags,
            )

            # Add to technique's event log if available
            if hasattr(technique, 'library_load_log'):
                technique.library_load_log.add_event(event)
                log.debug(f"Recorded library load event: {lib_path} with full state")
        except Exception as e:
            log.debug(f"Failed to create LibraryLoadEvent: {e}")

        # Also record path candidate for validation (original behavior)
        if not hasattr(technique, '_record_path_candidate'):
            return

        try:
            technique._record_path_candidate(
                state=self.state,
                library=lib_path,
                symbol=None,  # dlopen doesn't resolve symbols
                dlopen_addr=self.state.addr,
            )
            log.debug(f"Recorded path candidate for validation: {lib_path}")
        except Exception as e:
            log.debug(f"Failed to record path candidate: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.loaded_libraries = {}
        cls.library_paths = []
        cls.preloader = None
        cls.technique = None
        cls._handle_counter = DEFAULT_HANDLE_BASE
