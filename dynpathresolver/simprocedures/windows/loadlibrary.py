"""SimProcedures for LoadLibraryA and LoadLibraryW."""
import os
import logging
from typing import Any
import angr
import claripy

log = logging.getLogger(__name__)

class DynLoadLibraryA(angr.SimProcedure):
    """SimProcedure for LoadLibraryA (ANSI version)."""
    loaded_libraries: dict[int, Any] = {}
    library_paths: list[str] = []

    @classmethod
    def reset(cls):
        cls.loaded_libraries = {}
        cls.library_paths = []

    def _get_library_paths(self):
        if self.state is not None:
            return self.state.globals.get('dpr_library_paths', self.__class__.library_paths)
        return self.__class__.library_paths

    def _get_loaded_libraries(self):
        if self.state is not None:
            return self.state.globals.get('dpr_win_loaded_libraries', self.__class__.loaded_libraries)
        return self.__class__.loaded_libraries

    def run(self, lpLibFileName):
        """
        Simulate LoadLibraryA(lpLibFileName).

        Args:
            lpLibFileName: Pointer to ANSI library name string

        Returns:
            Handle to loaded module, or NULL (0) on failure
        """
        lib_name = self._get_string_ansi(lpLibFileName)
        if not lib_name:
            return claripy.BVV(0, self.state.arch.bits)

        resolved = self._find_library(lib_name)
        if not resolved:
            return claripy.BVV(0, self.state.arch.bits)

        handle = self._load_library(resolved)
        return claripy.BVV(handle or 0, self.state.arch.bits)

    def _get_string_ansi(self, ptr) -> str | None:
        if self.state.solver.symbolic(ptr):
            return None
        try:
            addr = self.state.solver.eval(ptr)
            s = self.state.mem[addr].string.concrete
            return s.decode('ascii', errors='ignore') if isinstance(s, bytes) else str(s)
        except Exception:
            return None

    def _find_library(self, lib_name: str) -> str | None:
        search_paths = list(self._get_library_paths()) + ['.', '/lib']
        for path in search_paths:
            candidate = os.path.join(path, lib_name)
            if os.path.exists(candidate):
                return os.path.abspath(candidate)
            candidate = os.path.join(path, os.path.basename(lib_name))
            if os.path.exists(candidate):
                return os.path.abspath(candidate)
        return None

    def _load_library(self, lib_path: str) -> int | None:
        try:
            loaded = self.state.project.loader.dynamic_load(lib_path)
            lib = loaded[0] if isinstance(loaded, list) else loaded
            if lib:
                handle = getattr(lib, 'mapped_base', 0)
                loaded = self._get_loaded_libraries()
                loaded[handle] = lib
                return handle
        except Exception as e:
            log.warning(f"Error loading {lib_path}: {e}")
        return None

class DynLoadLibraryW(DynLoadLibraryA):
    """SimProcedure for LoadLibraryW (Unicode version)."""
    def run(self, lpLibFileName):
        """
        Simulate LoadLibraryW(lpLibFileName).

        Args:
            lpLibFileName: Pointer to Unicode (wide) library name string

        Returns:
            Handle to loaded module, or NULL (0) on failure
        """
        lib_name = self._get_string_unicode(lpLibFileName)
        if not lib_name:
            return claripy.BVV(0, self.state.arch.bits)
        resolved = self._find_library(lib_name)
        if not resolved:
            return claripy.BVV(0, self.state.arch.bits)
        handle = self._load_library(resolved)
        return claripy.BVV(handle or 0, self.state.arch.bits)

    def _get_string_unicode(self, ptr) -> str | None:
        if self.state.solver.symbolic(ptr):
            return None
        try:
            addr = self.state.solver.eval(ptr)
            chars = []
            for i in range(256):
                word = self.state.memory.load(addr + i*2, 2, endness='Iend_LE')
                if self.state.solver.symbolic(word):
                    break
                val = self.state.solver.eval(word)
                if val == 0:
                    break
                chars.append(chr(val))
            return ''.join(chars) if chars else None
        except Exception:
            return None
