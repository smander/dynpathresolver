"""
SimProcedure for dlmopen() - load library into separate namespace.

dlmopen allows loading libraries into a separate link-map namespace,
providing isolation between different versions of the same library.
"""

import logging

import angr
import claripy

from dynpathresolver.config.constants import LM_ID_BASE, LM_ID_NEWLM
from .dlopen import DynDlopen

log = logging.getLogger(__name__)


class DynDlmopen(angr.SimProcedure):
    """
    SimProcedure for dlmopen that loads libraries into namespaces.

    Signature: void* dlmopen(Lmid_t lmid, const char *filename, int flags)

    This procedure:
    1. Gets the namespace ID (lmid)
    2. Reads the library filename
    3. Loads the library (using DynDlopen infrastructure)
    4. Returns a handle to the loaded library

    Note: For simplicity, all namespaces share the same library tracking.
    True namespace isolation would require separate symbol resolution contexts.
    """

    # Track namespace assignments: namespace_id -> list of handles
    namespaces: dict[int, list[int]] = {LM_ID_BASE: []}

    # Counter for new namespace IDs
    _namespace_counter: int = 1

    def run(self, lmid, path_ptr, flags):
        """
        Simulate dlmopen(lmid, path, flags).

        Args:
            lmid: Namespace ID (LM_ID_BASE, LM_ID_NEWLM, or existing namespace)
            path_ptr: Pointer to library path string
            flags: dlopen-style flags (RTLD_NOW, RTLD_LAZY, etc.)

        Returns:
            Handle to loaded library, or NULL (0) on failure
        """
        # Concretize lmid
        if self.state.solver.symbolic(lmid):
            if self.state.solver.satisfiable():
                lmid_val = self.state.solver.eval(lmid)
            else:
                log.warning("dlmopen: Symbolic lmid, cannot resolve")
                return claripy.BVS("dlmopen_handle", self.state.arch.bits)
        else:
            lmid_val = self.state.solver.eval(lmid)

        # Handle signed comparison for LM_ID_NEWLM (-1)
        if lmid_val > 0x7FFFFFFF:
            lmid_val = -1

        # Read namespaces from state.globals
        namespaces = self.state.globals.get('dpr_dlmopen_namespaces', self.__class__.namespaces)

        # Determine namespace
        if lmid_val == LM_ID_NEWLM:
            # Create new namespace
            namespace_id = self._create_namespace()
            log.info(f"dlmopen: Created new namespace {namespace_id}")
        elif lmid_val == LM_ID_BASE:
            namespace_id = LM_ID_BASE
        else:
            # Use existing namespace
            namespace_id = lmid_val
            if namespace_id not in namespaces:
                log.warning(f"dlmopen: Unknown namespace {namespace_id}, using base")
                namespace_id = LM_ID_BASE

        # Get library path
        lib_path = self._get_library_path(path_ptr)

        if lib_path is None:
            log.warning("dlmopen: Could not resolve library path (symbolic)")
            return claripy.BVS("dlmopen_handle", self.state.arch.bits)

        log.info(f"dlmopen: Loading '{lib_path}' into namespace {namespace_id}")

        # Use DynDlopen's library finding and loading logic
        resolved_path = self._find_library(lib_path)

        if resolved_path is None:
            log.warning(f"dlmopen: Library not found: {lib_path}")
            DlError.set_error(f"dlmopen: {lib_path}: cannot open shared object file", self.state)
            return claripy.BVV(0, self.state.arch.bits)

        # Load the library
        handle = self._load_library(resolved_path)

        if handle is None:
            log.warning(f"dlmopen: Failed to load library: {resolved_path}")
            DlError.set_error(f"dlmopen: {resolved_path}: failed to load", self.state)
            return claripy.BVV(0, self.state.arch.bits)

        # Track in namespace (via state.globals)
        namespaces = self.state.globals.get('dpr_dlmopen_namespaces', self.__class__.namespaces)
        if namespace_id not in namespaces:
            namespaces[namespace_id] = []
        namespaces[namespace_id].append(handle)
        self.state.globals['dpr_dlmopen_namespaces'] = namespaces

        log.info(f"dlmopen: Loaded '{resolved_path}' at handle 0x{handle:x} in namespace {namespace_id}")
        return claripy.BVV(handle, self.state.arch.bits)

    def _get_library_path(self, path_ptr) -> str | None:
        """Extract library path string from memory."""
        if self.state.solver.symbolic(path_ptr):
            if self.state.solver.satisfiable():
                path_ptr = self.state.solver.eval(path_ptr)
            else:
                return None

        try:
            path_bytes = self.state.mem[path_ptr].string.concrete
            if isinstance(path_bytes, bytes):
                return path_bytes.decode('utf-8', errors='ignore')
            return str(path_bytes)
        except Exception as e:
            log.debug(f"dlmopen: Error reading path string: {e}")
            return None

    def _find_library(self, lib_path: str) -> str | None:
        """Find library using DynDlopen's search logic."""
        # Create temporary instance to use its method
        dlopen = DynDlopen(
            project=self.state.project,
            cc=self.cc,
            prototype=self.prototype,
        )
        dlopen.state = self.state
        return dlopen._find_library(lib_path)

    def _load_library(self, lib_path: str) -> int | None:
        """Load library using DynDlopen's loading logic."""
        dlopen = DynDlopen(
            project=self.state.project,
            cc=self.cc,
            prototype=self.prototype,
        )
        dlopen.state = self.state
        return dlopen._load_library(lib_path)

    def _create_namespace(self) -> int:
        """Create a new namespace and return its ID (using state.globals)."""
        namespaces = self.state.globals.get('dpr_dlmopen_namespaces', self.__class__.namespaces)
        namespace_id = self.__class__._namespace_counter
        self.__class__._namespace_counter += 1
        namespaces[namespace_id] = []
        self.state.globals['dpr_dlmopen_namespaces'] = namespaces
        return namespace_id

    @classmethod
    def get_namespace(cls, handle: int, state=None) -> int | None:
        """Get the namespace ID for a given handle (per-state if state provided)."""
        if state is not None:
            namespaces = state.globals.get('dpr_dlmopen_namespaces', cls.namespaces)
        else:
            namespaces = cls.namespaces
        for ns_id, handles in namespaces.items():
            if handle in handles:
                return ns_id
        return None

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.namespaces = {LM_ID_BASE: []}
        cls._namespace_counter = 1


# Import DlError for error tracking (will be defined in dlerror.py)
try:
    from .dlerror import DlError
except ImportError:
    # Stub if dlerror not yet implemented
    class DlError:
        @classmethod
        def set_error(cls, msg: str, state=None):
            pass
