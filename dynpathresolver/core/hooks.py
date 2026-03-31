"""Hooking mixin for DynPathResolver — platform-specific function hooks."""

import logging
from typing import TYPE_CHECKING

from dynpathresolver.simprocedures import (
    DynDlopen, DynDlsym, DynDlclose,
    DynDlmopen, DynDlvsym, DynDladdr, DynDlinfo, DynDlerror,
    DynTlsGetAddr, DynTlsDescResolver,
)
from dynpathresolver.simprocedures.windows import DynLoadLibraryA, DynLoadLibraryW, DynGetProcAddress
from dynpathresolver.simprocedures.syscalls import (
    DynMmap, DynMunmap, DynMprotect, DynMremap,
    DynOpen, DynOpenat, DynFopen, DynMemfdCreate,
    DynSigaction, DynSignal, DynRaise,
    DynExecve, DynExecveat, DynFexecve,
    DynPrctl, DynPtrace,
    DynProcessVmReadv, DynProcessVmWritev,
    DynClone, DynClone3,
    DynSetenv, DynPutenv, DynUnsetenv, DynGetenv,
    DynSocket, DynConnect, DynBind, DynListen, DynAccept,
    DynRecv, DynRecvfrom, DynSend, DynSendto,
)

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class HookingMixin:
    """Mixin providing platform-specific function hooking."""

    def _hook_linux(self, project: "angr.Project") -> None:
        """Hook dlopen, dlsym, dlclose and extended dl* functions (Linux)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        # Hook the functions
        # These symbols are typically in libc or libdl
        symbols_to_hook = {
            # Core dl* functions
            'dlopen': DynDlopen,
            'dlsym': DynDlsym,
            'dlclose': DynDlclose,
            # Extended dl* functions
            'dlmopen': DynDlmopen,
            'dlvsym': DynDlvsym,
            'dladdr': DynDladdr,
            'dlinfo': DynDlinfo,
            'dlerror': DynDlerror,
            # Internal glibc variant (Phase 2)
            '__libc_dlopen_mode': DynDlopen,
            # TLS support
            '__tls_get_addr': DynTlsGetAddr,
            '_dl_tlsdesc_return': DynTlsDescResolver,
            '_dl_tlsdesc_dynamic': DynTlsDescResolver,
            # File I/O hooks (for .so tracking and anti-debug bypass)
            'fopen': DynFopen,
            'fopen64': DynFopen,
        }

        self._hook_symbols(project, symbols_to_hook)

    def _hook_windows(self, project: "angr.Project") -> None:
        """Hook LoadLibraryA, LoadLibraryW, GetProcAddress, FreeLibrary (Windows)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        symbols_to_hook = {
            'LoadLibraryA': DynLoadLibraryA,
            'LoadLibraryW': DynLoadLibraryW,
            'GetProcAddress': DynGetProcAddress,
            'FreeLibrary': DynDlclose,  # FreeLibrary is similar to dlclose
        }

        self._hook_symbols(project, symbols_to_hook)

    def _hook_symbols(self, project: "angr.Project", symbols_to_hook: dict) -> None:
        """Hook a set of symbols with their corresponding SimProcedures."""
        for sym_name, simproc_class in symbols_to_hook.items():
            # Try to find and hook the symbol
            try:
                # Check if symbol exists in any loaded object
                sym = project.loader.find_symbol(sym_name)
                if sym:
                    # Use replace=True to override angr's default hooks
                    project.hook(sym.rebased_addr, simproc_class(), replace=True)
                    log.info(f"Hooked {sym_name} at 0x{sym.rebased_addr:x}")
                else:
                    # Hook by name for extern resolution
                    project.hook_symbol(sym_name, simproc_class(), replace=True)
                    log.info(f"Hooked {sym_name} by symbol name")
            except Exception as e:
                log.debug(f"Could not hook {sym_name}: {e}")
                # Try hook_symbol as fallback
                try:
                    project.hook_symbol(sym_name, simproc_class(), replace=True)
                    log.info(f"Hooked {sym_name} by symbol name (fallback)")
                except Exception as e2:
                    log.warning(f"Failed to hook {sym_name}: {e2}")

    def _hook_syscalls(self, project: "angr.Project") -> None:
        """Hook syscalls for memory and file operations (Linux)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        syscalls_to_hook = {
            'mmap': DynMmap,
            'mmap64': DynMmap,
            'munmap': DynMunmap,
            'mprotect': DynMprotect,
            'mremap': DynMremap,
            'open': DynOpen,
            'open64': DynOpen,
            'openat': DynOpenat,
            'memfd_create': DynMemfdCreate,
        }

        self._hook_symbols(project, syscalls_to_hook)

    def _hook_signal_functions(self, project: "angr.Project") -> None:
        """Hook signal handling functions (Linux)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        signal_funcs_to_hook = {
            'sigaction': DynSigaction,
            'signal': DynSignal,
            'raise': DynRaise,
        }

        self._hook_symbols(project, signal_funcs_to_hook)

    def _hook_env_functions(self, project: "angr.Project") -> None:
        """Hook environment manipulation functions."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        env_funcs_to_hook = {
            'setenv': DynSetenv,
            'putenv': DynPutenv,
            'unsetenv': DynUnsetenv,
            'getenv': DynGetenv,
        }

        self._hook_symbols(project, env_funcs_to_hook)

    def _hook_exec_functions(self, project: "angr.Project") -> None:
        """Hook process execution functions."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        exec_funcs_to_hook = {
            'execve': DynExecve,
            'execveat': DynExecveat,
            'fexecve': DynFexecve,
            'clone': DynClone,
            'clone3': DynClone3,
        }

        self._hook_symbols(project, exec_funcs_to_hook)

    def _hook_security_functions(self, project: "angr.Project") -> None:
        """Hook security-related functions (prctl, ptrace, process_vm_*)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        security_funcs_to_hook = {
            'prctl': DynPrctl,
            'ptrace': DynPtrace,
            'process_vm_readv': DynProcessVmReadv,
            'process_vm_writev': DynProcessVmWritev,
        }

        self._hook_symbols(project, security_funcs_to_hook)

    def _hook_socket_functions(self, project: "angr.Project") -> None:
        """Hook socket/network functions (Linux)."""
        # SimProcedure configuration is now done via state.globals
        # (see _init_state_globals in technique.py)

        socket_funcs_to_hook = {
            'socket': DynSocket,
            'connect': DynConnect,
            'bind': DynBind,
            'listen': DynListen,
            'accept': DynAccept,
            'accept4': DynAccept,
            'recv': DynRecv,
            'recvfrom': DynRecvfrom,
            'send': DynSend,
            'sendto': DynSendto,
        }

        self._hook_symbols(project, socket_funcs_to_hook)
