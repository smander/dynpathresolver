"""SimProcedures for syscall-level library loading detection."""

from .mmap import DynMmap, DynMunmap
from .mprotect import DynMprotect
from .mremap import DynMremap
from .open import DynOpen, DynOpenat
from .fopen import DynFopen
from .memfd import DynMemfdCreate
from .signal import DynSigaction, DynSignal, DynRaise
from .exec import DynExecve, DynExecveat, DynFexecve
from .prctl import DynPrctl
from .ptrace import DynPtrace
from .process_vm import DynProcessVmReadv, DynProcessVmWritev
from .clone import DynClone, DynClone3
from .env import DynSetenv, DynPutenv, DynUnsetenv, DynGetenv
from .socket import (
    DynSocket, DynConnect, DynBind, DynListen, DynAccept,
    DynRecv, DynRecvfrom, DynSend, DynSendto,
)

__all__ = [
    # Memory mapping
    "DynMmap",
    "DynMunmap",
    "DynMprotect",
    "DynMremap",
    # File operations
    "DynOpen",
    "DynOpenat",
    "DynFopen",
    # Fileless loading
    "DynMemfdCreate",
    # Signal handling
    "DynSigaction",
    "DynSignal",
    "DynRaise",
    # Process execution
    "DynExecve",
    "DynExecveat",
    "DynFexecve",
    # Security/anti-debug
    "DynPrctl",
    "DynPtrace",
    # Cross-process operations
    "DynProcessVmReadv",
    "DynProcessVmWritev",
    # Process/thread creation
    "DynClone",
    "DynClone3",
    # Environment manipulation
    "DynSetenv",
    "DynPutenv",
    "DynUnsetenv",
    "DynGetenv",
    # Socket/network operations
    "DynSocket",
    "DynConnect",
    "DynBind",
    "DynListen",
    "DynAccept",
    "DynRecv",
    "DynRecvfrom",
    "DynSend",
    "DynSendto",
]
