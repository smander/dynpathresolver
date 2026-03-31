"""SimProcedures for dynamic library loading."""

from .dlopen import DynDlopen
from .dlsym import DynDlsym
from .dlclose import DynDlclose
from .dlmopen import DynDlmopen
from .dlvsym import DynDlvsym
from .dladdr import DynDladdr
from .dlinfo import DynDlinfo
from .dlerror import DynDlerror, DlError
from .tls import DynTlsGetAddr, DynTlsDescResolver, TLSManager

__all__ = [
    # Core dl* functions
    "DynDlopen",
    "DynDlsym",
    "DynDlclose",
    # Extended dl* functions
    "DynDlmopen",
    "DynDlvsym",
    "DynDladdr",
    "DynDlinfo",
    "DynDlerror",
    "DlError",
    # TLS support
    "DynTlsGetAddr",
    "DynTlsDescResolver",
    "TLSManager",
]
