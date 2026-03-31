"""State tracking components."""

from .memory_tracker import MemoryRegionTracker, MappedRegion, OpenFile
from .taint_tracker import TaintTracker, TaintedControlFlow, TaintedLibraryPath
from .shadow_memory import ShadowMemory, ByteMetadata, TaintSource
from .stage_tracker import StageTracker, StageSource, PayloadStage, StageTransition
from .env_tracker import EnvironmentTracker, EnvironmentVariable, LdPreloadEntry, LdAuditEntry
from .ifunc_tracker import IFuncTracker, IFuncSymbol, IFuncResolution
from .init_tracker import InitFiniTracker, InitFunction, InitExecution
from .process_tracker import ProcessExecutionTracker, ExecutedProgram, ClonedProcess
from .security_tracker import SecurityPolicyTracker, PrctlEvent, PtraceEvent, SecurityPolicyChange
from .signal_handler import SignalHandlerTracker, SignalHandler, SignalEvent

__all__ = [
    # Memory tracker
    "MemoryRegionTracker",
    "MappedRegion",
    "OpenFile",
    # Taint tracker
    "TaintTracker",
    "TaintedControlFlow",
    "TaintedLibraryPath",
    # Shadow memory
    "ShadowMemory",
    "ByteMetadata",
    "TaintSource",
    # Stage tracker
    "StageTracker",
    "StageSource",
    "PayloadStage",
    "StageTransition",
    # Environment tracker
    "EnvironmentTracker",
    "EnvironmentVariable",
    "LdPreloadEntry",
    "LdAuditEntry",
    # IFunc tracker
    "IFuncTracker",
    "IFuncSymbol",
    "IFuncResolution",
    # Init/Fini tracker
    "InitFiniTracker",
    "InitFunction",
    "InitExecution",
    # Process tracker
    "ProcessExecutionTracker",
    "ExecutedProgram",
    "ClonedProcess",
    # Security tracker
    "SecurityPolicyTracker",
    "PrctlEvent",
    "PtraceEvent",
    "SecurityPolicyChange",
    # Signal handler
    "SignalHandlerTracker",
    "SignalHandler",
    "SignalEvent",
]
