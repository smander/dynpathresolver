"""Core analysis engine components."""

from .technique import DynPathResolver
from .resolver import SpeculativeResolver
from .interceptor import EventInterceptor
from .discovery_log import DiscoveryLog
from .recursive_analyzer import RecursiveLibraryAnalyzer, LibraryLoadSite, DiscoveryChain
from .directed import DirectedAnalyzer, DirectedExploration
from .cfg_builder import (
    CompleteCFGBuilder,
    CompleteCFG,
    CompleteCFGNode,
    CompleteCFGEdge,
    RegisterState,
    Instruction,
    EdgeType,
)
from .library_load_event import (
    LibraryLoadEvent,
    LibraryLoadLog,
    RegisterSnapshot,
    MemoryRegion,
)
from dynpathresolver.config.enums import LoadingMethod

__all__ = [
    "DynPathResolver",
    "SpeculativeResolver",
    "EventInterceptor",
    "DiscoveryLog",
    "RecursiveLibraryAnalyzer",
    "LibraryLoadSite",
    "DiscoveryChain",
    "DirectedAnalyzer",
    "DirectedExploration",
    # CFG Builder
    "CompleteCFGBuilder",
    "CompleteCFG",
    "CompleteCFGNode",
    "CompleteCFGEdge",
    "RegisterState",
    "Instruction",
    "EdgeType",
    # Library Load Events
    "LibraryLoadEvent",
    "LibraryLoadLog",
    "RegisterSnapshot",
    "MemoryRegion",
    "LoadingMethod",
]
