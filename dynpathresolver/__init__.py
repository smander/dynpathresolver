"""DynPathResolver - Dynamic-assisted CFG recovery for angr."""

# Core components
from dynpathresolver.core import (
    DynPathResolver,
    SpeculativeResolver,
    EventInterceptor,
    DiscoveryLog,
    RecursiveLibraryAnalyzer,
    LibraryLoadSite,
    DiscoveryChain,
    DirectedAnalyzer,
    DirectedExploration,
    # CFG Builder
    CompleteCFGBuilder,
    CompleteCFG,
    CompleteCFGNode,
    CompleteCFGEdge,
    RegisterState,
    EdgeType,
)

# ELF components
from dynpathresolver.elf import (
    LibraryPreloader,
    VtableResolver,
    CFGPatcher,
    PlatformDetector,
)

# Validation components
from dynpathresolver.validation import (
    ValidationStatus,
    ValidationResult,
    PathCandidate,
    HybridValidator,
    FridaValidator,
)

# LoadingMethod from canonical source
from dynpathresolver.config.enums import LoadingMethod

# Analysis components
from dynpathresolver.analysis import (
    SuspiciousIndicator,
    SuspiciousPath,
    StringFragmentAssembler,
    EnvironmentPredictor,
    BehavioralPatternAnalyzer,
    SymbolicPathTracker,
    LoadBehaviorDetector,
    PatternPredictor,
    HeuristicPredictor,
)

# Detection components
from dynpathresolver.detection import (
    GuardType,
    Guard,
    GuardDetector,
    GuardPatcher,
    UnpackingDetector,
    UnpackingHandler,
)

# Simprocedures
from dynpathresolver.simprocedures import DynDlopen, DynDlsym, DynDlclose
from dynpathresolver.simprocedures.windows import DynLoadLibraryA, DynLoadLibraryW, DynGetProcAddress

# Config components
from dynpathresolver.config.settings import DynPathResolverConfig
from dynpathresolver.config.enums import ValidationMode, Platform

__version__ = "0.1.0"

__all__ = [
    # Core
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
    "EdgeType",
    # ELF
    "LibraryPreloader",
    "VtableResolver",
    "CFGPatcher",
    "PlatformDetector",
    # Validation
    "ValidationStatus",
    "ValidationResult",
    "LoadingMethod",
    "PathCandidate",
    "HybridValidator",
    "FridaValidator",
    # Analysis
    "SuspiciousIndicator",
    "SuspiciousPath",
    "StringFragmentAssembler",
    "EnvironmentPredictor",
    "BehavioralPatternAnalyzer",
    "SymbolicPathTracker",
    "LoadBehaviorDetector",
    "PatternPredictor",
    "HeuristicPredictor",
    # Detection
    "GuardType",
    "Guard",
    "GuardDetector",
    "GuardPatcher",
    "UnpackingDetector",
    "UnpackingHandler",
    # Simprocedures
    "DynDlopen",
    "DynDlsym",
    "DynDlclose",
    "DynLoadLibraryA",
    "DynLoadLibraryW",
    "DynGetProcAddress",
    # Config
    "DynPathResolverConfig",
    "ValidationMode",
    "Platform",
]
