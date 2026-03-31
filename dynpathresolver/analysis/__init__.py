"""Analysis components including predictors and control flow."""

from .predictor import (
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
from .control_flow import (
    IndirectFlowEvent,
    RopGadget,
    RopChain,
    JopGadget,
    JopChain,
    IndirectFlowTracker,
    RopDetector,
    JopDetector,
)

__all__ = [
    # Predictor classes
    "SuspiciousIndicator",
    "SuspiciousPath",
    "StringFragmentAssembler",
    "EnvironmentPredictor",
    "BehavioralPatternAnalyzer",
    "SymbolicPathTracker",
    "LoadBehaviorDetector",
    "PatternPredictor",
    "HeuristicPredictor",
    # Control flow classes
    "IndirectFlowEvent",
    "RopGadget",
    "RopChain",
    "JopGadget",
    "JopChain",
    "IndirectFlowTracker",
    "RopDetector",
    "JopDetector",
]
