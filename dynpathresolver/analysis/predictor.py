"""Backward-compatibility re-exports from analysis submodules."""
from dynpathresolver.analysis.string_assembler import StringFragmentAssembler  # noqa: F401
from dynpathresolver.analysis.pattern_predictor import (  # noqa: F401
    SuspiciousIndicator,
    SuspiciousPath,
    PatternPredictor,
    EnvironmentPredictor,
)
from dynpathresolver.analysis.behavior_analyzer import (  # noqa: F401
    BehavioralPatternAnalyzer,
    SymbolicPathTracker,
    LoadBehaviorDetector,
)
from dynpathresolver.analysis.heuristic_predictor import HeuristicPredictor  # noqa: F401
