"""Unified heuristic predictor combining all detection methods.

This module provides the HeuristicPredictor facade class that orchestrates
multiple detection strategies:
1. String fragment assembly (finding library names in binary)
2. Behavioral pattern analysis (detecting suspicious loading)
3. Environment-based resolution (finding libraries on disk)
4. Symbolic path tracking (following path construction)
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.analysis.string_assembler import StringFragmentAssembler
from dynpathresolver.analysis.pattern_predictor import (
    EnvironmentPredictor,
    PatternPredictor,
    SuspiciousIndicator,
    SuspiciousPath,
)
from dynpathresolver.analysis.behavior_analyzer import (
    BehavioralPatternAnalyzer,
    LoadBehaviorDetector,
)

log = logging.getLogger(__name__)


class HeuristicPredictor:
    """
    Unified predictor combining all heuristic methods.

    This class orchestrates multiple detection strategies:
    1. String fragment assembly (finding library names in binary)
    2. Behavioral pattern analysis (detecting suspicious loading)
    3. Environment-based resolution (finding libraries on disk)
    4. Symbolic path tracking (following path construction)
    """

    def __init__(self, project: "angr.Project", platform: str, library_paths: list[str]):
        self.project = project
        self.platform = platform
        self.fragment_assembler = StringFragmentAssembler(project, platform)
        self.env_predictor = EnvironmentPredictor(platform, library_paths)
        self.pattern_predictor = PatternPredictor(project, platform)

        # Additional behavioral analyzers
        self.behavior_analyzer = BehavioralPatternAnalyzer(project, platform)
        self.load_detector = LoadBehaviorDetector(project)

        # Store analysis results
        self.all_analyzed_paths: list[SuspiciousPath] = []

    def predict(self) -> dict[str, str]:
        """
        Run all prediction methods and return resolved libraries.

        Returns:
            Dict mapping library name to resolved filesystem path
        """
        candidates: set[str] = set()

        # Gather candidates from fragment assembly
        try:
            fragment_candidates = self.fragment_assembler.find_candidate_names()
            candidates.update(fragment_candidates)
            log.debug(f"Fragment assembler found {len(fragment_candidates)} candidates")
        except Exception as e:
            log.debug(f"Fragment assembly failed: {e}")

        # Gather candidates from pattern analysis (now behavioral)
        try:
            pattern_candidates = self.pattern_predictor.analyze()
            candidates.update(pattern_candidates)
            log.debug(f"Pattern predictor found {len(pattern_candidates)} candidates")

            # Collect analyzed paths from pattern predictor
            self.all_analyzed_paths.extend(self.pattern_predictor.analyzed_paths)
        except Exception as e:
            log.debug(f"Pattern analysis failed: {e}")

        # Gather candidates from load behavior detection
        try:
            load_detections = self.load_detector.get_detected_loads()
            for detection in load_detections:
                candidates.add(detection.path)
                self.all_analyzed_paths.append(detection)
            log.debug(f"Load detector found {len(load_detections)} candidates")
        except Exception as e:
            log.debug(f"Load detection failed: {e}")

        # Resolve candidates against filesystem
        resolved = self.env_predictor.find_all_matches(candidates)
        log.info(f"Heuristic prediction resolved {len(resolved)} libraries "
                f"from {len(candidates)} candidates")

        return resolved

    def predict_with_analysis(self) -> tuple[dict[str, str], list[SuspiciousPath]]:
        """
        Run prediction and return both resolved paths and full analysis.

        Returns:
            Tuple of (resolved_dict, list of SuspiciousPath analysis)
        """
        resolved = self.predict()
        return resolved, self.all_analyzed_paths

    def analyze_runtime_path(self, state: "angr.SimState",
                              path: str, call_type: str = 'dlopen') -> SuspiciousPath:
        """
        Analyze a path discovered at runtime during symbolic execution.

        This is called by SimProcedures when they intercept a dlopen/LoadLibrary.

        Args:
            state: The angr state at the call
            path: The library path being loaded
            call_type: Type of call ('dlopen', 'LoadLibraryA', etc.)

        Returns:
            SuspiciousPath with full analysis
        """
        context = {
            'source': f'runtime_{call_type}',
            'call_addr': state.addr,
            'history_depth': state.history.depth,
        }

        # Analyze the path
        analysis = self.pattern_predictor.analyze_dlopen_call(state, path)

        # Store for later retrieval
        self.all_analyzed_paths.append(analysis)

        return analysis

    def get_suspicious_discoveries(self, min_score: float = 0.3) -> list[SuspiciousPath]:
        """
        Get all discovered paths that appear suspicious.

        Args:
            min_score: Minimum suspicion score threshold

        Returns:
            List of suspicious paths above threshold
        """
        return [p for p in self.all_analyzed_paths
                if p.suspicion_score() >= min_score]

    def get_threat_summary(self) -> dict:
        """
        Get a summary of detected threats by category.

        Returns:
            Dict with threat categories and counts
        """
        summary = {
            'total_paths': len(self.all_analyzed_paths),
            'suspicious_paths': 0,
            'by_indicator': {},
            'high_risk_paths': [],
        }

        for path in self.all_analyzed_paths:
            if path.is_suspicious():
                summary['suspicious_paths'] += 1

            for indicator in path.indicators:
                key = indicator.name
                summary['by_indicator'][key] = summary['by_indicator'].get(key, 0) + 1

            if path.suspicion_score() >= 0.7:
                summary['high_risk_paths'].append({
                    'path': path.path,
                    'score': path.suspicion_score(),
                    'indicators': [i.name for i in path.indicators],
                })

        return summary

    def record_syscall(self, state: "angr.SimState",
                        syscall: str, args: dict) -> None:
        """
        Record a syscall for behavioral analysis.

        Args:
            state: Current angr state
            syscall: Syscall name
            args: Syscall arguments
        """
        if syscall == 'open' or syscall == 'openat':
            path = args.get('path', '')
            flags = args.get('flags', 0)
            fd = args.get('fd', -1)
            if fd >= 0:
                self.load_detector.record_open(state, path, flags, fd)

        elif syscall == 'mmap':
            self.load_detector.record_mmap(
                state,
                args.get('addr', 0),
                args.get('length', 0),
                args.get('prot', 0),
                args.get('flags', 0),
                args.get('fd', -1),
            )

        elif syscall == 'memfd_create':
            self.load_detector.record_memfd_create(
                state,
                args.get('name', ''),
                args.get('fd', -1),
            )
