#!/usr/bin/env python3
"""
run_evaluation.py - Comprehensive evaluation suite for DynPathResolver

This script runs all evaluation benchmarks and generates metrics for the research paper.

Usage:
    python run_evaluation.py [--output-dir DIR] [--benchmarks DIR] [--symbolic-steps N]

Output:
    - results.json: Detailed per-benchmark results
    - summary.csv: Summary statistics
    - results_table.tex: LaTeX table for paper
    - detection_table.tex: LaTeX table for detection features
"""

import argparse
import gc
import json
import csv
import os
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional
from pathlib import Path

import angr

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dynpathresolver import DynPathResolver
from dynpathresolver.simprocedures import DynDlopen, DynDlsym, DynDlclose


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class MemoryTrackingMetrics:
    """Metrics from syscall-level memory tracking."""
    total_mmaps: int = 0
    total_mprotects: int = 0
    total_opens: int = 0
    executable_regions: int = 0
    wx_transitions: int = 0
    manual_library_loads: int = 0
    file_backed_regions: int = 0
    memfd_count: int = 0


@dataclass
class ControlFlowMetrics:
    """Metrics from indirect control flow tracking."""
    total_indirect_calls: int = 0
    total_indirect_jumps: int = 0
    total_returns: int = 0
    dynamic_code_calls: int = 0
    has_dynamic_execution: bool = False


@dataclass
class RopJopMetrics:
    """Metrics from ROP/JOP detection."""
    rop_chains_detected: int = 0
    jop_chains_detected: int = 0
    total_gadgets_found: int = 0
    suspicious_returns: int = 0


@dataclass
class SignalMetrics:
    """Metrics from signal handler tracking."""
    handlers_registered: int = 0
    signals_raised: int = 0
    has_signal_based_loading: bool = False
    handler_addresses: List[int] = field(default_factory=list)


@dataclass
class DetectionMetrics:
    """Combined detection metrics from symbolic execution."""
    memory: MemoryTrackingMetrics = field(default_factory=MemoryTrackingMetrics)
    control_flow: ControlFlowMetrics = field(default_factory=ControlFlowMetrics)
    rop_jop: RopJopMetrics = field(default_factory=RopJopMetrics)
    signals: SignalMetrics = field(default_factory=SignalMetrics)

    # Execution info
    symbolic_steps: int = 0
    active_states: int = 0
    deadended_states: int = 0
    execution_time: float = 0.0


@dataclass
class BenchmarkResult:
    """Results from analyzing a single benchmark."""
    name: str
    binary_path: str

    # Static analysis metrics (baseline)
    static_objects: int
    static_functions: int
    static_cfg_nodes: int
    static_cfg_edges: int
    static_payload_visible: bool
    static_symbols_found: int
    static_time_seconds: float

    # DynPathResolver metrics
    dynpath_objects: int
    dynpath_functions: int
    dynpath_cfg_nodes: int
    dynpath_cfg_edges: int
    dynpath_payload_visible: bool
    dynpath_symbols_found: int
    dynpath_libraries_loaded: int
    dynpath_time_seconds: float

    # Improvement metrics
    edge_increase: int
    edge_increase_percent: float
    symbol_increase: int
    overhead_percent: float

    # Ground truth (if available)
    ground_truth_edges: Optional[int] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None

    # Detection metrics from symbolic execution
    detection: Optional[DetectionMetrics] = None

    # Error tracking
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class EvaluationSummary:
    """Summary statistics across all benchmarks."""
    total_benchmarks: int
    successful_benchmarks: int
    failed_benchmarks: int

    # CFG recovery metrics
    avg_edge_increase: float
    avg_edge_increase_percent: float
    avg_symbol_increase: float
    avg_overhead_percent: float

    total_static_edges: int
    total_dynpath_edges: int
    total_new_edges: int

    avg_precision: Optional[float]
    avg_recall: Optional[float]
    avg_f1: Optional[float]

    # Detection metrics summary
    benchmarks_with_detection: int = 0
    total_indirect_calls: int = 0
    total_wx_transitions: int = 0
    total_rop_chains: int = 0
    total_jop_chains: int = 0
    total_signal_handlers: int = 0
    benchmarks_with_dynamic_code: int = 0
    benchmarks_with_signal_loading: int = 0


# =============================================================================
# Benchmark Evaluator
# =============================================================================

class BenchmarkEvaluator:
    """Evaluates a single benchmark binary."""

    def __init__(self, binary_path: str, lib_dir: str = None,
                 payload_symbols: List[str] = None,
                 ground_truth_edges: int = None,
                 ground_truth: Dict = None):
        self.binary_path = binary_path
        self.lib_dir = lib_dir or os.path.dirname(binary_path)
        self.payload_symbols = payload_symbols or []
        self.ground_truth_edges = ground_truth_edges
        self.ground_truth = ground_truth or {}
        self.name = os.path.basename(os.path.dirname(binary_path))

    def run_static_analysis(self) -> Dict:
        """Run pure static analysis without DynPathResolver (baseline)."""
        start_time = time.time()

        try:
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Build CFG
            cfg = project.analyses.CFGFast()

            # Count objects
            objects = len(project.loader.all_objects)

            # Check for payload library
            payload_visible = any(
                'payload' in str(obj.binary).lower() or 'secret' in str(obj.binary).lower()
                for obj in project.loader.all_objects
            )

            # Check for payload symbols
            symbols_found = 0
            for sym_name in self.payload_symbols:
                if project.loader.find_symbol(sym_name):
                    symbols_found += 1

            elapsed = time.time() - start_time

            return {
                'objects': objects,
                'functions': len(cfg.kb.functions),
                'cfg_nodes': len(cfg.graph.nodes()),
                'cfg_edges': len(cfg.graph.edges()),
                'payload_visible': payload_visible,
                'symbols_found': symbols_found,
                'time': elapsed,
                'error': None
            }

        except Exception as e:
            return {
                'objects': 0,
                'functions': 0,
                'cfg_nodes': 0,
                'cfg_edges': 0,
                'payload_visible': False,
                'symbols_found': 0,
                'time': time.time() - start_time,
                'error': str(e)
            }

    def run_dynpath_analysis(self) -> Dict:
        """Run analysis with DynPathResolver (dlopen-aware CFG recovery)."""
        start_time = time.time()

        try:
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Reset and configure DynDlopen
            DynDlopen.reset()
            DynDlopen.library_paths = [self.lib_dir, os.path.abspath(self.lib_dir)]

            # Simulate dlopen call to load payload library
            state = project.factory.blank_state()
            dlopen_proc = DynDlopen()
            dlopen_proc.state = state

            # Try to load payload libraries
            for lib_name in ['libpayload.so', 'libsecret.so', 'libplugin.so']:
                lib_path = os.path.join(self.lib_dir, lib_name)
                if os.path.exists(lib_path):
                    try:
                        dlopen_proc._load_library(lib_path)
                    except:
                        pass

            # Count objects after loading
            objects = len(project.loader.all_objects)

            # Check for payload library
            payload_visible = any(
                'payload' in str(obj.binary).lower() or 'secret' in str(obj.binary).lower()
                for obj in project.loader.all_objects
            )

            # Build CFG
            cfg = project.analyses.CFGFast()

            # Check for payload symbols
            symbols_found = 0
            for sym_name in self.payload_symbols:
                if project.loader.find_symbol(sym_name):
                    symbols_found += 1

            # Count loaded libraries
            libraries_loaded = len(DynDlopen.loaded_libraries)

            elapsed = time.time() - start_time

            return {
                'objects': objects,
                'functions': len(cfg.kb.functions),
                'cfg_nodes': len(cfg.graph.nodes()),
                'cfg_edges': len(cfg.graph.edges()),
                'payload_visible': payload_visible,
                'symbols_found': symbols_found,
                'libraries_loaded': libraries_loaded,
                'time': elapsed,
                'error': None
            }

        except Exception as e:
            return {
                'objects': 0,
                'functions': 0,
                'cfg_nodes': 0,
                'cfg_edges': 0,
                'payload_visible': False,
                'symbols_found': 0,
                'libraries_loaded': 0,
                'time': time.time() - start_time,
                'error': str(e)
            }

    def run_detection_analysis(self, max_steps: int = 100) -> DetectionMetrics:
        """
        Run detection analysis with symbolic execution.

        This evaluates detection features:
        - Syscall-level memory tracking (mmap, mprotect, W->X)
        - Indirect control flow tracking
        - ROP/JOP detection
        - Signal handler tracking
        """
        start_time = time.time()
        metrics = DetectionMetrics()

        try:
            project = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={'main_opts': {'base_addr': 0x400000}}
            )

            # Create DynPathResolver with all detection features enabled
            technique = DynPathResolver(
                library_paths=[self.lib_dir],
                handle_syscall_loading=True,
                track_indirect_flow=True,
                detect_rop=True,
                detect_jop=True,
                track_signals=True,
                path_predictor='heuristic',
            )

            # Create simulation manager with memory-efficient options
            state = project.factory.entry_state(
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                }
            )
            simgr = project.factory.simgr(state)
            simgr.use_technique(technique)

            # Run symbolic execution
            steps = 0
            while len(simgr.active) > 0 and steps < max_steps:
                simgr.step()
                steps += 1

            metrics.symbolic_steps = steps
            metrics.active_states = len(simgr.active)
            metrics.deadended_states = len(simgr.deadended) if hasattr(simgr, 'deadended') else 0

            # Collect memory tracking metrics
            if technique.memory_tracker:
                stats = technique.memory_tracker.get_statistics()
                metrics.memory = MemoryTrackingMetrics(
                    total_mmaps=stats.get('total_mmaps', 0),
                    total_mprotects=stats.get('total_mprotects', 0),
                    total_opens=stats.get('total_opens', 0),
                    executable_regions=len(technique.get_executable_regions()),
                    wx_transitions=len(technique.memory_tracker.get_wx_transitions()),
                    manual_library_loads=len(technique.get_manual_library_loads()),
                    file_backed_regions=len(technique.memory_tracker.get_file_backed_regions()),
                    memfd_count=stats.get('memfd_count', 0),
                )

            # Collect control flow metrics
            if technique.indirect_flow_tracker:
                stats = technique.indirect_flow_tracker.get_statistics()
                metrics.control_flow = ControlFlowMetrics(
                    total_indirect_calls=stats.get('total_indirect_calls', 0),
                    total_indirect_jumps=stats.get('total_indirect_jumps', 0),
                    total_returns=stats.get('total_returns', 0),
                    dynamic_code_calls=len(technique.get_dynamic_calls()),
                    has_dynamic_execution=technique.indirect_flow_tracker.has_dynamic_execution(),
                )

            # Collect ROP/JOP metrics
            rop_chains = technique.get_rop_chains()
            jop_chains = technique.get_jop_chains()
            metrics.rop_jop = RopJopMetrics(
                rop_chains_detected=len(rop_chains),
                jop_chains_detected=len(jop_chains),
                total_gadgets_found=technique.rop_detector.get_statistics().get('gadgets_found', 0) if technique.rop_detector else 0,
                suspicious_returns=0,
            )

            # Collect signal metrics
            if technique.signal_tracker:
                handlers = technique.get_signal_handlers()
                stats = technique.signal_tracker.get_statistics()
                metrics.signals = SignalMetrics(
                    handlers_registered=len(handlers),
                    signals_raised=stats.get('signals_raised', 0),
                    has_signal_based_loading=technique.signal_tracker.has_signal_based_loading(),
                    handler_addresses=[h.handler_addr for h in handlers],
                )

            metrics.execution_time = time.time() - start_time

            # Clean up to free memory
            del simgr, state, project, technique
            gc.collect()

        except Exception as e:
            metrics.execution_time = time.time() - start_time
            print(f"      Detection analysis error: {e}")

        return metrics

    def evaluate(self, run_detection: bool = True, max_steps: int = 100) -> BenchmarkResult:
        """Run full evaluation on this benchmark."""
        print(f"  Evaluating: {self.name}")

        # Run static analysis (baseline)
        print(f"    Running static analysis...")
        static = self.run_static_analysis()

        # Run DynPathResolver analysis
        print(f"    Running DynPathResolver analysis...")
        dynpath = self.run_dynpath_analysis()

        # Run detection analysis if requested
        detection = None
        if run_detection:
            print(f"    Running detection analysis (symbolic execution)...")
            detection = self.run_detection_analysis(max_steps=max_steps)

        # Calculate improvements
        edge_increase = dynpath['cfg_edges'] - static['cfg_edges']
        edge_increase_pct = (edge_increase / static['cfg_edges'] * 100) if static['cfg_edges'] > 0 else 0
        symbol_increase = dynpath['symbols_found'] - static['symbols_found']
        overhead_pct = ((dynpath['time'] - static['time']) / static['time'] * 100) if static['time'] > 0 else 0

        # Calculate precision/recall if ground truth available
        precision = recall = f1 = None
        if self.ground_truth_edges:
            precision = 1.0 if edge_increase > 0 else 0.0
            recall = min(edge_increase / self.ground_truth_edges, 1.0) if self.ground_truth_edges > 0 else 0
            if precision + recall > 0:
                f1 = 2 * (precision * recall) / (precision + recall)
            else:
                f1 = 0.0

        errors = []
        if static['error']:
            errors.append(f"Static: {static['error']}")
        if dynpath['error']:
            errors.append(f"DynPath: {dynpath['error']}")

        return BenchmarkResult(
            name=self.name,
            binary_path=self.binary_path,
            static_objects=static['objects'],
            static_functions=static['functions'],
            static_cfg_nodes=static['cfg_nodes'],
            static_cfg_edges=static['cfg_edges'],
            static_payload_visible=static['payload_visible'],
            static_symbols_found=static['symbols_found'],
            static_time_seconds=static['time'],
            dynpath_objects=dynpath['objects'],
            dynpath_functions=dynpath['functions'],
            dynpath_cfg_nodes=dynpath['cfg_nodes'],
            dynpath_cfg_edges=dynpath['cfg_edges'],
            dynpath_payload_visible=dynpath['payload_visible'],
            dynpath_symbols_found=dynpath['symbols_found'],
            dynpath_libraries_loaded=dynpath['libraries_loaded'],
            dynpath_time_seconds=dynpath['time'],
            edge_increase=edge_increase,
            edge_increase_percent=edge_increase_pct,
            symbol_increase=symbol_increase,
            overhead_percent=overhead_pct,
            ground_truth_edges=self.ground_truth_edges,
            precision=precision,
            recall=recall,
            f1_score=f1,
            detection=detection,
            errors=errors
        )


# =============================================================================
# Evaluation Runner
# =============================================================================

class EvaluationRunner:
    """Runs evaluation across all benchmarks."""

    # Benchmarks to skip for detection analysis (cause memory issues)
    SKIP_DETECTION = {'08_anti_debug', '12_manual_elf_load', '13_mmap_exec'}

    def __init__(self, benchmarks_dir: str, output_dir: str,
                 run_detection: bool = True, max_steps: int = 100):
        self.benchmarks_dir = benchmarks_dir
        self.output_dir = output_dir
        self.run_detection = run_detection
        self.max_steps = max_steps
        self.results: List[BenchmarkResult] = []

    def discover_benchmarks(self) -> List[Dict]:
        """Discover benchmark binaries in the benchmarks directory."""
        benchmarks = []

        # Define benchmark configurations for complex loaders
        benchmark_configs = [
            {
                'name': 'complex_loader',
                'binary': 'loader',
                'symbols': ['secret_init', 'secret_compute', 'secret_exfiltrate', 'secret_cleanup'],
                'ground_truth_edges': 150
            },
            {
                'name': 'network_triggered_loader',
                'binary': 'loader',
                'symbols': ['execute_payload', 'payload_init', 'exfiltrate_data', 'hidden_backdoor', 'payload_cleanup'],
                'ground_truth_edges': 200
            },
        ]

        # Add synthetic benchmarks from examples/benchmarks/
        synthetic_dir = os.path.join(self.benchmarks_dir, 'benchmarks')
        if os.path.isdir(synthetic_dir):
            for item in sorted(os.listdir(synthetic_dir)):
                item_path = os.path.join(synthetic_dir, item)
                if os.path.isdir(item_path) and item[0].isdigit():
                    binary_path = os.path.join(item_path, 'test_binary')
                    ground_truth_path = os.path.join(item_path, 'ground_truth.json')

                    # Load ground truth if available
                    ground_truth = {}
                    if os.path.exists(ground_truth_path):
                        try:
                            with open(ground_truth_path) as f:
                                ground_truth = json.load(f)
                        except:
                            pass

                    if os.path.exists(binary_path):
                        benchmark_configs.append({
                            'name': item,
                            'binary': 'test_binary',
                            'dir': item_path,
                            'symbols': [],
                            'ground_truth_edges': None,
                            'ground_truth': ground_truth,
                        })

        # Resolve paths
        for config in benchmark_configs:
            if 'dir' in config:
                bench_dir = config['dir']
            else:
                bench_dir = os.path.join(self.benchmarks_dir, config['name'])

            binary_path = os.path.join(bench_dir, config['binary'])

            if os.path.exists(binary_path):
                benchmarks.append({
                    'name': config['name'],
                    'binary_path': binary_path,
                    'lib_dir': bench_dir,
                    'symbols': config['symbols'],
                    'ground_truth_edges': config.get('ground_truth_edges'),
                    'ground_truth': config.get('ground_truth', {}),
                })
            else:
                print(f"  Warning: Benchmark binary not found: {binary_path}")

        return benchmarks

    def run(self) -> EvaluationSummary:
        """Run evaluation on all benchmarks."""
        print("=" * 60)
        print("DynPathResolver Evaluation Suite")
        print("=" * 60)

        # Discover benchmarks
        print("\nDiscovering benchmarks...")
        benchmarks = self.discover_benchmarks()
        print(f"  Found {len(benchmarks)} benchmarks")

        if not benchmarks:
            print("  No benchmarks found!")
            return None

        # Run evaluation on each benchmark
        print("\nRunning evaluations...")
        for bench in benchmarks:
            # Skip problematic benchmarks for detection analysis
            skip_detection = bench['name'] in self.SKIP_DETECTION
            if skip_detection and self.run_detection:
                print(f"  Skipping detection for {bench['name']} (known memory issues)")

            evaluator = BenchmarkEvaluator(
                binary_path=bench['binary_path'],
                lib_dir=bench['lib_dir'],
                payload_symbols=bench['symbols'],
                ground_truth_edges=bench['ground_truth_edges'],
                ground_truth=bench.get('ground_truth', {}),
            )

            result = evaluator.evaluate(
                run_detection=self.run_detection and not skip_detection,
                max_steps=self.max_steps
            )
            self.results.append(result)

        # Calculate summary statistics
        summary = self.calculate_summary()

        # Save results
        self.save_results(summary)

        # Print summary
        self.print_summary(summary)

        return summary

    def calculate_summary(self) -> EvaluationSummary:
        """Calculate summary statistics."""
        successful = [r for r in self.results if not r.errors]
        failed = [r for r in self.results if r.errors]

        if not successful:
            return EvaluationSummary(
                total_benchmarks=len(self.results),
                successful_benchmarks=0,
                failed_benchmarks=len(failed),
                avg_edge_increase=0,
                avg_edge_increase_percent=0,
                avg_symbol_increase=0,
                avg_overhead_percent=0,
                total_static_edges=0,
                total_dynpath_edges=0,
                total_new_edges=0,
                avg_precision=None,
                avg_recall=None,
                avg_f1=None
            )

        # Calculate averages
        avg_edge_inc = sum(r.edge_increase for r in successful) / len(successful)
        avg_edge_pct = sum(r.edge_increase_percent for r in successful) / len(successful)
        avg_sym_inc = sum(r.symbol_increase for r in successful) / len(successful)
        avg_overhead = sum(r.overhead_percent for r in successful) / len(successful)

        # Totals
        total_static = sum(r.static_cfg_edges for r in successful)
        total_dynpath = sum(r.dynpath_cfg_edges for r in successful)
        total_new = sum(r.edge_increase for r in successful)

        # Precision/recall (only for benchmarks with ground truth)
        with_gt = [r for r in successful if r.precision is not None]
        avg_prec = sum(r.precision for r in with_gt) / len(with_gt) if with_gt else None
        avg_rec = sum(r.recall for r in with_gt) / len(with_gt) if with_gt else None
        avg_f1 = sum(r.f1_score for r in with_gt) / len(with_gt) if with_gt else None

        # Detection metrics
        with_detection = [r for r in successful if r.detection is not None]
        detection_count = len(with_detection)
        total_indirect = sum(r.detection.control_flow.total_indirect_calls for r in with_detection)
        total_wx = sum(r.detection.memory.wx_transitions for r in with_detection)
        total_rop = sum(r.detection.rop_jop.rop_chains_detected for r in with_detection)
        total_jop = sum(r.detection.rop_jop.jop_chains_detected for r in with_detection)
        total_signals = sum(r.detection.signals.handlers_registered for r in with_detection)
        dynamic_code = sum(1 for r in with_detection if r.detection.control_flow.has_dynamic_execution)
        signal_loading = sum(1 for r in with_detection if r.detection.signals.has_signal_based_loading)

        return EvaluationSummary(
            total_benchmarks=len(self.results),
            successful_benchmarks=len(successful),
            failed_benchmarks=len(failed),
            avg_edge_increase=avg_edge_inc,
            avg_edge_increase_percent=avg_edge_pct,
            avg_symbol_increase=avg_sym_inc,
            avg_overhead_percent=avg_overhead,
            total_static_edges=total_static,
            total_dynpath_edges=total_dynpath,
            total_new_edges=total_new,
            avg_precision=avg_prec,
            avg_recall=avg_rec,
            avg_f1=avg_f1,
            # Detection metrics
            benchmarks_with_detection=detection_count,
            total_indirect_calls=total_indirect,
            total_wx_transitions=total_wx,
            total_rop_chains=total_rop,
            total_jop_chains=total_jop,
            total_signal_handlers=total_signals,
            benchmarks_with_dynamic_code=dynamic_code,
            benchmarks_with_signal_loading=signal_loading,
        )

    def save_results(self, summary: EvaluationSummary):
        """Save results to files."""
        os.makedirs(self.output_dir, exist_ok=True)

        # Save detailed results as JSON
        results_path = os.path.join(self.output_dir, 'results.json')
        with open(results_path, 'w') as f:
            json.dump({
                'benchmarks': [asdict(r) for r in self.results],
                'summary': asdict(summary)
            }, f, indent=2, default=str)
        print(f"\n  Saved detailed results to: {results_path}")

        # Save summary as CSV
        csv_path = os.path.join(self.output_dir, 'summary.csv')
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Benchmark', 'Static Edges', 'DynPath Edges', 'Edge Increase',
                'Increase %', 'Symbols Found', 'Libraries Loaded',
                'Static Time (s)', 'DynPath Time (s)', 'Overhead %',
                # Detection columns
                'Indirect Calls', 'W->X Transitions', 'ROP Chains',
                'JOP Chains', 'Signal Handlers'
            ])
            for r in self.results:
                d = r.detection
                writer.writerow([
                    r.name, r.static_cfg_edges, r.dynpath_cfg_edges,
                    r.edge_increase, f"{r.edge_increase_percent:.1f}",
                    r.dynpath_symbols_found, r.dynpath_libraries_loaded,
                    f"{r.static_time_seconds:.3f}", f"{r.dynpath_time_seconds:.3f}",
                    f"{r.overhead_percent:.1f}",
                    # Detection data
                    d.control_flow.total_indirect_calls if d else 0,
                    d.memory.wx_transitions if d else 0,
                    d.rop_jop.rop_chains_detected if d else 0,
                    d.rop_jop.jop_chains_detected if d else 0,
                    d.signals.handlers_registered if d else 0,
                ])
        print(f"  Saved summary CSV to: {csv_path}")

        # Generate LaTeX tables
        latex_path = os.path.join(self.output_dir, 'results_table.tex')
        with open(latex_path, 'w') as f:
            f.write(self.generate_cfg_latex_table())
        print(f"  Saved CFG results LaTeX table to: {latex_path}")

        detection_latex_path = os.path.join(self.output_dir, 'detection_table.tex')
        with open(detection_latex_path, 'w') as f:
            f.write(self.generate_detection_latex_table())
        print(f"  Saved detection LaTeX table to: {detection_latex_path}")

    def generate_cfg_latex_table(self) -> str:
        """Generate LaTeX table for CFG recovery metrics."""
        lines = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{CFG Recovery: Static Analysis vs DynPathResolver}",
            r"\label{tab:cfg-results}",
            r"\begin{tabular}{lrrrrr}",
            r"\toprule",
            r"Benchmark & \multicolumn{2}{c}{CFG Edges} & Increase & Symbols & Overhead \\",
            r" & Static & DynPath & (\%) & Found & (\%) \\",
            r"\midrule",
        ]

        for r in self.results:
            name = r.name.replace('_', r'\_')
            lines.append(
                f"{name} & {r.static_cfg_edges} & {r.dynpath_cfg_edges} & "
                f"+{r.edge_increase_percent:.1f}\\% & {r.dynpath_symbols_found} & "
                f"+{r.overhead_percent:.1f}\\% \\\\"
            )

        if self.results:
            avg_edge = sum(r.edge_increase_percent for r in self.results) / len(self.results)
            avg_overhead = sum(r.overhead_percent for r in self.results) / len(self.results)
            lines.extend([
                r"\midrule",
                f"\\textbf{{Average}} & & & +{avg_edge:.1f}\\% & & +{avg_overhead:.1f}\\% \\\\",
            ])

        lines.extend([
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
        ])

        return '\n'.join(lines)

    def generate_detection_latex_table(self) -> str:
        """Generate LaTeX table for detection features."""
        lines = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{Hidden Dependency Detection Results}",
            r"\label{tab:detection-results}",
            r"\begin{tabular}{lrrrrrr}",
            r"\toprule",
            r"Benchmark & Steps & Indirect & W$\rightarrow$X & ROP & JOP & Signal \\",
            r" & & Calls & Trans. & Chains & Chains & Handlers \\",
            r"\midrule",
        ]

        for r in self.results:
            if r.detection:
                d = r.detection
                name = r.name.replace('_', r'\_')
                lines.append(
                    f"{name} & {d.symbolic_steps} & "
                    f"{d.control_flow.total_indirect_calls} & "
                    f"{d.memory.wx_transitions} & "
                    f"{d.rop_jop.rop_chains_detected} & "
                    f"{d.rop_jop.jop_chains_detected} & "
                    f"{d.signals.handlers_registered} \\\\"
                )

        # Calculate totals
        with_detection = [r for r in self.results if r.detection]
        if with_detection:
            total_indirect = sum(r.detection.control_flow.total_indirect_calls for r in with_detection)
            total_wx = sum(r.detection.memory.wx_transitions for r in with_detection)
            total_rop = sum(r.detection.rop_jop.rop_chains_detected for r in with_detection)
            total_jop = sum(r.detection.rop_jop.jop_chains_detected for r in with_detection)
            total_signals = sum(r.detection.signals.handlers_registered for r in with_detection)
            lines.extend([
                r"\midrule",
                f"\\textbf{{Total}} & & {total_indirect} & {total_wx} & "
                f"{total_rop} & {total_jop} & {total_signals} \\\\",
            ])

        lines.extend([
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
        ])

        return '\n'.join(lines)

    def print_summary(self, summary: EvaluationSummary):
        """Print summary to console."""
        print("\n" + "=" * 60)
        print("EVALUATION SUMMARY")
        print("=" * 60)
        print(f"\nBenchmarks: {summary.total_benchmarks} total, "
              f"{summary.successful_benchmarks} successful, "
              f"{summary.failed_benchmarks} failed")

        print(f"\nCFG Edge Recovery:")
        print(f"  Total static edges:    {summary.total_static_edges}")
        print(f"  Total DynPath edges:   {summary.total_dynpath_edges}")
        print(f"  New edges discovered:  {summary.total_new_edges}")
        print(f"  Average increase:      {summary.avg_edge_increase:.1f} edges "
              f"(+{summary.avg_edge_increase_percent:.1f}%)")

        print(f"\nSymbol Resolution:")
        print(f"  Average symbols found: +{summary.avg_symbol_increase:.1f}")

        print(f"\nPerformance:")
        print(f"  Average overhead:      +{summary.avg_overhead_percent:.1f}%")

        if summary.avg_precision is not None:
            print(f"\nAccuracy (with ground truth):")
            print(f"  Precision: {summary.avg_precision:.2f}")
            print(f"  Recall:    {summary.avg_recall:.2f}")
            print(f"  F1 Score:  {summary.avg_f1:.2f}")

        # Detection summary
        if summary.benchmarks_with_detection > 0:
            print(f"\nDetection Analysis ({summary.benchmarks_with_detection} benchmarks):")
            print(f"  Total indirect calls tracked:   {summary.total_indirect_calls}")
            print(f"  Total W->X transitions:         {summary.total_wx_transitions}")
            print(f"  Total ROP chains detected:      {summary.total_rop_chains}")
            print(f"  Total JOP chains detected:      {summary.total_jop_chains}")
            print(f"  Total signal handlers:          {summary.total_signal_handlers}")
            print(f"  Benchmarks with dynamic code:   {summary.benchmarks_with_dynamic_code}")
            print(f"  Benchmarks with signal loading: {summary.benchmarks_with_signal_loading}")

        print("\n" + "=" * 60)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='DynPathResolver Evaluation Suite')
    parser.add_argument('--benchmarks-dir', '-b',
                        default='examples',
                        help='Directory containing benchmark binaries')
    parser.add_argument('--output-dir', '-o',
                        default='evaluation/results',
                        help='Directory for output files')
    parser.add_argument('--no-detection', action='store_true',
                        help='Skip detection analysis (symbolic execution)')
    parser.add_argument('--symbolic-steps', type=int,
                        default=100,
                        help='Maximum symbolic execution steps for detection analysis')

    args = parser.parse_args()

    runner = EvaluationRunner(
        args.benchmarks_dir,
        args.output_dir,
        run_detection=not args.no_detection,
        max_steps=args.symbolic_steps
    )
    runner.run()


if __name__ == '__main__':
    main()
