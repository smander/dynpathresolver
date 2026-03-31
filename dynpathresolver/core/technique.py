"""Main DynPathResolver exploration technique."""

import logging
import angr

# Core imports (same package)
from .interceptor import EventInterceptor
from .resolver import SpeculativeResolver
from .directed import DirectedAnalyzer, DirectedExploration
from .library_load_event import LibraryLoadLog

# Mixin imports
from .hooks import HookingMixin
from .event_resolution import ResolutionMixin
from .validation_mixin import ValidationMixin
from .completion import CompletionMixin

# ELF imports
from dynpathresolver.elf.preloader import LibraryPreloader
from dynpathresolver.elf.vtable import VtableResolver
from dynpathresolver.elf.patcher import CFGPatcher
from dynpathresolver.elf.relocation import RelocationProcessor, GOTTracker, LazyBindingSimulator
from dynpathresolver.elf.platform import PlatformDetector

# Analysis imports
from dynpathresolver.analysis.predictor import HeuristicPredictor
from dynpathresolver.analysis.control_flow import IndirectFlowTracker, RopDetector, JopDetector

# Detection imports
from dynpathresolver.detection.unpacking import UnpackingDetector, UnpackingHandler
from dynpathresolver.detection.guards import GuardDetector
from dynpathresolver.detection.decryption_detector import DecryptionDetector

# Validation imports
from dynpathresolver.validation.validator import HybridValidator, PathCandidate, ValidationResult

# Tracking imports
from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker
from dynpathresolver.tracking.signal_handler import SignalHandlerTracker
from dynpathresolver.tracking.env_tracker import EnvironmentTracker
from dynpathresolver.tracking.ifunc_tracker import IFuncTracker
from dynpathresolver.tracking.init_tracker import InitFiniTracker
from dynpathresolver.tracking.process_tracker import ProcessExecutionTracker
from dynpathresolver.tracking.security_tracker import SecurityPolicyTracker
from dynpathresolver.tracking.shadow_memory import ShadowMemory
from dynpathresolver.tracking.taint_tracker import TaintTracker
from dynpathresolver.tracking.stage_tracker import StageTracker

# Config imports
from dynpathresolver.config.constants import PERIODIC_CHECK_INTERVAL, DEEP_CHECK_INTERVAL

# Re-exports for backward compatibility (tests import these from technique.py)
from .hooks import (
    DynDlmopen, DynDlvsym, DynDladdr, DynDlinfo, DynDlerror,
    DynTlsGetAddr, DynTlsDescResolver,
)
# RelocationProcessor, GOTTracker, LazyBindingSimulator are also imported
# above (line 23) and re-exported implicitly — tests import them from here.

log = logging.getLogger(__name__)


class DynPathResolver(
    HookingMixin,
    ResolutionMixin,
    ValidationMixin,
    CompletionMixin,
    angr.ExplorationTechnique,
):
    """
    Dynamic-assisted CFG recovery exploration technique.

    Resolves indirect control flow (jumps, calls, vtables) by combining
    symbolic execution with speculative solving and library preloading.
    """

    def __init__(
        self,
        max_forks: int = 8,
        preload_common: bool = True,
        library_paths: list[str] | None = None,
        vtable_backtrack_limit: int = 1000,
        output_dir: str | None = None,
        # V2 parameters
        directed_mode: bool = False,
        platform: str = 'auto',
        path_predictor: str = 'heuristic',
        handle_unpacking: bool = False,
        validation_mode: str = 'none',
        # V3 parameters: Syscall-level detection
        handle_syscall_loading: bool = False,
        track_indirect_flow: bool = False,
        detect_rop: bool = False,
        detect_jop: bool = False,
        track_signals: bool = False,
        # Phase 2 parameters: Linux-specific features
        track_environment: bool = False,
        track_ifunc: bool = False,
        track_init_fini: bool = False,
        track_process_exec: bool = False,
        track_security_policy: bool = False,
        # Network/socket parameters
        track_network: bool = False,
        network_payloads: dict[int, bytes] | None = None,
        # Phase 3 parameters: Analysis features
        enable_taint_tracking: bool = False,
        enable_decryption_detection: bool = False,
        enable_stage_tracking: bool = False,
    ):
        super().__init__()

        # Validate V2 parameters
        valid_platforms = ('auto', 'linux', 'windows')
        if platform not in valid_platforms:
            raise ValueError(f"Unknown platform: {platform!r}. Valid options: {valid_platforms}")

        valid_predictors = ('none', 'heuristic')
        if path_predictor not in valid_predictors:
            raise ValueError(f"Unknown path_predictor: {path_predictor!r}. Valid options: {valid_predictors}")

        valid_validation_modes = ('none', 'detect', 'validate')
        if validation_mode not in valid_validation_modes:
            raise ValueError(f"Unknown validation_mode: {validation_mode!r}. Valid options: {valid_validation_modes}")

        self.max_forks = max_forks
        self.preload_common = preload_common
        self.library_paths = library_paths or []
        self.vtable_backtrack_limit = vtable_backtrack_limit
        self.output_dir = output_dir

        # V2 parameters
        self.directed_mode = directed_mode
        self.platform = platform
        self.path_predictor = path_predictor
        self.handle_unpacking = handle_unpacking
        self.validation_mode = validation_mode

        # V3 parameters: Syscall-level detection
        self.handle_syscall_loading = handle_syscall_loading
        self.track_indirect_flow = track_indirect_flow
        self.detect_rop = detect_rop
        self.detect_jop = detect_jop
        self.track_signals = track_signals

        # Phase 2 parameters: Linux-specific features
        self.track_environment = track_environment
        self.track_ifunc = track_ifunc
        self.track_init_fini = track_init_fini
        self.track_process_exec = track_process_exec
        self.track_security_policy = track_security_policy

        # Network/socket parameters
        self.track_network = track_network
        self.network_payloads = network_payloads or {}

        # Phase 3 parameters: Analysis features
        self.enable_taint_tracking = enable_taint_tracking
        self.enable_decryption_detection = enable_decryption_detection
        self.enable_stage_tracking = enable_stage_tracking

        # Components (initialized in setup)
        self.interceptor: EventInterceptor | None = None
        self.resolver: SpeculativeResolver | None = None
        self.preloader: LibraryPreloader | None = None
        self.vtable_resolver: VtableResolver | None = None
        self.cfg_patcher: CFGPatcher | None = None

        # V2 placeholder components (initialized in setup)
        self.directed_analyzer: DirectedAnalyzer | None = None
        self.directed_explorer: DirectedExploration | None = None
        self.heuristic_predictor: HeuristicPredictor | None = None
        self.unpacking_detector: UnpackingDetector | None = None
        self.unpacking_handler: UnpackingHandler | None = None
        self._detected_platform = None
        self._step_count = 0

        # Validation components (initialized in setup based on validation_mode)
        self.guard_detector: GuardDetector | None = None
        self.validator: HybridValidator | None = None
        self.path_candidates: list[PathCandidate] = []
        self.validation_results: list[ValidationResult] = []

        # Library load event log (captures full register state at each load)
        self.library_load_log: LibraryLoadLog = LibraryLoadLog()

        # Relocation and GOT/PLT tracking components
        self.relocation_processor: RelocationProcessor | None = None
        self.got_tracker: GOTTracker | None = None
        self.lazy_binding_sim: LazyBindingSimulator | None = None

        # V3 components: Syscall-level detection
        self.memory_tracker: MemoryRegionTracker | None = None
        self.indirect_flow_tracker: IndirectFlowTracker | None = None
        self.rop_detector: RopDetector | None = None
        self.jop_detector: JopDetector | None = None
        self.signal_tracker: SignalHandlerTracker | None = None

        # Phase 2 components: Linux-specific features
        self.env_tracker: EnvironmentTracker | None = None
        self.ifunc_tracker: IFuncTracker | None = None
        self.init_tracker: InitFiniTracker | None = None
        self.process_tracker: ProcessExecutionTracker | None = None
        self.security_tracker: SecurityPolicyTracker | None = None

        # Phase 3 components: Analysis features
        self.shadow_memory: ShadowMemory | None = None
        self.taint_tracker: TaintTracker | None = None
        self.decryption_detector: DecryptionDetector | None = None
        self.stage_tracker: StageTracker | None = None

    def setup(self, simgr: "angr.SimulationManager") -> None:
        """Initialize components when technique is applied."""
        project = simgr._project

        self._setup_core_components(project)
        self._setup_library_preloading(project)
        self._setup_hooks(project)
        self._setup_relocation_tracking(project)
        self._setup_v2_components(project, simgr)
        self._setup_v3_syscall_detection(project)
        self._setup_linux_trackers(project)
        self._setup_analysis_features()
        self._setup_attach_states(simgr)

    # -- Private setup helpers ------------------------------------------------

    def _setup_core_components(self, project: "angr.Project") -> None:
        """Detect platform and create core analysis components."""
        # V2: Detect platform if 'auto'
        if self.platform == 'auto':
            self._detected_platform = PlatformDetector.detect(project)
        else:
            self._detected_platform = self.platform

        self.interceptor = EventInterceptor(project)
        self.resolver = SpeculativeResolver(project, self.max_forks)
        self.preloader = LibraryPreloader(project)
        self.vtable_resolver = VtableResolver(project, self.vtable_backtrack_limit)
        self.cfg_patcher = CFGPatcher(project)

    def _setup_library_preloading(self, project: "angr.Project") -> None:
        """Preload common libraries and user-specified library paths."""
        if self.preload_common:
            self.preloader.load_common_libs()
        self.preloader.scan_and_load_string_refs()
        for path in self.library_paths:
            self.preloader.add_library_paths([path])

    def _setup_hooks(self, project: "angr.Project") -> None:
        """Install platform-specific dynamic loading hooks."""
        # V2: Hook platform-specific dynamic loading functions
        if self._detected_platform == 'windows':
            self._hook_windows(project)
        else:
            self._hook_linux(project)

    def _setup_relocation_tracking(self, project: "angr.Project") -> None:
        """Initialize relocation processing and GOT/PLT tracking."""
        self.relocation_processor = RelocationProcessor(project)
        self.relocation_processor.initialize()
        self.got_tracker = GOTTracker(project)
        self.got_tracker.initialize()
        self.lazy_binding_sim = LazyBindingSimulator(project)
        self.lazy_binding_sim.initialize()

    def _setup_v2_components(
        self, project: "angr.Project", simgr: "angr.SimulationManager"
    ) -> None:
        """Initialize V2 components: directed mode, predictor, unpacking, validation."""
        # V2: Initialize DirectedAnalyzer and DirectedExploration if directed_mode=True
        if self.directed_mode:
            self.directed_analyzer = DirectedAnalyzer(project)
            target_sites = self.directed_analyzer.find_dynamic_loading_sites()
            self.directed_explorer = DirectedExploration(target_sites)
            # Compute distances if we have a CFG
            try:
                cfg = project.analyses.CFGFast()
                self.directed_explorer.compute_distances(cfg)
            except Exception as e:
                log.debug(f"Could not compute distances for directed mode: {e}")

        # V2: Initialize HeuristicPredictor if path_predictor='heuristic'
        if self.path_predictor == 'heuristic':
            self.heuristic_predictor = HeuristicPredictor(
                project,
                self._detected_platform,
                self.library_paths,
            )

        # V2: Initialize UnpackingDetector and UnpackingHandler if handle_unpacking=True
        if self.handle_unpacking:
            self.unpacking_detector = UnpackingDetector(project)
            self.unpacking_handler = UnpackingHandler(project, self.unpacking_detector)
            # Install write breakpoints on existing states
            for state in simgr.active:
                self.unpacking_handler.install_write_breakpoint(state)

        # V2: Initialize GuardDetector and HybridValidator based on validation_mode
        if self.validation_mode != 'none':
            self.guard_detector = GuardDetector(project)
            # Detect guards in binary
            self.guard_detector.detect_guards()

            if self.validation_mode == 'validate':
                self.validator = HybridValidator(project, self.guard_detector)

    def _setup_v3_syscall_detection(self, project: "angr.Project") -> None:
        """Initialize V3 syscall-level detection: memory, indirect flow, ROP/JOP, signals."""
        if self.handle_syscall_loading:
            self.memory_tracker = MemoryRegionTracker(project)
            self._hook_syscalls(project)
            log.info("Syscall-level loading detection enabled")

        if self.track_indirect_flow:
            self.indirect_flow_tracker = IndirectFlowTracker(
                project, self.memory_tracker
            )
            log.info("Indirect control flow tracking enabled")

        if self.detect_rop:
            self.rop_detector = RopDetector(project, self.memory_tracker)
            self.rop_detector.find_gadgets()
            log.info(f"ROP detection enabled, found {len(self.rop_detector.gadgets)} gadgets")

        if self.detect_jop:
            self.jop_detector = JopDetector(project, self.memory_tracker)
            self.jop_detector.find_gadgets()
            log.info("JOP detection enabled")

        if self.track_signals:
            self.signal_tracker = SignalHandlerTracker(project)
            self._hook_signal_functions(project)
            log.info("Signal handler tracking enabled")

        if self.track_network:
            if self.memory_tracker is None:
                self.memory_tracker = MemoryRegionTracker(project)
            self._hook_socket_functions(project)
            log.info("Network/socket tracking enabled")

    def _setup_linux_trackers(self, project: "angr.Project") -> None:
        """Initialize Phase 2 Linux-specific feature trackers."""
        if self.track_environment:
            self.env_tracker = EnvironmentTracker(project)
            self._hook_env_functions(project)
            log.info("Environment variable tracking enabled")

        if self.track_ifunc:
            self.ifunc_tracker = IFuncTracker(project)
            self.ifunc_tracker.scan_for_ifuncs()
            log.info(f"IFUNC tracking enabled, found {len(self.ifunc_tracker.ifunc_symbols)} IFUNCs")

        if self.track_init_fini:
            self.init_tracker = InitFiniTracker(project)
            self.init_tracker.scan_all_objects()
            log.info(f"Init/Fini tracking enabled, found {len(self.init_tracker.init_functions)} init functions")

        if self.track_process_exec:
            self.process_tracker = ProcessExecutionTracker(project)
            self._hook_exec_functions(project)
            log.info("Process execution tracking enabled")

        if self.track_security_policy:
            self.security_tracker = SecurityPolicyTracker(project)
            self._hook_security_functions(project)
            log.info("Security policy tracking enabled")

    def _setup_analysis_features(self) -> None:
        """Initialize Phase 3 analysis features: shadow memory, taint, decryption, stages."""
        # Shadow memory is shared between taint tracker and decryption detector
        if self.enable_taint_tracking or self.enable_decryption_detection:
            self.shadow_memory = ShadowMemory()

        if self.enable_taint_tracking:
            self.taint_tracker = TaintTracker(shadow=self.shadow_memory)
            log.info("Taint tracking enabled")

        if self.enable_decryption_detection:
            self.decryption_detector = DecryptionDetector(shadow=self.shadow_memory)
            log.info("Decryption detection enabled")

        if self.enable_stage_tracking:
            self.stage_tracker = StageTracker(
                memory_tracker=self.memory_tracker,
                taint_tracker=self.taint_tracker,
            )
            log.info("Multi-stage payload tracking enabled")

    def _setup_attach_states(self, simgr: "angr.SimulationManager") -> None:
        """Attach interceptor and trackers to all active states, initialize state globals."""
        for state in simgr.active:
            self.interceptor.attach(state)
            # V3: Attach indirect flow tracker if enabled
            if self.indirect_flow_tracker:
                self.indirect_flow_tracker.attach(state)
            # Phase 3: Attach taint propagation if enabled
            if self.taint_tracker:
                self.taint_tracker.attach_propagation(state)
            # Store all component references in state globals for per-state isolation
            self._init_state_globals(state)

    def _init_state_globals(self, state: "angr.SimState") -> None:
        """Initialize per-state globals with all component references.

        This ensures each state branch carries its own references to
        the technique and all tracker objects, avoiding class-level
        mutable state in SimProcedures.
        """
        # Core references (used by dl* SimProcedures)
        state.globals['dpr_technique'] = self
        state.globals['dpr_preloader'] = self.preloader
        state.globals['dpr_library_paths'] = list(self.library_paths)
        state.globals['dpr_loaded_libraries'] = state.globals.get(
            'dpr_loaded_libraries', {}
        )
        if 'dpr_win_loaded_libraries' not in state.globals:
            state.globals['dpr_win_loaded_libraries'] = {}

        # Tracker references (used by syscall SimProcedures)
        state.globals['dpr_memory_tracker'] = self.memory_tracker
        state.globals['dpr_signal_tracker'] = self.signal_tracker
        state.globals['dpr_env_tracker'] = self.env_tracker
        state.globals['dpr_process_tracker'] = self.process_tracker
        state.globals['dpr_security_tracker'] = self.security_tracker
        state.globals['dpr_heuristic_predictor'] = self.heuristic_predictor
        state.globals['dpr_network_payloads'] = self.network_payloads

        # Per-state behavioral state (initialized with defaults)
        if 'dpr_dlerror_last_error' not in state.globals:
            state.globals['dpr_dlerror_last_error'] = None
        if 'dpr_ptrace_is_traced' not in state.globals:
            state.globals['dpr_ptrace_is_traced'] = False
        if 'dpr_prctl_dumpable' not in state.globals:
            state.globals['dpr_prctl_dumpable'] = 1
        if 'dpr_prctl_seccomp' not in state.globals:
            state.globals['dpr_prctl_seccomp'] = 0
        if 'dpr_prctl_no_new_privs' not in state.globals:
            state.globals['dpr_prctl_no_new_privs'] = 0

        # Per-state caches and allocators
        if 'dpr_dlmopen_namespaces' not in state.globals:
            state.globals['dpr_dlmopen_namespaces'] = {0: []}
        if 'dpr_resolved_symbols' not in state.globals:
            state.globals['dpr_resolved_symbols'] = {}
        if 'dpr_resolved_versioned_symbols' not in state.globals:
            state.globals['dpr_resolved_versioned_symbols'] = {}

    def step(
        self,
        simgr: "angr.SimulationManager",
        stash: str = 'active',
        **kwargs,
    ) -> "angr.SimulationManager":
        """Process one step of symbolic execution."""
        self._step_count += 1

        # V2: If directed_mode, prioritize states before stepping
        if self.directed_mode and self.directed_explorer and simgr.active:
            simgr.active = self.directed_explorer.prioritize(simgr.active)

        # Normal step first
        simgr = simgr.step(stash=stash, **kwargs)

        # Process any intercepted events
        if self.interceptor:
            for event in self.interceptor.drain_pending():
                self._handle_event(simgr, event)

        # Attach interceptor to any new states and ensure state globals
        for state in simgr.active:
            if self.interceptor:
                self.interceptor.attach(state)
            # V3: Attach indirect flow tracker to new states
            if self.indirect_flow_tracker:
                self.indirect_flow_tracker.attach(state)
            # Ensure state globals are initialized (no-op if already set)
            if 'dpr_technique' not in state.globals:
                self._init_state_globals(state)

        # V3: Check for ROP/JOP patterns periodically
        if self._step_count % PERIODIC_CHECK_INTERVAL == 0:
            self._check_rop_jop(simgr)

        # V2: If handle_unpacking, install breakpoints on new states
        # and periodically check should_rescan()
        if self.handle_unpacking and self.unpacking_handler:
            for state in simgr.active:
                self.unpacking_handler.install_write_breakpoint(state)

            # Check for unpacking every DEEP_CHECK_INTERVAL steps
            if self._step_count % DEEP_CHECK_INTERVAL == 0:
                if self.unpacking_handler.should_rescan():
                    log.info("Unpacking activity detected, may need CFG rescan")

        return simgr
