"""Completion mixin for DynPathResolver — result export and getter methods."""

import logging
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class CompletionMixin:
    """Mixin providing exploration completion logic and result getters."""

    def complete(self, simgr: "angr.SimulationManager") -> bool:
        """Called when exploration ends - export results."""
        # Scan loaded libraries for recursive .so references
        self._scan_loaded_libs_for_references(simgr)

        # Run validation if enabled
        if self.validation_mode == 'validate':
            self.run_validation()

        # V3: Log syscall-level detection results
        if self.memory_tracker:
            stats = self.memory_tracker.get_statistics()
            log.info(f"Memory tracking stats: {stats}")
            exec_regions = self.memory_tracker.get_executable_regions()
            if exec_regions:
                log.info(f"Found {len(exec_regions)} executable memory regions")
            library_loads = self.memory_tracker.find_library_loads()
            if library_loads:
                log.warning(f"Detected {len(library_loads)} manual library loads")
                self._load_manual_library_discoveries(simgr, library_loads)

        if self.indirect_flow_tracker:
            stats = self.indirect_flow_tracker.get_statistics()
            log.info(f"Indirect flow tracking stats: {stats}")
            if self.indirect_flow_tracker.has_dynamic_execution():
                log.warning("Code execution in dynamically mapped memory detected!")

        if self.rop_detector:
            chains = self.rop_detector.get_detected_chains()
            if chains:
                log.warning(f"Detected {len(chains)} potential ROP chains")

        if self.jop_detector:
            chains = self.jop_detector.get_detected_chains()
            if chains:
                log.warning(f"Detected {len(chains)} potential JOP chains")

        if self.signal_tracker:
            stats = self.signal_tracker.get_statistics()
            log.info(f"Signal tracking stats: {stats}")
            if self.signal_tracker.has_signal_based_loading():
                log.warning("Library loading in signal handlers detected!")

        # Phase 2: Log Linux-specific feature results
        if self.env_tracker:
            stats = self.env_tracker.get_statistics()
            log.info(f"Environment tracking stats: {stats}")
            if self.env_tracker.has_library_injection():
                log.warning("Library injection via environment variables detected!")
            security_vars = self.env_tracker.get_security_variables()
            if security_vars:
                log.warning(f"Security-relevant env vars modified: {[v.name for v in security_vars]}")

        if self.ifunc_tracker:
            stats = self.ifunc_tracker.get_statistics()
            log.info(f"IFUNC tracking stats: {stats}")
            if stats['total_resolutions'] > 0:
                log.info(f"Resolved {stats['total_resolutions']} IFUNCs")

        if self.init_tracker:
            stats = self.init_tracker.get_statistics()
            log.info(f"Init/Fini tracking stats: {stats}")
            unexecuted = self.init_tracker.get_unexecuted_inits()
            if unexecuted:
                log.debug(f"{len(unexecuted)} init functions not executed")

        if self.process_tracker:
            stats = self.process_tracker.get_statistics()
            log.info(f"Process execution stats: {stats}")
            if stats['total_execs'] > 0:
                log.warning(f"Detected {stats['total_execs']} process replacements (exec*)")
            if stats['total_clones'] > 0:
                log.info(f"Detected {stats['total_clones']} clone/fork operations")

        if self.security_tracker:
            stats = self.security_tracker.get_statistics()
            log.info(f"Security policy stats: {stats}")
            if self.security_tracker.has_anti_debug():
                log.warning("Anti-debug techniques detected!")
            if self.security_tracker.get_code_injection_events():
                log.warning("Cross-process code injection detected!")

        # Phase 3: Log analysis feature results
        if self.taint_tracker:
            stats = self.taint_tracker.get_statistics()
            log.info(f"Taint tracking stats: {stats}")
            if self.taint_tracker.has_tainted_control_flow():
                log.warning("Tainted data influenced control flow!")
            if self.taint_tracker.has_tainted_library_paths():
                log.warning("Tainted data used as library paths!")

        if self.decryption_detector:
            stats = self.decryption_detector.get_statistics()
            log.info(f"Decryption detection stats: {stats}")
            decrypted_strings = self.decryption_detector.get_decrypted_strings()
            if decrypted_strings:
                log.info(f"Detected {len(decrypted_strings)} decrypted strings")

        if self.stage_tracker:
            stats = self.stage_tracker.get_statistics()
            log.info(f"Stage tracking stats: {stats}")
            if self.stage_tracker.has_multi_stage():
                log.warning(f"Multi-stage payload detected: {stats['total_stages']} stages")

        if self.output_dir and self.cfg_patcher:
            self.cfg_patcher.export_results(self.output_dir)
        return False  # Don't signal completion to other techniques

    def _scan_loaded_libs_for_references(self, simgr: "angr.SimulationManager") -> None:
        """Scan loaded libraries for .so string references (recursive discovery).

        This catches multi-stage loading where libstage1.so contains a
        dlopen("libstage2.so") string that we can't reach via symbolic execution
        because symex doesn't flow into loaded library code.
        """
        from dynpathresolver.simprocedures.dlopen import DynDlopen

        # Collect loaded library paths from all states
        all_states = list(simgr.active) + list(getattr(simgr, 'deadended', []))
        loaded_paths = set()
        for state in all_states:
            loaded = state.globals.get('dpr_loaded_libraries', {})
            for lib in loaded.values():
                if hasattr(lib, 'binary') and lib.binary:
                    loaded_paths.add(lib.binary)

        # Also collect from class-level storage
        for lib in DynDlopen.loaded_libraries.values():
            if hasattr(lib, 'binary') and lib.binary:
                loaded_paths.add(lib.binary)

        # Also scan the main binary for .so references
        # (catches signal handlers and other code that references libraries)
        project = simgr._project
        main_binary = project.loader.main_object.binary
        if main_binary and os.path.isfile(main_binary):
            loaded_paths.add(main_binary)

        # Build search paths
        search_dirs = list(self.library_paths)
        main_path = project.loader.main_object.binary
        if main_path:
            search_dirs.append(os.path.dirname(main_path))

        # Scan each loaded library's binary for .so references
        already_known = {os.path.basename(p) for p in loaded_paths}
        pattern = re.compile(rb'[\x20-\x7e]*lib[\x20-\x7e]+\.so[\x20-\x7e]*')
        new_discoveries = []

        for lib_path in loaded_paths:
            if not os.path.isfile(lib_path):
                continue
            try:
                with open(lib_path, 'rb') as f:
                    data = f.read()

                for match in pattern.finditer(data):
                    name = match.group().decode('utf-8', 'ignore').strip()
                    # Clean up the name
                    if '/' in name:
                        name = name.split('/')[-1]
                    if not (name.startswith('lib') and '.so' in name):
                        continue
                    if name in already_known:
                        continue

                    # Try to find the file in search dirs
                    for search_dir in search_dirs:
                        candidate = os.path.join(search_dir, name)
                        if os.path.isfile(candidate):
                            log.info(f"Recursive discovery: {name} referenced by {os.path.basename(lib_path)}")
                            new_discoveries.append((name, candidate))
                            already_known.add(name)
                            break
            except Exception as e:
                log.debug(f"Error scanning {lib_path}: {e}")

        # Load discovered libraries
        for lib_name, lib_full_path in new_discoveries:
            try:
                loaded = project.loader.dynamic_load(lib_full_path)
                if loaded:
                    lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                    handle = lib_obj.mapped_base if hasattr(lib_obj, 'mapped_base') else id(lib_obj)
                    DynDlopen.loaded_libraries[handle] = lib_obj
                    # Also update state globals
                    for state in all_states:
                        loaded_libs = state.globals.get('dpr_loaded_libraries', {})
                        loaded_libs[handle] = lib_obj
                        state.globals['dpr_loaded_libraries'] = loaded_libs
                    log.info(f"Loaded recursive discovery: {lib_name} at 0x{handle:x}")
            except Exception as e:
                log.debug(f"Could not load recursive discovery {lib_name}: {e}")

    def _load_manual_library_discoveries(self, simgr, library_loads):
        """Load manually-detected library loads into CLE."""
        from dynpathresolver.simprocedures.dlopen import DynDlopen

        project = simgr._project
        all_states = list(simgr.active) + list(getattr(simgr, 'deadended', []))

        search_dirs = list(self.library_paths)
        main_path = project.loader.main_object.binary
        if main_path:
            search_dirs.append(os.path.dirname(main_path))

        already_loaded = set()
        for lib in DynDlopen.loaded_libraries.values():
            if hasattr(lib, 'binary') and lib.binary:
                already_loaded.add(os.path.basename(lib.binary))

        # Collect .so paths from two sources
        so_paths = set()

        # Source 1: executable mmap regions with .so filepath
        for region in library_loads:
            if region.filepath and not region.filepath.startswith('memfd:') \
                    and '/proc/self/fd/' not in region.filepath:
                so_paths.add(region.filepath)

        # Source 2: any .so opened via open()/fopen()
        if self.memory_tracker:
            for of in self.memory_tracker.open_files.values():
                if '.so' in of.path and not of.path.startswith('/proc/'):
                    so_paths.add(of.path)

        for filepath in so_paths:
            lib_name = os.path.basename(filepath)
            if lib_name in already_loaded:
                continue
            actual_path = self._resolve_so_path(filepath, search_dirs)
            if not actual_path:
                continue
            try:
                loaded = project.loader.dynamic_load(actual_path)
                if loaded:
                    lib_obj = loaded[0] if isinstance(loaded, list) else loaded
                    handle = getattr(lib_obj, 'mapped_base', 0) or id(lib_obj)
                    DynDlopen.loaded_libraries[handle] = lib_obj
                    for state in all_states:
                        ll = state.globals.get('dpr_loaded_libraries', {})
                        ll[handle] = lib_obj
                        state.globals['dpr_loaded_libraries'] = ll
                    already_loaded.add(lib_name)
                    log.info(f"Loaded manual library discovery: {lib_name}")
            except Exception as e:
                log.debug(f"Could not load manual discovery {lib_name}: {e}")

    def _resolve_so_path(self, filepath, search_dirs):
        """Resolve a potentially relative .so path to absolute."""
        if os.path.isfile(filepath):
            return os.path.abspath(filepath)
        clean = filepath.lstrip('./')
        for d in search_dirs:
            for name in [clean, os.path.basename(filepath)]:
                candidate = os.path.join(d, name)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
        return None

    # === V3 Getter Methods ===

    def get_executable_regions(self) -> list:
        """Get all executable dynamically-mapped regions."""
        if self.memory_tracker:
            return self.memory_tracker.get_executable_regions()
        return []

    def get_manual_library_loads(self) -> list:
        """Get regions that look like manually loaded libraries."""
        if self.memory_tracker:
            return self.memory_tracker.find_library_loads()
        return []

    def get_library_load_events(self) -> list:
        """
        Get all library load events with full register/flag state.

        Returns a list of LibraryLoadEvent objects containing:
        - Library path and name
        - Loading method (dlopen, mmap, memfd, etc.)
        - Complete register snapshot at load time
        - CPU flags
        - Path constraints
        - Call stack
        """
        return self.library_load_log.events

    def get_dynamic_calls(self) -> list:
        """Get all calls to dynamically mapped memory."""
        if self.indirect_flow_tracker:
            return self.indirect_flow_tracker.get_dynamic_calls()
        return []

    def get_rop_chains(self) -> list:
        """Get all detected ROP chains."""
        if self.rop_detector:
            return self.rop_detector.get_detected_chains()
        return []

    def get_jop_chains(self) -> list:
        """Get all detected JOP chains."""
        if self.jop_detector:
            return self.jop_detector.get_detected_chains()
        return []

    def get_signal_handlers(self) -> list:
        """Get all registered signal handlers."""
        if self.signal_tracker:
            return self.signal_tracker.get_all_handlers()
        return []
