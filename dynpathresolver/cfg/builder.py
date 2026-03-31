"""
Complete CFG builder combining CFGEmulated with DynPathResolver.

This module provides the CompleteCFGBuilder class for comprehensive CFG
recovery that includes:
- Full symbolic execution via CFGEmulated
- Dynamic library discovery via DynPathResolver hooks
- Complete state information (registers, flags, constraints)
- Merged CFG with both static and dynamic edges
"""

import logging
from typing import TYPE_CHECKING

import angr

from dynpathresolver.cfg.types import (
    CompleteCFG,
    CompleteCFGEdge,
    CompleteCFGNode,
    EdgeType,
    Instruction,
    RegisterState,
)

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


class CompleteCFGBuilder:
    """
    Builds a complete CFG by combining CFGEmulated with DynPathResolver.

    This class:
    1. Runs CFGEmulated to get static CFG with full state information
    2. Hooks DynPathResolver's SimProcedures to capture dynamic edges
    3. Merges results into a CompleteCFG with all state information
    """

    def __init__(
        self,
        project: "angr.Project",
        # CFGEmulated options
        context_sensitivity_level: int = 1,
        keep_state: bool = True,
        max_iterations: int = 100000,
        max_steps: int = 100000,
        # DynPathResolver options
        library_paths: list[str] | None = None,
        resolve_indirect: bool = True,
        track_memory: bool = True,
    ):
        """
        Initialize the CFG builder.

        Args:
            project: angr Project
            context_sensitivity_level: Context sensitivity for CFGEmulated (0-3)
            keep_state: Whether to keep full states at each node
            max_iterations: Maximum iterations for CFGEmulated
            max_steps: Maximum steps for exploration
            library_paths: Paths to search for libraries
            resolve_indirect: Whether to resolve indirect jumps/calls
            track_memory: Whether to track memory accesses
        """
        self.project = project
        self.context_sensitivity_level = context_sensitivity_level
        self.keep_state = keep_state
        self.max_iterations = max_iterations
        self.max_steps = max_steps
        self.library_paths = library_paths or []
        self.resolve_indirect = resolve_indirect
        self.track_memory = track_memory

        # Results
        self.complete_cfg: CompleteCFG | None = None

        # Dynamic discoveries (populated during CFG building)
        self._discovered_libraries: list[str] = []
        self._resolved_symbols: dict[str, int] = {}
        self._dynamic_edges: list[tuple[int, int, str]] = []  # (src, dst, type)

    def _setup_hooks(self) -> None:
        """Setup DynPathResolver hooks to capture dynamic edges."""
        from dynpathresolver.simprocedures import DynDlopen, DynDlsym
        from dynpathresolver.simprocedures.windows import DynLoadLibraryA, DynGetProcAddress

        # Store reference to builder for callbacks
        builder = self

        # Create wrapper classes that report to the builder
        class TrackedDlopen(DynDlopen):
            def run(self, path, flags=None):
                result = super().run(path, flags)
                if path is not None:
                    try:
                        lib_path = self.state.solver.eval(path, cast_to=bytes).decode('utf-8').rstrip('\x00')
                        builder._discovered_libraries.append(lib_path)
                        builder._dynamic_edges.append((
                            self.state.addr,
                            0,  # Target unknown until resolved
                            f"dlopen:{lib_path}"
                        ))
                        log.info(f"CFGBuilder: Tracked dlopen({lib_path})")
                    except Exception:
                        pass
                return result

        class TrackedDlsym(DynDlsym):
            def run(self, handle, symbol):
                result = super().run(handle, symbol)
                if symbol is not None:
                    try:
                        sym_name = self.state.solver.eval(symbol, cast_to=bytes).decode('utf-8').rstrip('\x00')
                        # Try to get concrete result
                        if not self.state.solver.symbolic(result):
                            addr = self.state.solver.eval(result)
                            builder._resolved_symbols[sym_name] = addr
                            builder._dynamic_edges.append((
                                self.state.addr,
                                addr,
                                f"dlsym:{sym_name}"
                            ))
                            log.info(f"CFGBuilder: Tracked dlsym({sym_name}) -> 0x{addr:x}")
                    except Exception:
                        pass
                return result

        # Hook the functions
        symbols_to_hook = {
            'dlopen': TrackedDlopen,
            'dlsym': TrackedDlsym,
        }

        for sym_name, simproc_class in symbols_to_hook.items():
            try:
                sym = self.project.loader.find_symbol(sym_name)
                if sym:
                    self.project.hook(sym.rebased_addr, simproc_class(), replace=True)
                    log.debug(f"CFGBuilder: Hooked {sym_name} at 0x{sym.rebased_addr:x}")
                else:
                    self.project.hook_symbol(sym_name, simproc_class(), replace=True)
                    log.debug(f"CFGBuilder: Hooked {sym_name} by symbol name")
            except Exception as e:
                log.debug(f"CFGBuilder: Could not hook {sym_name}: {e}")

    def _extract_instructions(self, block: "angr.block.Block") -> list[Instruction]:
        """Extract instructions from an angr block."""
        instructions = []
        try:
            for insn in block.capstone.insns:
                instructions.append(Instruction(
                    addr=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes=bytes(insn.bytes),
                ))
        except Exception as e:
            log.debug(f"Could not extract instructions from block: {e}")
        return instructions

    def _convert_angr_cfg(self, angr_cfg: "angr.analyses.cfg.CFGEmulated") -> CompleteCFG:
        """Convert angr's CFGEmulated to our CompleteCFG format."""
        complete_cfg = CompleteCFG()

        # Process all nodes
        for angr_node in angr_cfg.graph.nodes():
            if angr_node.addr is None:
                continue

            # Create our node
            node = CompleteCFGNode(
                addr=angr_node.addr,
                size=angr_node.size if angr_node.size else 0,
            )

            # Extract instructions
            if angr_node.block:
                node.instructions = self._extract_instructions(angr_node.block)

            # Get function info
            if angr_node.function_address:
                node.function_addr = angr_node.function_address
                func = angr_cfg.kb.functions.get(angr_node.function_address)
                if func:
                    node.function_name = func.name
                    complete_cfg.functions[angr_node.function_address] = func.name

            # Extract state information if available
            if hasattr(angr_node, 'final_states') and angr_node.final_states:
                for state in angr_node.final_states:
                    reg_state = RegisterState.from_state(state)
                    node.exit_states.append(reg_state)

                    # Extract constraints
                    try:
                        for constraint in state.solver.constraints:
                            node.constraints.append(str(constraint))
                    except Exception:
                        pass

            # Check if this node loads libraries or resolves symbols
            for lib in self._discovered_libraries:
                # Check if any instruction in this block references the library
                for instr in node.instructions:
                    if lib in instr.op_str:
                        node.loads_library = lib
                        break

            # Mark special nodes
            if angr_node.addr == self.project.entry:
                node.is_entry = True

            complete_cfg.add_node(node)

        # Process all edges
        for src_node, dst_node, edge_data in angr_cfg.graph.edges(data=True):
            if src_node.addr is None or dst_node.addr is None:
                continue

            # Determine edge type
            jumpkind = edge_data.get('jumpkind', 'Ijk_Boring')
            edge_type = self._jumpkind_to_edge_type(jumpkind)

            edge = CompleteCFGEdge(
                src_addr=src_node.addr,
                dst_addr=dst_node.addr,
                edge_type=edge_type,
            )

            complete_cfg.add_edge(edge)

        # Add dynamic edges
        for src, dst, info in self._dynamic_edges:
            if dst != 0 and dst in complete_cfg.nodes:
                edge = CompleteCFGEdge(
                    src_addr=src,
                    dst_addr=dst,
                    edge_type=EdgeType.DYNAMIC_LOAD if 'dlopen' in info else EdgeType.INDIRECT_CALL,
                    resolution_method='DynPathResolver',
                    confidence=1.0,
                )
                if 'dlopen' in info:
                    edge.library_loaded = info.split(':')[1] if ':' in info else None
                elif 'dlsym' in info:
                    edge.symbol_resolved = info.split(':')[1] if ':' in info else None

                complete_cfg.add_edge(edge)

                # Mark target as dynamic
                if dst in complete_cfg.nodes:
                    complete_cfg.nodes[dst].is_dynamic_target = True

        # Store discoveries
        complete_cfg.discovered_libraries = self._discovered_libraries.copy()
        complete_cfg.resolved_symbols = self._resolved_symbols.copy()

        return complete_cfg

    def _jumpkind_to_edge_type(self, jumpkind: str) -> EdgeType:
        """Convert angr jumpkind to our EdgeType."""
        mapping = {
            'Ijk_Boring': EdgeType.FALLTHROUGH,
            'Ijk_Call': EdgeType.DIRECT_CALL,
            'Ijk_Ret': EdgeType.RETURN,
            'Ijk_Sys_syscall': EdgeType.SYSCALL,
            'Ijk_Sys_int': EdgeType.SYSCALL,
        }
        return mapping.get(jumpkind, EdgeType.DIRECT_JUMP)

    def build(
        self,
        starts: list[int] | None = None,
        call_depth: int = 5,
    ) -> CompleteCFG:
        """
        Build the complete CFG.

        Args:
            starts: Starting addresses (defaults to entry point)
            call_depth: Maximum call depth to explore

        Returns:
            CompleteCFG with full state information
        """
        log.info("Starting CompleteCFGBuilder...")

        # Setup hooks
        self._setup_hooks()

        # Determine start addresses
        if starts is None:
            starts = [self.project.entry]

        log.info(f"Building CFG from {len(starts)} start point(s)")

        # Build CFGEmulated with state tracking
        state_options = {
            angr.sim_options.TRACK_REGISTER_ACTIONS,
            angr.sim_options.TRACK_MEMORY_ACTIONS,
        }

        try:
            angr_cfg = self.project.analyses.CFGEmulated(
                starts=starts,
                context_sensitivity_level=self.context_sensitivity_level,
                keep_state=self.keep_state,
                call_depth=call_depth,
                max_iterations=self.max_iterations,
                max_steps=self.max_steps,
                state_add_options=state_options if self.keep_state else None,
                normalize=True,
            )
            log.info(f"CFGEmulated completed: {len(angr_cfg.graph.nodes())} nodes, "
                    f"{len(angr_cfg.graph.edges())} edges")
        except Exception as e:
            log.error(f"CFGEmulated failed: {e}")
            # Fallback to CFGFast
            log.info("Falling back to CFGFast...")
            angr_cfg = self.project.analyses.CFGFast(
                normalize=True,
            )
            log.info(f"CFGFast completed: {len(angr_cfg.graph.nodes())} nodes")

        # Convert to our format
        self.complete_cfg = self._convert_angr_cfg(angr_cfg)

        log.info(f"CompleteCFG built: {self.complete_cfg.total_basic_blocks} blocks, "
                f"{len(self.complete_cfg.edges)} edges "
                f"({self.complete_cfg.static_edges} static, {self.complete_cfg.dynamic_edges} dynamic)")

        if self._discovered_libraries:
            log.info(f"Discovered libraries: {self._discovered_libraries}")
        if self._resolved_symbols:
            log.info(f"Resolved symbols: {list(self._resolved_symbols.keys())}")

        return self.complete_cfg

    def build_with_exploration(
        self,
        max_steps: int = 10000,
        timeout: int | None = None,
    ) -> CompleteCFG:
        """
        Build CFG using simulation manager exploration for more complete coverage.

        This runs full symbolic execution with DynPathResolver as an exploration
        technique, then builds the CFG from visited states.

        Args:
            max_steps: Maximum exploration steps
            timeout: Timeout in seconds (None for no timeout)

        Returns:
            CompleteCFG with full state information
        """
        from dynpathresolver.core.technique import DynPathResolver

        log.info("Starting exploration-based CFG building...")

        # Create simulation manager
        state = self.project.factory.entry_state(
            add_options={
                angr.sim_options.TRACK_REGISTER_ACTIONS,
                angr.sim_options.TRACK_MEMORY_ACTIONS,
            }
        )
        simgr = self.project.factory.simgr(state)

        # Create and attach DynPathResolver
        dpr = DynPathResolver(
            library_paths=self.library_paths,
            handle_syscall_loading=True,
            track_indirect_flow=True,
        )
        simgr.use_technique(dpr)

        # Explore
        log.info(f"Exploring with max_steps={max_steps}")
        step_count = 0
        visited_addrs: set[int] = set()
        states_at_addr: dict[int, list["angr.SimState"]] = {}

        while simgr.active and step_count < max_steps:
            simgr.step()
            step_count += 1

            # Record visited addresses and states
            for s in simgr.active:
                addr = s.addr
                visited_addrs.add(addr)
                if self.keep_state:
                    if addr not in states_at_addr:
                        states_at_addr[addr] = []
                    states_at_addr[addr].append(s.copy())

            if step_count % 1000 == 0:
                log.debug(f"Step {step_count}: {len(simgr.active)} active, "
                         f"{len(visited_addrs)} visited")

        log.info(f"Exploration completed: {step_count} steps, {len(visited_addrs)} addresses")

        # Get discoveries from DynPathResolver
        if dpr.cfg_patcher:
            for entry in dpr.cfg_patcher.discovery_log.entries:
                self._dynamic_edges.append((
                    entry['source'],
                    entry['target'],
                    entry.get('library_loaded', 'indirect')
                ))

        # Now build CFGFast and augment with exploration data
        angr_cfg = self.project.analyses.CFGFast(normalize=True)
        self.complete_cfg = self._convert_angr_cfg(angr_cfg)

        # Add state information from exploration
        for addr, states in states_at_addr.items():
            if addr in self.complete_cfg.nodes:
                node = self.complete_cfg.nodes[addr]
                for state in states[:5]:  # Limit to 5 states per node
                    node.exit_states.append(RegisterState.from_state(state))

        return self.complete_cfg

    def build_with_libraries(
        self,
        max_steps: int = 500,
    ) -> CompleteCFG:
        """
        Build CFG that includes dynamically loaded libraries.

        This method:
        1. Runs symbolic execution with DynPathResolver
        2. When dlopen is called, loads the library into the project
        3. Builds CFG for main binary + all loaded libraries
        4. Creates DYNAMIC_LOAD edges from dlopen call sites to library entry
        5. Creates INDIRECT_CALL edges from dlsym callers to resolved functions

        Args:
            max_steps: Maximum exploration steps

        Returns:
            CompleteCFG with main binary + library CFGs connected
        """
        from dynpathresolver.core.technique import DynPathResolver
        import os

        log.info("Building combined CFG with dynamic libraries...")

        # Track loaded libraries and their info
        loaded_lib_info: dict[str, dict] = {}  # path -> {base_addr, entry, functions}
        dlopen_call_sites: list[tuple[int, str]] = []  # (call_addr, lib_path)

        # Create exploration state
        state = self.project.factory.entry_state()
        simgr = self.project.factory.simgr(state)

        # Create DynPathResolver
        dpr = DynPathResolver(
            library_paths=self.library_paths,
            validation_mode='none',
        )
        simgr.use_technique(dpr)

        # Run exploration
        log.info(f"Running symbolic execution (max {max_steps} steps)...")
        simgr.run(n=max_steps)
        dpr.complete(simgr)

        # Get library load events from DynPathResolver
        for event in dpr.get_library_load_events():
            lib_path = event.library_path
            if os.path.exists(lib_path):
                log.info(f"Found library load: {lib_path}")

                # Determine the best call site address
                # Prefer using return address from call stack (first entry minus instruction size)
                call_site = event.call_site  # Default: SimProcedure address
                if event.call_stack and len(event.call_stack) > 0:
                    # First entry in call_stack is the return address
                    # For ARM64, instructions are 4 bytes; for x86_64, BL/CALL varies
                    return_addr = event.call_stack[0]
                    if return_addr > 0:
                        # Use return address - 4 for ARM64, this gives us the BL instruction
                        # For more accurate results, we could check architecture
                        instr_size = 4  # ARM64 fixed-width instructions
                        call_site = return_addr - instr_size
                        log.debug(f"Using caller address 0x{call_site:x} (return: 0x{return_addr:x})")

                dlopen_call_sites.append((call_site, lib_path))

                # Check if library is already loaded in the project
                lib_obj = None
                for obj in self.project.loader.all_objects:
                    if hasattr(obj, 'binary') and obj.binary == lib_path:
                        lib_obj = obj
                        log.debug(f"Library already loaded: {lib_path}")
                        break

                # If not already loaded, try to load it
                if lib_obj is None:
                    try:
                        loaded_objs = self.project.loader.dynamic_load(lib_path)
                        if loaded_objs:
                            lib_obj = loaded_objs[0] if isinstance(loaded_objs, list) else loaded_objs
                            log.info(f"Loaded {lib_path} at 0x{lib_obj.mapped_base:x}")
                    except Exception as e:
                        log.warning(f"Could not load library {lib_path}: {e}")

                # Record library info if we have a library object
                if lib_obj is not None:
                    loaded_lib_info[lib_path] = {
                        'base_addr': lib_obj.mapped_base,
                        'min_addr': lib_obj.min_addr,
                        'max_addr': lib_obj.max_addr,
                        'entry': getattr(lib_obj, 'entry', lib_obj.min_addr),
                        'name': os.path.basename(lib_path),
                    }
                    log.info(f"Recorded library info: {lib_path} at 0x{lib_obj.mapped_base:x}")

        # Now build CFGFast for the entire project (includes loaded libs)
        log.info("Building CFGFast for all loaded objects...")
        angr_cfg = self.project.analyses.CFGFast(normalize=True)

        # Convert to CompleteCFG
        self.complete_cfg = self._convert_angr_cfg(angr_cfg)

        # Add dynamic edges from dlopen call sites to library entries
        for call_site, lib_path in dlopen_call_sites:
            if lib_path in loaded_lib_info:
                lib_info = loaded_lib_info[lib_path]
                entry_addr = lib_info['entry']

                # Create DYNAMIC_LOAD edge
                edge = CompleteCFGEdge(
                    src_addr=call_site,
                    dst_addr=entry_addr,
                    edge_type=EdgeType.DYNAMIC_LOAD,
                    library_loaded=lib_path,
                    resolution_method='DynPathResolver',
                    confidence=1.0,
                )
                self.complete_cfg.add_edge(edge)
                log.info(f"Added edge: 0x{call_site:x} -> 0x{entry_addr:x} (dlopen {lib_info['name']})")

                # Mark the target node
                if entry_addr in self.complete_cfg.nodes:
                    self.complete_cfg.nodes[entry_addr].is_dynamic_target = True

        # Mark library functions in CFG
        for lib_path, lib_info in loaded_lib_info.items():
            lib_name = lib_info['name']
            min_addr = lib_info['min_addr']
            max_addr = lib_info['max_addr']

            for addr, node in self.complete_cfg.nodes.items():
                if min_addr <= addr <= max_addr:
                    # This node is in a loaded library
                    if not node.function_name or node.function_name.startswith('sub_'):
                        node.function_name = f"{lib_name}:0x{addr:x}"

        # Store library info
        self.complete_cfg.discovered_libraries = list(loaded_lib_info.keys())

        log.info(f"Combined CFG: {self.complete_cfg.total_basic_blocks} blocks, "
                f"{len(self.complete_cfg.edges)} edges, "
                f"{len(loaded_lib_info)} libraries loaded")

        return self.complete_cfg
