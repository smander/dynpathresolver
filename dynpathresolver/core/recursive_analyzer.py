"""
Recursive library analyzer for multi-stage loading detection.

This module analyzes discovered libraries for their own dynamic loading calls,
enabling detection of library chains (e.g., main -> libA.so -> libB.so).
"""

import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import angr
import claripy

if TYPE_CHECKING:
    from dynpathresolver.simprocedures.dlopen import DynDlopen

log = logging.getLogger(__name__)


@dataclass
class LibraryLoadSite:
    """Represents a dlopen/LoadLibrary call site within a library."""
    library_path: str  # The library containing this call site
    call_addr: int  # Address of the dlopen call
    target_library: str | None  # Resolved target library name (if determinable)
    is_symbolic: bool = False  # Whether the path is symbolic/computed


@dataclass
class DiscoveryChain:
    """Represents a chain of library loads."""
    chain: list[str] = field(default_factory=list)  # [main_binary, lib1, lib2, ...]
    depth: int = 0


class RecursiveLibraryAnalyzer:
    """
    Analyzes discovered libraries for their own dynamic loading calls.

    This enables detection of multi-stage loading where library A loads library B,
    and library B loads library C, etc.
    """

    def __init__(
        self,
        library_paths: list[str] | None = None,
        max_depth: int = 5,
        max_time_per_lib: float = 30.0,
        max_steps_per_lib: int = 5000,
    ):
        """
        Initialize the recursive analyzer.

        Args:
            library_paths: Paths to search for libraries
            max_depth: Maximum recursion depth for library chains
            max_time_per_lib: Maximum analysis time per library (seconds)
            max_steps_per_lib: Maximum symbolic execution steps per library
        """
        self.library_paths = library_paths or []
        self.max_depth = max_depth
        self.max_time_per_lib = max_time_per_lib
        self.max_steps_per_lib = max_steps_per_lib

        # Track analyzed libraries to avoid re-analysis
        self.analyzed_libraries: set[str] = set()

        # Track all discovered libraries (including from recursive analysis)
        self.all_discovered_libraries: dict[str, DiscoveryChain] = {}

        # Track load sites found in each library
        self.load_sites: dict[str, list[LibraryLoadSite]] = {}

    def analyze_library(
        self,
        library_path: str,
        parent_chain: list[str] | None = None,
        depth: int = 0,
    ) -> list[str]:
        """
        Analyze a library for dlopen calls and recursively analyze discovered libraries.

        Args:
            library_path: Path to the library to analyze
            parent_chain: Chain of libraries that led to this one
            depth: Current recursion depth

        Returns:
            List of all discovered library paths (including recursive discoveries)
        """
        if depth >= self.max_depth:
            log.warning(f"Max recursion depth {self.max_depth} reached for {library_path}")
            return []

        # Normalize path
        library_path = os.path.abspath(library_path)

        # Skip if already analyzed
        if library_path in self.analyzed_libraries:
            log.debug(f"Library already analyzed: {library_path}")
            return []

        self.analyzed_libraries.add(library_path)

        # Build chain
        chain = (parent_chain or []) + [library_path]

        log.info(f"Recursive analysis of {os.path.basename(library_path)} (depth={depth})")

        # Find dlopen call sites in this library
        load_sites = self._find_load_sites(library_path)
        self.load_sites[library_path] = load_sites

        # Collect all discovered libraries
        discovered = []

        for site in load_sites:
            if site.target_library and not site.is_symbolic:
                # Resolve the target library path
                resolved = self._resolve_library(site.target_library, library_path)
                if resolved:
                    log.info(f"  Found: {site.target_library} -> {resolved}")
                    discovered.append(resolved)

                    # Record in all_discovered_libraries
                    self.all_discovered_libraries[resolved] = DiscoveryChain(
                        chain=chain + [resolved],
                        depth=depth + 1,
                    )

                    # Recursively analyze the discovered library
                    recursive_discoveries = self.analyze_library(
                        resolved,
                        parent_chain=chain,
                        depth=depth + 1,
                    )
                    discovered.extend(recursive_discoveries)
            elif site.is_symbolic:
                log.debug(f"  Symbolic path at 0x{site.call_addr:x} - cannot resolve statically")

        return discovered

    def _find_load_sites(self, library_path: str) -> list[LibraryLoadSite]:
        """
        Find all dlopen/LoadLibrary call sites in a library.

        Uses a combination of:
        1. Static analysis to find call sites to dlopen
        2. String reference analysis to find library names
        3. Light symbolic execution to resolve computed paths
        """
        sites = []

        try:
            # Load the library as an angr project
            project = angr.Project(
                library_path,
                auto_load_libs=False,
                load_options={'main_opts': {'base_addr': 0}},
            )
        except Exception as e:
            log.warning(f"Could not load {library_path}: {e}")
            return sites

        # Method 1: Find PLT entries for dlopen
        dlopen_plt = self._find_plt_entry(project, 'dlopen')

        # Method 2: Find direct references to dlopen calls using CFG
        try:
            cfg = project.analyses.CFGFast()

            if dlopen_plt:
                # Find all call sites to dlopen PLT
                for node in cfg.graph.nodes():
                    if node.block:
                        try:
                            block = project.factory.block(node.addr)
                            for insn in block.capstone.insns:
                                if insn.mnemonic == 'call':
                                    # Check if it's calling dlopen
                                    target = self._get_call_target(insn, project)
                                    if target == dlopen_plt:
                                        site = self._analyze_dlopen_call(
                                            project, node.addr, library_path
                                        )
                                        if site:
                                            sites.append(site)
                        except Exception:
                            pass

            # Method 3: Find string references to .so files
            string_refs = self._find_library_strings(project)
            for addr, lib_name in string_refs:
                # Check if this string is used in a dlopen context
                site = LibraryLoadSite(
                    library_path=library_path,
                    call_addr=addr,
                    target_library=lib_name,
                    is_symbolic=False,
                )
                # Avoid duplicates
                if not any(s.target_library == lib_name for s in sites):
                    sites.append(site)

        except Exception as e:
            log.debug(f"CFG analysis failed for {library_path}: {e}")

        # Method 4: Light symbolic execution from exported functions
        symbolic_sites = self._symbolic_analysis(project, library_path)
        for site in symbolic_sites:
            if not any(s.target_library == site.target_library for s in sites):
                sites.append(site)

        return sites

    def _find_plt_entry(self, project: "angr.Project", symbol: str) -> int | None:
        """Find the PLT entry address for a symbol."""
        try:
            sym = project.loader.find_symbol(symbol)
            if sym:
                return sym.rebased_addr
        except Exception:
            pass

        # Try to find in PLT section
        main_obj = project.loader.main_object
        if hasattr(main_obj, 'plt'):
            for name, addr in main_obj.plt.items():
                if name == symbol:
                    return addr

        return None

    def _get_call_target(self, insn, project: "angr.Project") -> int | None:
        """Get the target address of a call instruction."""
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == 2:  # Immediate
                return op.imm
            elif op.type == 3:  # Memory
                # Indirect call through memory (like call [rip+offset])
                if hasattr(op, 'mem') and hasattr(op.mem, 'disp'):
                    # RIP-relative addressing
                    target_addr = insn.address + insn.size + op.mem.disp
                    # Read the actual target from memory
                    try:
                        target = project.loader.memory.unpack_word(target_addr)
                        return target
                    except Exception:
                        pass
        return None

    def _analyze_dlopen_call(
        self,
        project: "angr.Project",
        call_addr: int,
        library_path: str,
    ) -> LibraryLoadSite | None:
        """Analyze a dlopen call to extract the library path argument."""
        try:
            # Create state at the call site
            state = project.factory.blank_state(addr=call_addr)

            # Try to get the first argument (library path)
            # For x86_64, first arg is in rdi
            if project.arch.name == 'AMD64':
                path_ptr = state.regs.rdi
            elif project.arch.name == 'X86':
                # First arg is on stack at esp+4 (after return address)
                path_ptr = state.memory.load(state.regs.esp + 4, 4, endness='Iend_LE')
            else:
                return None

            # Try to read the string
            if state.solver.symbolic(path_ptr):
                return LibraryLoadSite(
                    library_path=library_path,
                    call_addr=call_addr,
                    target_library=None,
                    is_symbolic=True,
                )

            ptr_val = state.solver.eval(path_ptr)
            path_bytes = state.memory.load(ptr_val, 256)

            if state.solver.symbolic(path_bytes):
                return LibraryLoadSite(
                    library_path=library_path,
                    call_addr=call_addr,
                    target_library=None,
                    is_symbolic=True,
                )

            path_str = state.solver.eval(path_bytes, cast_to=bytes)
            null_idx = path_str.find(b'\x00')
            if null_idx > 0:
                path_str = path_str[:null_idx].decode('utf-8', errors='ignore')
                return LibraryLoadSite(
                    library_path=library_path,
                    call_addr=call_addr,
                    target_library=path_str,
                    is_symbolic=False,
                )

        except Exception as e:
            log.debug(f"Could not analyze dlopen call at 0x{call_addr:x}: {e}")

        return None

    def _find_library_strings(self, project: "angr.Project") -> list[tuple[int, str]]:
        """Find strings that look like library names in the binary."""
        results = []

        try:
            # Look in .rodata and .data sections
            for section in project.loader.main_object.sections:
                if section.name in ('.rodata', '.data', '.text'):
                    try:
                        data = project.loader.memory.load(
                            section.vaddr,
                            min(section.memsize, 0x100000)  # Limit to 1MB
                        )

                        # Find .so strings
                        pos = 0
                        while pos < len(data):
                            # Look for ".so" pattern
                            so_idx = data.find(b'.so', pos)
                            if so_idx == -1:
                                break

                            # Extract the full string
                            start = so_idx
                            while start > 0 and data[start-1:start] not in (b'\x00', b' ', b'\t', b'\n'):
                                start -= 1

                            end = so_idx + 3
                            while end < len(data) and data[end:end+1] not in (b'\x00', b'"', b"'"):
                                end += 1

                            lib_name = data[start:end].decode('utf-8', errors='ignore')

                            # Filter valid library names
                            if self._is_valid_library_name(lib_name):
                                addr = section.vaddr + start
                                results.append((addr, lib_name))

                            pos = so_idx + 3

                    except Exception:
                        pass

        except Exception as e:
            log.debug(f"String search failed: {e}")

        return results

    def _is_valid_library_name(self, name: str) -> bool:
        """Check if a string looks like a valid library name."""
        if not name:
            return False

        # Must end with .so or .so.N
        if not (name.endswith('.so') or '.so.' in name):
            return False

        # Must not be too long
        if len(name) > 256:
            return False

        # Should have reasonable characters
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/')
        if not all(c in valid_chars for c in name):
            return False

        # Skip standard system libraries (usually already handled)
        skip_prefixes = ('libc.so', 'libdl.so', 'libpthread.so', 'libm.so', 'ld-linux')
        if any(name.startswith(p) or name.endswith(p) for p in skip_prefixes):
            return False

        return True

    def _symbolic_analysis(
        self,
        project: "angr.Project",
        library_path: str,
    ) -> list[LibraryLoadSite]:
        """
        Run light symbolic execution from exported functions to find dlopen calls.
        """
        sites = []

        try:
            import time
            from ..simprocedures.dlopen import DynDlopen

            # Find exported functions that might call dlopen
            entry_points = []

            main_obj = project.loader.main_object
            if hasattr(main_obj, 'symbols'):
                for sym in main_obj.symbols:
                    if sym.is_function and sym.is_export:
                        entry_points.append(sym.rebased_addr)

            # Also try common entry points
            if hasattr(main_obj, 'entry'):
                entry_points.append(main_obj.entry)

            # Limit entry points to analyze
            entry_points = entry_points[:10]

            # Create a mock dlopen that records calls
            discovered_libs = []

            class RecordingDlopen(angr.SimProcedure):
                def run(self, path_ptr, flags):
                    try:
                        if not self.state.solver.symbolic(path_ptr):
                            ptr = self.state.solver.eval(path_ptr)
                            path_bytes = self.state.mem[ptr].string.concrete
                            if isinstance(path_bytes, bytes):
                                lib_name = path_bytes.decode('utf-8', errors='ignore')
                                discovered_libs.append(lib_name)
                    except Exception:
                        pass
                    return claripy.BVV(0x1000, self.state.arch.bits)

            # Hook dlopen
            dlopen_sym = project.loader.find_symbol('dlopen')
            if dlopen_sym:
                project.hook(dlopen_sym.rebased_addr, RecordingDlopen())

            # Hook by name as fallback
            try:
                project.hook_symbol('dlopen', RecordingDlopen())
            except Exception:
                pass

            # Run symbolic execution from each entry point
            start_time = time.time()

            for entry in entry_points:
                if time.time() - start_time > self.max_time_per_lib:
                    break

                try:
                    state = project.factory.call_state(entry)
                    simgr = project.factory.simulation_manager(state)

                    # Run limited exploration
                    steps = 0
                    while len(simgr.active) > 0 and steps < self.max_steps_per_lib // len(entry_points):
                        simgr.step()
                        steps += 1

                        if len(simgr.active) > 8:
                            simgr.active = simgr.active[:8]

                except Exception:
                    pass

            # Convert discovered libs to sites
            for lib_name in discovered_libs:
                if self._is_valid_library_name(lib_name):
                    sites.append(LibraryLoadSite(
                        library_path=library_path,
                        call_addr=0,  # Unknown exact address
                        target_library=lib_name,
                        is_symbolic=False,
                    ))

        except Exception as e:
            log.debug(f"Symbolic analysis failed for {library_path}: {e}")

        return sites

    def _resolve_library(self, lib_name: str, parent_library: str) -> str | None:
        """
        Resolve a library name to its full path.

        Args:
            lib_name: The library name (e.g., "libstage2.so" or "./libstage2.so")
            parent_library: Path to the library that references this one

        Returns:
            Resolved absolute path, or None if not found
        """
        # Handle relative paths
        if lib_name.startswith('./') or lib_name.startswith('../'):
            parent_dir = os.path.dirname(parent_library)
            full_path = os.path.normpath(os.path.join(parent_dir, lib_name))
            if os.path.isfile(full_path):
                return os.path.abspath(full_path)

        # Handle absolute paths
        if os.path.isabs(lib_name):
            if os.path.isfile(lib_name):
                return lib_name
            lib_name = os.path.basename(lib_name)

        # Search in configured paths
        search_paths = list(self.library_paths)

        # Add parent library's directory
        parent_dir = os.path.dirname(parent_library)
        if parent_dir and parent_dir not in search_paths:
            search_paths.insert(0, parent_dir)

        # Add current directory
        if '.' not in search_paths:
            search_paths.append('.')

        for search_dir in search_paths:
            full_path = os.path.join(search_dir, lib_name)
            if os.path.isfile(full_path):
                return os.path.abspath(full_path)

            # Also try without directory prefix in lib_name
            basename = os.path.basename(lib_name)
            full_path = os.path.join(search_dir, basename)
            if os.path.isfile(full_path):
                return os.path.abspath(full_path)

        return None

    def get_all_discovered_libraries(self) -> list[str]:
        """Get all discovered libraries including recursive discoveries."""
        return list(self.all_discovered_libraries.keys())

    def get_discovery_chain(self, library_path: str) -> DiscoveryChain | None:
        """Get the discovery chain for a library."""
        return self.all_discovered_libraries.get(os.path.abspath(library_path))

    def reset(self):
        """Reset analyzer state."""
        self.analyzed_libraries.clear()
        self.all_discovered_libraries.clear()
        self.load_sites.clear()
