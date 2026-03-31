"""Hybrid validator module for path validation via dynamic execution."""

import logging
import subprocess
import tempfile
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import claripy

from dynpathresolver.config.enums import LoadingMethod, ValidationStatus
from dynpathresolver.detection.guards import Guard, GuardDetector, GuardPatcher

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a path candidate."""

    library: str  # Library name/path
    symbol: str | None  # Resolved symbol if any
    status: ValidationStatus
    guards: list[Guard]  # Guards on this path
    concrete_inputs: bytes | None  # Inputs that trigger path
    error: str | None  # Error message if failed


@dataclass
class PathCandidate:
    """Represents a candidate path found by symbolic execution."""

    library: str  # Library to be loaded
    symbol: str | None  # Symbol to resolve (if any)
    dlopen_addr: int  # Address of dlopen call
    path_constraints: list  # Claripy constraints
    input_variables: list  # Symbolic input variables
    loading_method: LoadingMethod = LoadingMethod.UNKNOWN  # How the library is loaded


class HybridValidator:
    """Validates symbolic paths by generating concrete inputs and running dynamic execution."""

    def __init__(self, project: "angr.Project", guard_detector: GuardDetector):
        """
        Initialize the hybrid validator.

        Args:
            project: The angr project
            guard_detector: Guard detector instance for identifying anti-analysis guards
        """
        self.project = project
        self.guard_detector = guard_detector
        self._patcher = GuardPatcher(project)
        self._frida_validator: "FridaValidator | None" = None

        # Try to initialize Frida validator
        binary_path = getattr(project, 'filename', None)
        if binary_path:
            self._frida_validator = FridaValidator(binary_path)

    def generate_concrete_inputs(self, candidate: PathCandidate) -> bytes | None:
        """
        Solve path constraints to generate concrete inputs.

        Args:
            candidate: Path candidate with constraints and input variables

        Returns:
            Concrete bytes for inputs, or None if constraints unsatisfiable
        """
        # Handle empty constraints case
        if not candidate.path_constraints and not candidate.input_variables:
            return b''

        # Create solver and add constraints
        solver = claripy.Solver()

        for constraint in candidate.path_constraints:
            solver.add(constraint)

        # Check satisfiability
        if not solver.satisfiable():
            log.debug(f"Constraints unsatisfiable for {candidate.library}")
            return None

        # Generate concrete values for input variables
        result_bytes = bytearray()
        for var in candidate.input_variables:
            try:
                # Get concrete value for this variable
                concrete_val = solver.eval(var, 1)[0]

                # Convert to bytes based on variable size
                var_size = getattr(var, 'length', 64) // 8
                result_bytes.extend(concrete_val.to_bytes(var_size, 'little'))
            except Exception as e:
                log.warning(f"Could not evaluate variable: {e}")
                # Use zero bytes as fallback
                var_size = getattr(var, 'length', 64) // 8
                result_bytes.extend(b'\x00' * var_size)

        return bytes(result_bytes)

    def create_validation_harness(
        self,
        candidate: PathCandidate,
        guards: list[Guard],
    ) -> dict[str, Any]:
        """
        Generate LD_PRELOAD library and runner script for validation.

        Args:
            candidate: Path candidate to validate
            guards: Guards that need to be bypassed

        Returns:
            Dictionary containing harness configuration:
            - ld_preload_source: C source for LD_PRELOAD library (or None/empty)
            - runner_script: Shell script to run validation
            - binary_path: Path to binary under test
        """
        binary_path = getattr(self.project, 'filename', None)
        # Convert to absolute path for validation
        if binary_path and not os.path.isabs(binary_path):
            binary_path = os.path.abspath(binary_path)

        # Generate LD_PRELOAD source if there are guards to bypass
        ld_preload_source = ''
        if guards:
            ld_preload_source = self._patcher.generate_ld_preload(guards)

        # Generate runner script
        runner_script = self._generate_runner_script(
            binary_path=binary_path,
            expected_lib=candidate.library,
            use_ld_preload=bool(guards),
        )

        return {
            'ld_preload_source': ld_preload_source if ld_preload_source else None,
            'runner_script': runner_script,
            'binary_path': binary_path,
            'ld_preload_path': None,  # Will be set after compilation
        }

    def _generate_runner_script(
        self,
        binary_path: str,
        expected_lib: str,
        use_ld_preload: bool = False,
    ) -> str:
        """Generate shell script to run binary and check for dlopen calls."""
        script = f"""#!/bin/bash
# Validation runner script
# Expected library: {expected_lib}

BINARY="{binary_path}"
"""
        if use_ld_preload:
            script += """
if [ -n "$LD_PRELOAD_LIB" ]; then
    export LD_PRELOAD="$LD_PRELOAD_LIB"
fi
"""
        script += f"""
# Run with LD_DEBUG to trace library loads
LD_DEBUG=libs "$BINARY" 2>&1 | grep -q "{expected_lib}" && echo "DLOPEN:{expected_lib}"
"""
        return script

    def _validate_library_exists(self, lib_path: str) -> bool:
        """
        Validate that a library file exists and is a valid ELF.

        This is a static validation fallback when dynamic tracing fails.
        """
        if not os.path.isfile(lib_path):
            # Try relative to binary directory
            binary_path = getattr(self.project, 'filename', None)
            if binary_path:
                binary_dir = os.path.dirname(os.path.abspath(binary_path))
                alt_path = os.path.join(binary_dir, os.path.basename(lib_path))
                if os.path.isfile(alt_path):
                    lib_path = alt_path
                else:
                    return False
            else:
                return False

        # Check if it's a valid ELF file
        try:
            with open(lib_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    def _run_dynamic_validation(
        self,
        harness: dict[str, Any],
        concrete_inputs: bytes,
        expected_lib: str,
        timeout: int = 5,
        loading_method: LoadingMethod = LoadingMethod.UNKNOWN,
    ) -> tuple[bool, str | None, LoadingMethod]:
        """
        Run dynamic validation using Frida (preferred) or subprocess.
        Now traces ALL library loading mechanisms, not just dlopen.

        Args:
            harness: Harness configuration from create_validation_harness
            concrete_inputs: Concrete input bytes to provide
            expected_lib: Expected library to be loaded
            timeout: Timeout in seconds
            loading_method: Expected loading method (or UNKNOWN to auto-detect)

        Returns:
            Tuple of (path_reached, loaded_library, detected_loading_method)
        """
        binary_path = harness.get('binary_path')
        if not binary_path or not os.path.exists(binary_path):
            log.warning(f"Binary not found: {binary_path}")
            return (False, None, LoadingMethod.UNKNOWN)

        # Try Frida-based validation first (comprehensive tracing)
        if self._frida_validator and self._frida_validator._frida_available:
            log.debug(f"Using Frida for comprehensive dynamic validation of {expected_lib}")
            try:
                reached, detected_method = self._frida_validator.check_library_loaded(
                    inputs=concrete_inputs,
                    expected_lib=expected_lib,
                    timeout=timeout,
                    loading_method=loading_method,
                )
                if reached:
                    log.info(f"Frida confirmed library loading via {detected_method.value}: {expected_lib}")
                    return (True, expected_lib, detected_method)
                else:
                    log.debug(f"Frida did not detect library loading for: {expected_lib}")
            except Exception as e:
                log.debug(f"Frida validation failed, falling back to ltrace: {e}")

        # Fallback to ltrace-based validation
        binary_dir = os.path.dirname(os.path.abspath(binary_path))
        lib_basename = os.path.basename(expected_lib)

        try:
            # ltrace with comprehensive function list for all loading methods
            # dlopen: standard loading
            # memfd_create: fileless loading
            # mmap: manual loading with PROT_EXEC
            # open/fopen: file access for manual loading
            ltrace_functions = 'dlopen+memfd_create+mmap+mmap64+open+openat+fopen'

            result = subprocess.run(
                ['ltrace', '-e', ltrace_functions, binary_path],
                input=concrete_inputs,
                capture_output=True,
                timeout=timeout,
                cwd=binary_dir,
            )

            output = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')
            combined = output + stderr

            # Check for dlopen
            if 'dlopen(' in combined and (expected_lib in combined or lib_basename in combined):
                # Check if it's memfd-based dlopen
                if '/proc/self/fd/' in combined:
                    log.info(f"ltrace confirmed memfd+dlopen: {expected_lib}")
                    return (True, expected_lib, LoadingMethod.MEMFD_CREATE)
                log.info(f"ltrace confirmed dlopen: {expected_lib}")
                return (True, expected_lib, LoadingMethod.DLOPEN)

            # Check for memfd_create
            if 'memfd_create(' in combined:
                log.info(f"ltrace confirmed memfd_create: {expected_lib}")
                return (True, expected_lib, LoadingMethod.MEMFD_CREATE)

            # Check for mmap with the library (manual loading)
            if 'mmap(' in combined or 'mmap64(' in combined:
                if expected_lib in combined or lib_basename in combined:
                    log.info(f"ltrace confirmed mmap: {expected_lib}")
                    return (True, expected_lib, LoadingMethod.MMAP_EXEC)

            # Check for open/fopen with the library
            if ('open(' in combined or 'fopen(' in combined) and \
               (expected_lib in combined or lib_basename in combined):
                log.info(f"ltrace confirmed file open: {expected_lib}")
                return (True, expected_lib, LoadingMethod.MANUAL_ELF)

        except FileNotFoundError:
            log.debug("ltrace not available, falling back to strace")
        except subprocess.TimeoutExpired:
            log.debug(f"ltrace timed out after {timeout}s")
        except Exception as e:
            log.debug(f"ltrace failed: {e}")

        # Second fallback: strace for syscall-level tracing
        try:
            result = subprocess.run(
                ['strace', '-f', '-e', 'trace=openat,mmap,memfd_create', binary_path],
                input=concrete_inputs,
                capture_output=True,
                timeout=timeout,
                cwd=binary_dir,
            )

            stderr = result.stderr.decode('utf-8', errors='replace')

            # Check for memfd_create syscall
            if 'memfd_create(' in stderr:
                log.info(f"strace confirmed memfd_create: {expected_lib}")
                return (True, expected_lib, LoadingMethod.MEMFD_CREATE)

            # Check for openat with library
            if 'openat(' in stderr and (expected_lib in stderr or lib_basename in stderr):
                # Check if followed by mmap with PROT_EXEC
                if 'PROT_EXEC' in stderr:
                    log.info(f"strace confirmed mmap_exec: {expected_lib}")
                    return (True, expected_lib, LoadingMethod.MMAP_EXEC)
                log.info(f"strace confirmed file access: {expected_lib}")
                return (True, expected_lib, LoadingMethod.MANUAL_ELF)

        except FileNotFoundError:
            log.debug("strace not available, falling back to LD_DEBUG")
        except subprocess.TimeoutExpired:
            log.debug(f"strace timed out after {timeout}s")
        except Exception as e:
            log.debug(f"strace failed: {e}")

        # Third fallback: LD_DEBUG-based validation (only works for dlopen)
        try:
            env = os.environ.copy()
            env['LD_DEBUG'] = 'libs'

            if harness.get('ld_preload_path'):
                env['LD_PRELOAD'] = harness['ld_preload_path']

            result = subprocess.run(
                [binary_path],
                input=concrete_inputs,
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=binary_dir,
            )

            output = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')
            combined = output + stderr

            # Look for library loading in LD_DEBUG output
            if expected_lib in combined or lib_basename in combined:
                log.info(f"LD_DEBUG detected library reference: {expected_lib}")
                return (True, expected_lib, LoadingMethod.DLOPEN)

            return (False, None, LoadingMethod.UNKNOWN)

        except subprocess.TimeoutExpired:
            log.debug(f"Validation timed out after {timeout}s")
            return (False, None, LoadingMethod.UNKNOWN)
        except Exception as e:
            log.warning(f"Dynamic validation failed: {e}")
            return (False, None, LoadingMethod.UNKNOWN)

    def validate_candidate(
        self,
        candidate: PathCandidate,
        timeout: int = 5,
    ) -> ValidationResult:
        """
        Full validation pipeline for a path candidate.
        Now validates ALL loading methods, not just dlopen.

        Args:
            candidate: Path candidate to validate
            timeout: Timeout for dynamic execution

        Returns:
            ValidationResult with status and details
        """
        # Step 1: Generate concrete inputs
        concrete_inputs = self.generate_concrete_inputs(candidate)

        if concrete_inputs is None:
            return ValidationResult(
                library=candidate.library,
                symbol=candidate.symbol,
                status=ValidationStatus.UNVERIFIED,
                guards=[],
                concrete_inputs=None,
                error='Could not generate concrete inputs: constraints unsatisfiable',
            )

        # Step 2: Check for guards on path
        guards = self.guard_detector.get_guards_on_path(candidate)

        # Step 3: Create validation harness
        harness = self.create_validation_harness(candidate, guards)

        # Step 4: Run dynamic validation with comprehensive tracing
        reached, loaded_lib, detected_method = self._run_dynamic_validation(
            harness=harness,
            concrete_inputs=concrete_inputs,
            expected_lib=candidate.library,
            timeout=timeout,
            loading_method=candidate.loading_method,
        )

        # Step 5: Determine result status
        if guards:
            # Path is guarded - but still check if library exists
            # If it exists, it's GUARDED (valid but protected)
            if self._validate_library_exists(candidate.library):
                return ValidationResult(
                    library=candidate.library,
                    symbol=candidate.symbol,
                    status=ValidationStatus.GUARDED,
                    guards=guards,
                    concrete_inputs=concrete_inputs,
                    error=None,
                )
            else:
                return ValidationResult(
                    library=candidate.library,
                    symbol=candidate.symbol,
                    status=ValidationStatus.UNVERIFIED,
                    guards=guards,
                    concrete_inputs=concrete_inputs,
                    error='Library file not found',
                )

        if reached:
            method_str = detected_method.value if detected_method != LoadingMethod.UNKNOWN else 'unknown'
            log.info(f"Dynamically verified via {method_str}: {candidate.library}")
            return ValidationResult(
                library=candidate.library,
                symbol=candidate.symbol,
                status=ValidationStatus.VERIFIED,
                guards=[],
                concrete_inputs=concrete_inputs,
                error=None,
            )

        # Step 6: Fallback to static validation
        # If dynamic validation failed but the library file exists and is valid ELF,
        # mark as FILE_EXISTS (NOT the same as VERIFIED - we couldn't trace loading)
        if self._validate_library_exists(candidate.library):
            log.info(f"Static validation (file exists) for: {candidate.library}")
            return ValidationResult(
                library=candidate.library,
                symbol=candidate.symbol,
                status=ValidationStatus.FILE_EXISTS,
                guards=[],
                concrete_inputs=concrete_inputs,
                error='Dynamic validation failed but library file exists',
            )

        return ValidationResult(
            library=candidate.library,
            symbol=candidate.symbol,
            status=ValidationStatus.UNREACHABLE,
            guards=[],
            concrete_inputs=concrete_inputs,
            error='Path not reached during dynamic execution and library file not found',
        )

    def validate_all(
        self,
        candidates: list[PathCandidate],
        timeout: int = 5,
    ) -> list[ValidationResult]:
        """
        Validate all path candidates.

        Args:
            candidates: List of path candidates to validate
            timeout: Timeout per validation

        Returns:
            List of ValidationResult for each candidate
        """
        results = []
        for candidate in candidates:
            result = self.validate_candidate(candidate, timeout=timeout)
            results.append(result)
        return results


class FridaValidator:
    """Optional validator using Frida for dynamic instrumentation."""

    def __init__(self, binary_path: str):
        """
        Initialize Frida validator.

        Args:
            binary_path: Path to binary to instrument
        """
        # Always use absolute path
        self.binary_path = os.path.abspath(binary_path) if binary_path else binary_path
        self._frida_available = self._check_frida_available()

    def _check_frida_available(self) -> bool:
        """Check if Frida is available."""
        try:
            import frida  # noqa: F401
            return True
        except ImportError:
            log.debug("Frida not available")
            return False

    def _get_comprehensive_frida_script(self) -> str:
        """
        Generate Frida script that hooks ALL library loading mechanisms:
        - dlopen/dlsym (standard)
        - memfd_create + write (fileless loading)
        - mmap with PROT_EXEC (manual loading)
        - open + read (file-based manual loading)
        - Anti-debug bypass (ptrace, /proc/self/status)
        """
        return """
        // ============================================================
        // Comprehensive Library Loading Tracer
        // Hooks: dlopen, memfd_create, mmap, open, fopen
        // Anti-debug bypass: ptrace, /proc/self/status
        // ============================================================

        var libs_to_try = [null, "libdl.so", "libdl.so.2", "libc.so", "libc.so.6"];
        var PROT_EXEC = 4;  // Execute permission flag for mmap
        var PROT_READ = 1;

        // Track open file descriptors to correlate with mmap
        var fd_to_path = {};

        // Track .so files read via fopen (for memfd correlation)
        var fopen_so_files = [];

        // Track memfd file descriptors for correlation with dlopen
        var memfd_fds = {};

        var status_file_handles = {};

        // Find libc module first (needed for all hooks below)
        var libc_mod = null;
        Process.enumerateModules().forEach(function(mod) {
            if (mod.name.indexOf("libc") !== -1 && mod.name.indexOf(".so") !== -1) {
                libc_mod = mod;
            }
        });

        if (!libc_mod) {
            send({type: "error", msg: "libc not found - hooks will fail"});
        } else {
            send({type: "info", msg: "Found libc: " + libc_mod.name + " at " + libc_mod.base.toString()});
        }

        // ============================================================
        // ANTI-DEBUG BYPASS: Hook ptrace to always succeed
        // ============================================================
        var hooked_ptrace = false;

        // Use libc.findExportByName (works in Docker ARM64)
        if (libc_mod) {
            try {
                var ptrace_addr = libc_mod.findExportByName("ptrace");
                if (ptrace_addr) {
                    Interceptor.attach(ptrace_addr, {
                        onEnter: function(args) {
                            this.request = args[0].toInt32();
                        },
                        onLeave: function(retval) {
                            // PTRACE_TRACEME = 0, always return 0 (success)
                            if (this.request === 0) {
                                retval.replace(ptr(0));
                                send({type: "anti_debug_bypass", method: "ptrace"});
                            }
                        }
                    });
                    hooked_ptrace = true;
                    send({type: "info", msg: "Hooked ptrace via libc.findExportByName"});
                }
            } catch (e) {
                send({type: "debug", msg: "libc.findExportByName(ptrace) failed: " + e.toString()});
            }
        }

        // Fallback: use libc offset for ptrace (0xea700 in glibc 2.34 aarch64)
        if (!hooked_ptrace && libc_mod) {
            var ptrace_offsets = [0xea700, 0xea600, 0xea800];
            for (var k = 0; k < ptrace_offsets.length && !hooked_ptrace; k++) {
                try {
                    var ptrace_addr = libc_mod.base.add(ptrace_offsets[k]);
                    Interceptor.attach(ptrace_addr, {
                        onEnter: function(args) {
                            this.request = args[0].toInt32();
                        },
                        onLeave: function(retval) {
                            if (this.request === 0) {
                                retval.replace(ptr(0));
                                send({type: "anti_debug_bypass", method: "ptrace"});
                            }
                        }
                    });
                    hooked_ptrace = true;
                    send({type: "info", msg: "Hooked ptrace via offset 0x" + ptrace_offsets[k].toString(16)});
                } catch (e) {}
            }
        }

        // ============================================================
        // ANTI-DEBUG BYPASS: Hook atoi to hide TracerPid value
        // The anti-debug code does: int pid = atoi(line + 10);
        // We return 0 instead of the actual tracer PID
        // ============================================================
        // Hook atoi to bypass TracerPid check - return 0 for PID values
        // The check_proc_status function does: int pid = atoi(line + 10);
        // When reading TracerPid, atoi parses the tracer's PID (non-zero if being traced)
        if (libc_mod) {
            // Try libc.findExportByName first
            try {
                var atoi_addr = libc_mod.findExportByName("atoi");
                if (atoi_addr) {
                    var original_atoi = new NativeFunction(atoi_addr, 'int', ['pointer']);
                    Interceptor.replace(atoi_addr, new NativeCallback(function(str) {
                        var result = original_atoi(str);
                        // If result looks like a tracer PID, return 0 to hide it
                        if (result > 0 && result < 100000) {
                            send({type: "anti_debug_bypass", method: "atoi_tracerpid"});
                            return 0;
                        }
                        return result;
                    }, 'int', ['pointer']));
                    send({type: "info", msg: "Replaced atoi via libc.findExportByName"});
                }
            } catch (e) {
                // Fallback: use libc offset for atoi
                var atoi_offsets = [0x38220, 0x38200, 0x38240];
                for (var i = 0; i < atoi_offsets.length; i++) {
                    try {
                        var atoi_addr = libc_mod.base.add(atoi_offsets[i]);
                        var original_atoi = new NativeFunction(atoi_addr, 'int', ['pointer']);
                        Interceptor.replace(atoi_addr, new NativeCallback(function(str) {
                            var result = original_atoi(str);
                            if (result > 0 && result < 100000) {
                                send({type: "anti_debug_bypass", method: "atoi_tracerpid"});
                                return 0;
                            }
                            return result;
                        }, 'int', ['pointer']));
                        send({type: "info", msg: "Replaced atoi via offset 0x" + atoi_offsets[i].toString(16)});
                        break;
                    } catch (e2) {}
                }
            }
        }

        // ============================================================
        // 1. Hook dlopen (standard library loading)
        // Uses libc.findExportByName which works reliably in Docker ARM64
        // ============================================================
        var dlopen_funcs = ["dlopen", "__libc_dlopen_mode"];
        var hooked_dlopen = false;

        // Method 1: Use libc.findExportByName (works in Docker ARM64)
        if (libc_mod) {
            for (var j = 0; j < dlopen_funcs.length && !hooked_dlopen; j++) {
                try {
                    var addr = libc_mod.findExportByName(dlopen_funcs[j]);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onEnter: function(args) {
                                var path = args[0] ? args[0].readCString() : "(null)";
                                send({type: "dlopen", path: path, method: "dlopen"});

                                // Check if this is a memfd path (/proc/self/fd/N)
                                if (path && path.indexOf("/proc/self/fd/") === 0) {
                                    var fd_str = path.substring("/proc/self/fd/".length);
                                    var fd_num = parseInt(fd_str);
                                    if (memfd_fds[fd_num]) {
                                        // This is a memfd-based dlopen, report the original .so file
                                        send({type: "memfd_dlopen", path: memfd_fds[fd_num], memfd_path: path, method: "memfd_create"});
                                    }
                                }
                            }
                        });
                        send({type: "info", msg: "Hooked " + dlopen_funcs[j] + " via libc.findExportByName"});
                        hooked_dlopen = true;
                    }
                } catch (e) {
                    send({type: "debug", msg: "libc.findExportByName(" + dlopen_funcs[j] + ") failed: " + e.toString()});
                }
            }
        }

        // Method 2: Fallback using libc offset (works in Docker/emulation)
        // dlopen is at offset 0x820e0 in glibc 2.34+ (aarch64)
        if (!hooked_dlopen && libc_mod) {
            // Known offsets for dlopen in different glibc versions (aarch64)
            var offsets = [0x820e0, 0x81fe0, 0x82000, 0x80000];
            for (var k = 0; k < offsets.length && !hooked_dlopen; k++) {
                try {
                    var dlopen_addr = libc_mod.base.add(offsets[k]);
                    Interceptor.attach(dlopen_addr, {
                        onEnter: function(args) {
                            var path = args[0] ? args[0].readCString() : "(null)";
                            send({type: "dlopen", path: path, method: "dlopen"});

                            // Check if this is a memfd path
                            if (path && path.indexOf("/proc/self/fd/") === 0) {
                                var fd_str = path.substring("/proc/self/fd/".length);
                                var fd_num = parseInt(fd_str);
                                if (memfd_fds[fd_num]) {
                                    send({type: "memfd_dlopen", path: memfd_fds[fd_num], memfd_path: path, method: "memfd_create"});
                                }
                            }
                        }
                    });
                    send({type: "info", msg: "Hooked dlopen via libc offset 0x" + offsets[k].toString(16)});
                    hooked_dlopen = true;
                } catch (e) {}
            }
        }

        // ============================================================
        // 2. Hook dlsym (symbol resolution)
        // ============================================================
        for (var i = 0; i < libs_to_try.length; i++) {
            try {
                var addr = Module.findExportByName(libs_to_try[i], "dlsym");
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            var sym = args[1] ? args[1].readCString() : "(null)";
                            send({type: "dlsym", symbol: sym});
                        }
                    });
                    break;
                }
            } catch (e) {}
        }

        // ============================================================
        // 3. Hook memfd_create (fileless loading)
        // ============================================================
        try {
            var memfd_addr = Module.findExportByName(null, "memfd_create");
            if (memfd_addr) {
                Interceptor.attach(memfd_addr, {
                    onEnter: function(args) {
                        this.name = args[0] ? args[0].readCString() : "";
                    },
                    onLeave: function(retval) {
                        var fd = retval.toInt32();
                        if (fd >= 0) {
                            send({type: "memfd_create", fd: fd, name: this.name, method: "memfd_create"});
                            fd_to_path[fd] = "memfd:" + this.name;

                            // Track this memfd and associate with most recent fopen'd .so file
                            if (fopen_so_files.length > 0) {
                                memfd_fds[fd] = fopen_so_files[fopen_so_files.length - 1];
                                send({type: "info", msg: "Associated memfd " + fd + " with " + memfd_fds[fd]});
                            }
                        }
                    }
                });
                send({type: "info", msg: "Hooked memfd_create"});
            }
        } catch (e) {}

        // ============================================================
        // 4. Hook open/openat (track file descriptors)
        // Uses libc.findExportByName which works reliably in Docker ARM64
        // ============================================================
        var hooked_open = false;

        // libc_mod is already defined above in the dlopen section

        // Use libc.findExportByName (works in Docker ARM64 where Module.findExportByName fails)
        if (libc_mod) {
            try {
                var open_addr = libc_mod.findExportByName("open");
                if (open_addr) {
                    Interceptor.attach(open_addr, {
                        onEnter: function(args) {
                            this.path = args[0] ? args[0].readCString() : "";
                        },
                        onLeave: function(retval) {
                            var fd = retval.toInt32();
                            if (fd >= 0 && this.path) {
                                fd_to_path[fd] = this.path;
                                if (this.path.indexOf(".so") !== -1) {
                                    send({type: "open_so", path: this.path, fd: fd});
                                }
                            }
                        }
                    });
                    hooked_open = true;
                    send({type: "info", msg: "Hooked open via libc.findExportByName"});
                }
            } catch (e) {
                send({type: "debug", msg: "libc.findExportByName(open) failed: " + e.toString()});
            }
        }

        // Fallback: use libc offset for open (0xe3200 in glibc 2.34 aarch64)
        if (!hooked_open && libc_mod) {
            var open_offsets = [0xe3200, 0xe3100, 0xe3300];
            for (var k = 0; k < open_offsets.length && !hooked_open; k++) {
                try {
                    var open_addr = libc_mod.base.add(open_offsets[k]);
                    Interceptor.attach(open_addr, {
                        onEnter: function(args) {
                            this.path = args[0] ? args[0].readCString() : "";
                        },
                        onLeave: function(retval) {
                            var fd = retval.toInt32();
                            if (fd >= 0 && this.path) {
                                fd_to_path[fd] = this.path;
                                if (this.path.indexOf(".so") !== -1) {
                                    send({type: "open_so", path: this.path, fd: fd});
                                }
                            }
                        }
                    });
                    hooked_open = true;
                    send({type: "info", msg: "Hooked open via offset 0x" + open_offsets[k].toString(16)});
                } catch (e) {}
            }
        }

        // Hook openat (less critical, skip offset fallback for now)
        try {
            var openat_addr = Module.findExportByName(null, "openat");
            if (openat_addr) {
                Interceptor.attach(openat_addr, {
                    onEnter: function(args) {
                        this.path = args[1] ? args[1].readCString() : "";
                    },
                    onLeave: function(retval) {
                        var fd = retval.toInt32();
                        if (fd >= 0 && this.path) {
                            fd_to_path[fd] = this.path;
                            if (this.path.indexOf(".so") !== -1) {
                                send({type: "open_so", path: this.path, fd: fd});
                            }
                        }
                    }
                });
            }
        } catch (e) {}

        // ============================================================
        // 5. Hook fopen (for file reading - track .so files for memfd)
        // Uses libc.findExportByName which works reliably in Docker ARM64
        // ============================================================
        var hooked_fopen = false;

        // Use libc.findExportByName (works in Docker ARM64 where Module.findExportByName fails)
        if (libc_mod) {
            try {
                var fopen_addr = libc_mod.findExportByName("fopen");
                if (fopen_addr) {
                    Interceptor.attach(fopen_addr, {
                        onEnter: function(args) {
                            this.path = args[0] ? args[0].readCString() : "";
                        },
                        onLeave: function(retval) {
                            if (!retval.isNull() && this.path) {
                                if (this.path.indexOf(".so") !== -1) {
                                    send({type: "fopen_so", path: this.path});
                                    // Track this for memfd correlation
                                    fopen_so_files.push(this.path);
                                }
                            }
                        }
                    });
                    hooked_fopen = true;
                    send({type: "info", msg: "Hooked fopen via libc.findExportByName"});
                }
            } catch (e) {
                send({type: "debug", msg: "libc.findExportByName(fopen) failed: " + e.toString()});
            }
        }

        // Fallback: use libc offset for fopen (0x6f9e0 in glibc 2.34 aarch64)
        if (!hooked_fopen && libc_mod) {
            var fopen_offsets = [0x6f9e0, 0x6f900, 0x70000];
            for (var k = 0; k < fopen_offsets.length && !hooked_fopen; k++) {
                try {
                    var fopen_addr = libc_mod.base.add(fopen_offsets[k]);
                    Interceptor.attach(fopen_addr, {
                        onEnter: function(args) {
                            this.path = args[0] ? args[0].readCString() : "";
                        },
                        onLeave: function(retval) {
                            if (!retval.isNull() && this.path) {
                                if (this.path.indexOf(".so") !== -1) {
                                    send({type: "fopen_so", path: this.path});
                                    fopen_so_files.push(this.path);
                                }
                            }
                        }
                    });
                    hooked_fopen = true;
                    send({type: "info", msg: "Hooked fopen via offset 0x" + fopen_offsets[k].toString(16)});
                } catch (e) {}
            }
        }

        // ============================================================
        // 6. Hook mmap (detect PROT_EXEC mappings for manual ELF loading)
        // Uses libc.findExportByName which works reliably in Docker ARM64
        // ============================================================
        var hooked_mmap = false;

        // Use libc.findExportByName (works in Docker ARM64 where Module.findExportByName fails)
        if (libc_mod) {
            try {
                var mmap_addr = libc_mod.findExportByName("mmap");
                if (mmap_addr) {
                    Interceptor.attach(mmap_addr, {
                        onEnter: function(args) {
                            this.addr = args[0];
                            this.length = args[1].toInt32();
                            this.prot = args[2].toInt32();
                            this.flags = args[3].toInt32();
                            this.fd = args[4].toInt32();
                            this.offset = args[5] ? args[5].toInt32() : 0;
                        },
                        onLeave: function(retval) {
                            if ((this.prot & PROT_EXEC) !== 0 && this.fd >= 0) {
                                var path = fd_to_path[this.fd] || "unknown";
                                send({type: "mmap_exec", path: path, fd: this.fd, prot: this.prot, length: this.length, result: retval.toString(), method: "mmap_exec"});
                            } else if ((this.prot & PROT_EXEC) !== 0 && this.fd === -1) {
                                send({type: "mmap_anon_exec", prot: this.prot, length: this.length, result: retval.toString(), method: "manual_elf"});
                            }
                        }
                    });
                    hooked_mmap = true;
                    send({type: "info", msg: "Hooked mmap via libc.findExportByName"});
                }
            } catch (e) {
                send({type: "debug", msg: "libc.findExportByName(mmap) failed: " + e.toString()});
            }
        }

        // Fallback: use libc offset for mmap (0xe9ba0 in glibc 2.34 aarch64)
        if (!hooked_mmap && libc_mod) {
            var mmap_offsets = [0xe9ba0, 0xe9b00, 0xe9c00];
            for (var k = 0; k < mmap_offsets.length && !hooked_mmap; k++) {
                try {
                    var mmap_addr = libc_mod.base.add(mmap_offsets[k]);
                    Interceptor.attach(mmap_addr, {
                        onEnter: function(args) {
                            this.prot = args[2].toInt32();
                            this.fd = args[4].toInt32();
                            this.length = args[1].toInt32();
                        },
                        onLeave: function(retval) {
                            if ((this.prot & PROT_EXEC) !== 0 && this.fd >= 0) {
                                var path = fd_to_path[this.fd] || "unknown";
                                send({type: "mmap_exec", path: path, fd: this.fd, prot: this.prot, method: "mmap_exec"});
                            } else if ((this.prot & PROT_EXEC) !== 0 && this.fd === -1) {
                                send({type: "mmap_anon_exec", prot: this.prot, length: this.length, method: "manual_elf"});
                            }
                        }
                    });
                    hooked_mmap = true;
                    send({type: "info", msg: "Hooked mmap via offset 0x" + mmap_offsets[k].toString(16)});
                } catch (e) {}
            }
        }

        // ============================================================
        // 7. Hook mmap64 (alternative on some systems)
        // ============================================================
        try {
            var mmap64_addr = Module.findExportByName(null, "mmap64");
            if (mmap64_addr) {
                Interceptor.attach(mmap64_addr, {
                    onEnter: function(args) {
                        this.prot = args[2].toInt32();
                        this.fd = args[4].toInt32();
                    },
                    onLeave: function(retval) {
                        if ((this.prot & PROT_EXEC) !== 0 && this.fd >= 0) {
                            var path = fd_to_path[this.fd] || "unknown";
                            send({
                                type: "mmap_exec",
                                path: path,
                                fd: this.fd,
                                method: "mmap_exec"
                            });
                        }
                    }
                });
            }
        } catch (e) {}

        // ============================================================
        // 8. Hook close (cleanup fd tracking - but keep for correlation)
        // ============================================================
        try {
            var close_addr = Module.findExportByName(null, "close");
            if (close_addr) {
                Interceptor.attach(close_addr, {
                    onEnter: function(args) {
                        // Don't delete immediately - we may need for correlation
                        // var fd = args[0].toInt32();
                        // if (fd in fd_to_path) {
                        //     delete fd_to_path[fd];
                        // }
                    }
                });
            }
        } catch (e) {}

        send({type: "info", msg: "Comprehensive library loading tracer initialized (with anti-debug bypass)"});
        """

    def _attach_and_trace_all(
        self,
        inputs: bytes,
        timeout: int,
    ) -> dict[str, Any]:
        """
        Attach to process and trace ALL library loading calls using Frida.

        Args:
            inputs: Input bytes to provide to process
            timeout: Timeout in seconds

        Returns:
            Dictionary with loading events categorized by method
        """
        if not self._frida_available:
            return {
                'dlopen_calls': [],
                'mmap_exec_calls': [],
                'memfd_creates': [],
                'memfd_dlopen_calls': [],  # Correlation: fopen .so -> memfd -> dlopen /proc/self/fd/N
                'open_so_calls': [],
                'fopen_so_calls': [],
                'anti_debug_bypassed': False,
                'reached': False,
                'loading_method': LoadingMethod.UNKNOWN,
            }

        import frida

        import threading

        dlopen_calls = []
        mmap_exec_calls = []
        memfd_creates = []
        memfd_dlopen_calls = []  # Tracks correlated memfd->dlopen with original .so path
        open_so_calls = []
        fopen_so_calls = []
        anti_debug_bypassed = [False]  # Use list for mutability in closure
        event_received = threading.Event()  # Signal when a library loading event is received

        script_code = self._get_comprehensive_frida_script()

        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type', '')

                if msg_type == 'dlopen':
                    path = payload.get('path', '')
                    log.debug(f"Frida: dlopen called with: {path}")
                    dlopen_calls.append(path)
                    event_received.set()  # Signal that we got an event

                elif msg_type == 'memfd_dlopen':
                    # This is a correlated memfd->dlopen call with the original .so path
                    original_path = payload.get('path', '')
                    memfd_path = payload.get('memfd_path', '')
                    log.debug(f"Frida: memfd dlopen {memfd_path} -> original: {original_path}")
                    memfd_dlopen_calls.append(original_path)
                    event_received.set()

                elif msg_type == 'mmap_exec':
                    path = payload.get('path', '')
                    log.debug(f"Frida: mmap with PROT_EXEC for: {path}")
                    mmap_exec_calls.append(path)
                    event_received.set()

                elif msg_type == 'mmap_anon_exec':
                    # Anonymous executable mapping - likely manual ELF loading
                    log.debug(f"Frida: anonymous mmap with PROT_EXEC (manual ELF)")
                    # We'll correlate this with open_so_calls
                    event_received.set()

                elif msg_type == 'memfd_create':
                    fd = payload.get('fd', -1)
                    name = payload.get('name', '')
                    log.debug(f"Frida: memfd_create fd={fd} name={name}")
                    memfd_creates.append({'fd': fd, 'name': name})
                    event_received.set()

                elif msg_type == 'open_so':
                    path = payload.get('path', '')
                    log.debug(f"Frida: open() on .so file: {path}")
                    open_so_calls.append(path)
                    event_received.set()

                elif msg_type == 'fopen_so':
                    path = payload.get('path', '')
                    log.debug(f"Frida: fopen() on .so file: {path}")
                    fopen_so_calls.append(path)
                    event_received.set()

                elif msg_type == 'anti_debug_bypass':
                    method = payload.get('method', '')
                    log.debug(f"Frida: Anti-debug bypassed via {method}")
                    anti_debug_bypassed[0] = True

                elif msg_type == 'dlsym':
                    log.debug(f"Frida: dlsym called with: {payload.get('symbol', '')}")

                elif msg_type == 'info':
                    log.debug(f"Frida: {payload.get('msg', '')}")

                elif msg_type == 'error':
                    log.warning(f"Frida: {payload.get('msg', '')}")

            elif message['type'] == 'error':
                log.warning(f"Frida script error: {message.get('description', message)}")

        try:
            binary_dir = os.path.dirname(os.path.abspath(self.binary_path))
            pid = frida.spawn([self.binary_path], cwd=binary_dir, stdio='pipe')
            session = frida.attach(pid)

            script = session.create_script(script_code)
            script.on('message', on_message)
            script.load()

            # Small delay to ensure hooks are fully set up before process resumes
            # Critical for fast-executing binaries that use manual ELF loading (open+mmap)
            import time
            time.sleep(0.1)

            frida.resume(pid)

            # Wait for process to finish or timeout
            # Use a simple sleep approach - the process typically finishes quickly
            # and we need to give Frida's message loop time to process events
            try:
                import time
                # Simple approach: sleep for a reasonable time (min of timeout and 3 seconds)
                # Most library loading happens early in process execution
                wait_time = min(timeout, 3)
                time.sleep(wait_time)

                # If we got events early, we're done. If not, wait a bit more.
                if not (dlopen_calls or mmap_exec_calls or memfd_creates):
                    # No events yet, wait up to remaining timeout
                    remaining = timeout - wait_time
                    if remaining > 0:
                        event_received.wait(timeout=remaining)
            except Exception:
                pass
            finally:
                # Clean up Frida session with timeout protection
                # session.detach() can hang if process already exited in some environments
                # Use threading-based timeout which is more reliable than signal.alarm

                def detach_with_timeout(sess, timeout_sec=2):
                    """Detach session with timeout using a daemon thread."""
                    import threading
                    result = [False]

                    def do_detach():
                        try:
                            sess.detach()
                            result[0] = True
                        except Exception:
                            pass

                    t = threading.Thread(target=do_detach, daemon=True)
                    t.start()
                    t.join(timeout=timeout_sec)
                    # If thread is still alive, detach hung - just continue
                    return result[0]

                # Skip detach if session already detached
                if not session.is_detached:
                    detach_with_timeout(session, timeout_sec=2)

                # Kill the process if still running
                try:
                    frida.kill(pid)
                except Exception:
                    pass

            # Determine primary loading method
            loading_method = LoadingMethod.UNKNOWN
            reached = False

            if memfd_dlopen_calls:
                # Correlated memfd->dlopen with original .so path
                loading_method = LoadingMethod.MEMFD_CREATE
                reached = True
            elif dlopen_calls:
                # Check if it's memfd-based dlopen (by path pattern)
                if any('/proc/self/fd/' in path or 'memfd:' in path for path in dlopen_calls):
                    loading_method = LoadingMethod.MEMFD_CREATE
                else:
                    loading_method = LoadingMethod.DLOPEN
                reached = True
            elif mmap_exec_calls:
                loading_method = LoadingMethod.MMAP_EXEC
                reached = True
            elif memfd_creates:
                loading_method = LoadingMethod.MEMFD_CREATE
                reached = True
            elif open_so_calls or fopen_so_calls:
                # Opened .so but didn't mmap with exec - might be manual ELF
                loading_method = LoadingMethod.MANUAL_ELF
                reached = True

            return {
                'dlopen_calls': dlopen_calls,
                'mmap_exec_calls': mmap_exec_calls,
                'memfd_creates': memfd_creates,
                'memfd_dlopen_calls': memfd_dlopen_calls,
                'open_so_calls': open_so_calls,
                'fopen_so_calls': fopen_so_calls,
                'anti_debug_bypassed': anti_debug_bypassed[0],
                'reached': reached,
                'loading_method': loading_method,
            }

        except Exception as e:
            log.warning(f"Frida tracing failed: {e}")
            return {
                'dlopen_calls': [],
                'mmap_exec_calls': [],
                'memfd_creates': [],
                'memfd_dlopen_calls': [],
                'open_so_calls': [],
                'fopen_so_calls': [],
                'anti_debug_bypassed': False,
                'reached': False,
                'loading_method': LoadingMethod.UNKNOWN,
            }

    def _attach_and_trace(
        self,
        inputs: bytes,
        timeout: int,
    ) -> dict[str, Any]:
        """
        Attach to process and trace dlopen calls using Frida.
        Legacy method - now wraps _attach_and_trace_all for backward compatibility.

        Args:
            inputs: Input bytes to provide to process
            timeout: Timeout in seconds

        Returns:
            Dictionary with dlopen_calls and reached status
        """
        result = self._attach_and_trace_all(inputs, timeout)
        return {
            'dlopen_calls': result['dlopen_calls'],
            'reached': result['reached'],
        }

    def check_library_loaded(
        self,
        inputs: bytes,
        expected_lib: str,
        timeout: int = 5,
        loading_method: LoadingMethod = LoadingMethod.UNKNOWN,
    ) -> tuple[bool, LoadingMethod]:
        """
        Run binary and check if library was loaded via ANY method.

        Args:
            inputs: Input bytes to provide
            expected_lib: Expected library path/name
            timeout: Timeout in seconds
            loading_method: Expected loading method (or UNKNOWN to detect)

        Returns:
            Tuple of (library_loaded, detected_loading_method)
        """
        try:
            result = self._attach_and_trace_all(inputs, timeout)

            lib_basename = os.path.basename(expected_lib)

            def matches_lib(path: str) -> bool:
                """Check if path matches expected library."""
                if not path:
                    return False
                path_basename = os.path.basename(path)
                return (expected_lib in path or
                        lib_basename in path or
                        path in expected_lib or
                        lib_basename == path_basename)

            # Check memfd_dlopen calls (correlated fopen .so -> memfd -> dlopen)
            for lib in result.get('memfd_dlopen_calls', []):
                if matches_lib(lib):
                    log.info(f"Library loaded via memfd_create (correlated): {expected_lib}")
                    return (True, LoadingMethod.MEMFD_CREATE)

            # Check dlopen calls
            for lib in result.get('dlopen_calls', []):
                if matches_lib(lib):
                    detected_method = result.get('loading_method', LoadingMethod.DLOPEN)
                    log.info(f"Library loaded via {detected_method.value}: {expected_lib}")
                    return (True, detected_method)

            # Check mmap_exec calls (for manual ELF loading like benchmark 12, 13)
            for lib in result.get('mmap_exec_calls', []):
                if matches_lib(lib):
                    log.info(f"Library loaded via mmap_exec: {expected_lib}")
                    return (True, LoadingMethod.MMAP_EXEC)

            # Check open_so calls (for manual ELF loading)
            for lib in result.get('open_so_calls', []):
                if matches_lib(lib):
                    # If we saw mmap_exec on this file, it's mmap_exec
                    if any(matches_lib(m) for m in result.get('mmap_exec_calls', [])):
                        log.info(f"Library loaded via mmap_exec: {expected_lib}")
                        return (True, LoadingMethod.MMAP_EXEC)
                    else:
                        # open() without mmap_exec might still be manual ELF loading
                        # (mmap_exec might have "unknown" path if fd wasn't tracked)
                        if result.get('mmap_exec_calls'):
                            log.info(f"Library loaded via mmap_exec (inferred): {expected_lib}")
                            return (True, LoadingMethod.MMAP_EXEC)
                        log.info(f"Library opened (manual ELF): {expected_lib}")
                        return (True, LoadingMethod.MANUAL_ELF)

            # Check fopen_so calls (for memfd_create pattern)
            for lib in result.get('fopen_so_calls', []):
                if matches_lib(lib):
                    log.info(f"Library fopened (memfd/manual): {expected_lib}")
                    # fopen is typically used with memfd_create for reading before writing
                    if result.get('memfd_creates'):
                        return (True, LoadingMethod.MEMFD_CREATE)
                    return (True, LoadingMethod.MANUAL_ELF)

            # Check memfd_creates with fopen correlation
            if result.get('memfd_creates') and result.get('fopen_so_calls'):
                # We have memfd_create and fopen'd a .so - check if expected lib was fopen'd
                for lib in result.get('fopen_so_calls', []):
                    if matches_lib(lib):
                        log.info(f"Library loaded via memfd_create (fopen correlation): {expected_lib}")
                        return (True, LoadingMethod.MEMFD_CREATE)

            # Generic memfd detection (may have loaded without specific library name)
            if result.get('memfd_creates') and result.get('reached'):
                log.info(f"memfd_create detected - library likely loaded filelessly")
                return (True, LoadingMethod.MEMFD_CREATE)

            return (False, result.get('loading_method', LoadingMethod.UNKNOWN))

        except TimeoutError:
            log.debug(f"Frida validation timed out after {timeout}s")
            return (False, LoadingMethod.UNKNOWN)
        except Exception as e:
            log.warning(f"Frida validation failed: {e}")
            return (False, LoadingMethod.UNKNOWN)

    def check_dlopen_called(
        self,
        inputs: bytes,
        expected_lib: str,
        timeout: int = 5,
    ) -> bool:
        """
        Run binary and check if dlopen was called with expected library.
        Legacy method - now uses comprehensive tracing.

        Args:
            inputs: Input bytes to provide
            expected_lib: Expected library path
            timeout: Timeout in seconds

        Returns:
            True if library was loaded (via any method)
        """
        loaded, _ = self.check_library_loaded(inputs, expected_lib, timeout)
        return loaded
