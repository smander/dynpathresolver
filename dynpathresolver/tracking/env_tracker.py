"""
Environment variable tracking for security-relevant variables.

This module tracks LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, and other
environment variables that can be used for library injection.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)

# Security-relevant environment variables
SECURITY_ENV_VARS = {
    # Library injection
    'LD_PRELOAD': 'Preload libraries before any others',
    'LD_AUDIT': 'Runtime linker auditing interface',
    'LD_LIBRARY_PATH': 'Additional library search paths',
    # Debug/tracing
    'LD_DEBUG': 'Runtime linker debugging',
    'LD_DEBUG_OUTPUT': 'Debug output file',
    'LD_TRACE_LOADED_OBJECTS': 'Trace library loading',
    # Other security-relevant
    'LD_BIND_NOW': 'Resolve all symbols at startup',
    'LD_BIND_NOT': 'Don\'t update GOT/PLT after binding',
    'LD_DYNAMIC_WEAK': 'Allow weak symbol interposition',
}


@dataclass
class EnvironmentVariable:
    """Represents a tracked environment variable."""

    name: str
    value: str
    source: str = "initial"  # 'initial', 'setenv', 'putenv', 'unsetenv'
    state_addr: int = 0
    step: int = 0
    is_security_relevant: bool = False


@dataclass
class LdPreloadEntry:
    """Represents a library from LD_PRELOAD."""

    path: str
    index: int  # Position in LD_PRELOAD list
    state_addr: int = 0
    step: int = 0


@dataclass
class LdAuditEntry:
    """Represents an audit library from LD_AUDIT."""

    path: str
    state_addr: int = 0
    step: int = 0


class EnvironmentTracker:
    """
    Tracks security-relevant environment variables.

    This class:
    1. Scans initial environment for LD_PRELOAD, LD_AUDIT, etc.
    2. Hooks setenv/putenv/unsetenv to track changes
    3. Parses LD_PRELOAD and LD_AUDIT for injection detection
    4. Tracks LD_LIBRARY_PATH modifications
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Tracked variables
        self.variables: dict[str, EnvironmentVariable] = {}
        self.ld_preload_entries: list[LdPreloadEntry] = []
        self.ld_audit_entries: list[LdAuditEntry] = []

        # Statistics
        self.total_setenv: int = 0
        self.total_putenv: int = 0
        self.total_unsetenv: int = 0

    def scan_initial_env(self, state: "angr.SimState") -> None:
        """
        Scan initial environment for security-relevant variables.

        This should be called at the start of symbolic execution with
        the initial state to capture the starting environment.

        Args:
            state: The initial symbolic state
        """
        # Try to extract environment from state
        # This is architecture and OS dependent
        try:
            # Common approach: envp is typically passed as third argument to main
            # or accessible via environ global
            self._scan_environ_symbol(state)
        except Exception as e:
            log.debug(f"Could not scan initial environment: {e}")

    def _scan_environ_symbol(self, state: "angr.SimState") -> None:
        """Scan environment via 'environ' symbol if available."""
        # Find environ symbol
        environ_sym = self.project.loader.find_symbol('environ')
        if not environ_sym:
            environ_sym = self.project.loader.find_symbol('__environ')
        if not environ_sym:
            log.debug("Could not find environ symbol")
            return

        # Read environ pointer
        try:
            ptr_size = state.arch.bytes
            environ_ptr = state.mem[environ_sym.rebased_addr].uint64_t.concrete \
                if ptr_size == 8 else state.mem[environ_sym.rebased_addr].uint32_t.concrete

            if environ_ptr == 0:
                return

            # Read environment strings
            max_vars = 1000
            for i in range(max_vars):
                env_entry_addr = environ_ptr + (i * ptr_size)
                if ptr_size == 8:
                    str_ptr = state.mem[env_entry_addr].uint64_t.concrete
                else:
                    str_ptr = state.mem[env_entry_addr].uint32_t.concrete

                if str_ptr == 0:
                    break

                # Read the string
                env_str = self._read_string(state, str_ptr)
                if env_str and '=' in env_str:
                    name, value = env_str.split('=', 1)
                    self._record_variable(name, value, "initial", 0, 0)

        except Exception as e:
            log.debug(f"Error scanning environ: {e}")

    def _read_string(self, state: "angr.SimState", ptr: int,
                    max_len: int = 4096) -> str | None:
        """Read a null-terminated string from memory."""
        try:
            string_bytes = state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception:
            return None

    def _record_variable(self, name: str, value: str, source: str,
                        state_addr: int, step: int) -> EnvironmentVariable:
        """Record an environment variable."""
        is_security = name in SECURITY_ENV_VARS

        var = EnvironmentVariable(
            name=name,
            value=value,
            source=source,
            state_addr=state_addr,
            step=step,
            is_security_relevant=is_security,
        )
        self.variables[name] = var

        # Parse LD_PRELOAD and LD_AUDIT
        if name == 'LD_PRELOAD':
            self._parse_ld_preload(value, state_addr, step)
        elif name == 'LD_AUDIT':
            self._parse_ld_audit(value, state_addr, step)

        if is_security:
            log.warning(f"Security-relevant env var: {name}={value}")

        return var

    def _parse_ld_preload(self, value: str, state_addr: int, step: int) -> None:
        """Parse LD_PRELOAD value into individual libraries."""
        self.ld_preload_entries.clear()

        # LD_PRELOAD can be space or colon separated
        separators = ' :' if ' ' in value or ':' in value else ' '
        paths = value.replace(':', ' ').split()

        for i, path in enumerate(paths):
            path = path.strip()
            if path:
                entry = LdPreloadEntry(
                    path=path,
                    index=i,
                    state_addr=state_addr,
                    step=step,
                )
                self.ld_preload_entries.append(entry)
                log.warning(f"LD_PRELOAD[{i}]: {path}")

    def _parse_ld_audit(self, value: str, state_addr: int, step: int) -> None:
        """Parse LD_AUDIT value into individual audit libraries."""
        self.ld_audit_entries.clear()

        # LD_AUDIT is colon-separated
        paths = value.split(':')

        for path in paths:
            path = path.strip()
            if path:
                entry = LdAuditEntry(
                    path=path,
                    state_addr=state_addr,
                    step=step,
                )
                self.ld_audit_entries.append(entry)
                log.warning(f"LD_AUDIT: {path}")

    def record_setenv(self, state: "angr.SimState", name: str,
                      value: str, overwrite: int = 1) -> None:
        """
        Record a setenv() call.

        Args:
            state: Current symbolic state
            name: Environment variable name
            value: Environment variable value
            overwrite: Whether to overwrite existing (1) or not (0)
        """
        self.total_setenv += 1

        # Check if we should overwrite
        if name in self.variables and overwrite == 0:
            log.debug(f"setenv: {name} exists and overwrite=0, skipping")
            return

        step = state.history.depth if state.history else 0
        self._record_variable(name, value, "setenv", state.addr, step)

        log.info(f"setenv: {name}={value}")

    def record_putenv(self, state: "angr.SimState", string: str) -> None:
        """
        Record a putenv() call.

        Args:
            state: Current symbolic state
            string: Environment string in "NAME=VALUE" format
        """
        self.total_putenv += 1

        if '=' not in string:
            log.warning(f"putenv: invalid string (no '='): {string}")
            return

        name, value = string.split('=', 1)
        step = state.history.depth if state.history else 0
        self._record_variable(name, value, "putenv", state.addr, step)

        log.info(f"putenv: {name}={value}")

    def record_unsetenv(self, state: "angr.SimState", name: str) -> None:
        """
        Record an unsetenv() call.

        Args:
            state: Current symbolic state
            name: Environment variable name to unset
        """
        self.total_unsetenv += 1

        if name in self.variables:
            del self.variables[name]

        # Also clear parsed entries if relevant
        if name == 'LD_PRELOAD':
            self.ld_preload_entries.clear()
        elif name == 'LD_AUDIT':
            self.ld_audit_entries.clear()

        log.info(f"unsetenv: {name}")

    # === Query Methods ===

    def get_ld_preload(self) -> list[str]:
        """Get list of LD_PRELOAD library paths."""
        return [e.path for e in self.ld_preload_entries]

    def get_ld_audit(self) -> list[str]:
        """Get list of LD_AUDIT library paths."""
        return [e.path for e in self.ld_audit_entries]

    def get_ld_library_path(self) -> list[str]:
        """Get LD_LIBRARY_PATH as list of directories."""
        if 'LD_LIBRARY_PATH' not in self.variables:
            return []
        value = self.variables['LD_LIBRARY_PATH'].value
        return [p.strip() for p in value.split(':') if p.strip()]

    def get_security_variables(self) -> list[EnvironmentVariable]:
        """Get all security-relevant environment variables."""
        return [v for v in self.variables.values() if v.is_security_relevant]

    def has_library_injection(self) -> bool:
        """Check if any library injection variables are set."""
        return bool(self.ld_preload_entries) or bool(self.ld_audit_entries)

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_variables': len(self.variables),
            'security_variables': len(self.get_security_variables()),
            'ld_preload_count': len(self.ld_preload_entries),
            'ld_audit_count': len(self.ld_audit_entries),
            'total_setenv': self.total_setenv,
            'total_putenv': self.total_putenv,
            'total_unsetenv': self.total_unsetenv,
        }

    def reset(self) -> None:
        """Reset all tracking state."""
        self.variables.clear()
        self.ld_preload_entries.clear()
        self.ld_audit_entries.clear()
        self.total_setenv = 0
        self.total_putenv = 0
        self.total_unsetenv = 0
