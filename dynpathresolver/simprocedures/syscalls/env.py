"""
SimProcedures for environment manipulation functions.

These procedures intercept setenv, putenv, unsetenv, and getenv
to track security-relevant environment variable changes.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import ENV_ALLOC_BASE

if TYPE_CHECKING:
    from ...env_tracker import EnvironmentTracker

log = logging.getLogger(__name__)


class DynSetenv(angr.SimProcedure):
    """
    SimProcedure for setenv() that tracks environment changes.

    Signature: int setenv(const char *name, const char *value, int overwrite)

    This procedure:
    1. Extracts name and value from memory
    2. Records the change in EnvironmentTracker
    3. Detects security-relevant changes (LD_PRELOAD, etc.)
    """

    # Class-level configuration (set by DynPathResolver)
    env_tracker: "EnvironmentTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_env_tracker(self):
        """Get env_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_env_tracker', self.__class__.env_tracker)
        return self.__class__.env_tracker

    def run(self, name, value, overwrite):
        """
        Simulate setenv(name, value, overwrite).

        Args:
            name: Pointer to variable name
            value: Pointer to variable value
            overwrite: Whether to overwrite existing (1) or not (0)

        Returns:
            0 on success, -1 on error
        """
        # Extract name
        name_str = self._get_string(name)
        if name_str is None:
            log.warning("setenv: Could not resolve name")
            return claripy.BVV(-1, self.state.arch.bits)

        # Extract value
        value_str = self._get_string(value)
        if value_str is None:
            value_str = ""

        # Get overwrite flag
        overwrite_val = self._concretize(overwrite, 1)

        log.debug(f"setenv: {name_str}={value_str}, overwrite={overwrite_val}")

        # Record in environment tracker
        env_tracker = self._get_env_tracker()
        if env_tracker:
            env_tracker.record_setenv(
                state=self.state,
                name=name_str,
                value=value_str,
                overwrite=overwrite_val,
            )

        # Notify technique about security-relevant changes
        if name_str in ('LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH'):
            self._notify_technique(name_str, value_str)

        return claripy.BVV(0, self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory at pointer."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        if ptr == 0:
            return None

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"setenv: Error reading string: {e}")
            return None

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _notify_technique(self, name: str, value: str) -> None:
        """Notify technique about security-relevant env change."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_env_change'):
            try:
                technique._record_env_change(
                    state=self.state,
                    name=name,
                    value=value,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.env_tracker = None
        cls.technique = None


class DynPutenv(angr.SimProcedure):
    """
    SimProcedure for putenv() that tracks environment changes.

    Signature: int putenv(char *string)

    This procedure parses "NAME=VALUE" format strings.
    """

    # Class-level configuration (set by DynPathResolver)
    env_tracker: "EnvironmentTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_env_tracker(self):
        """Get env_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_env_tracker', self.__class__.env_tracker)
        return self.__class__.env_tracker

    def run(self, string):
        """
        Simulate putenv(string).

        Args:
            string: Pointer to "NAME=VALUE" string

        Returns:
            0 on success, non-zero on error
        """
        # Extract string
        env_str = self._get_string(string)
        if env_str is None:
            log.warning("putenv: Could not resolve string")
            return claripy.BVV(-1, self.state.arch.bits)

        log.debug(f"putenv: {env_str}")

        # Record in environment tracker
        env_tracker = self._get_env_tracker()
        if env_tracker:
            env_tracker.record_putenv(
                state=self.state,
                string=env_str,
            )

        # Check for security-relevant changes
        if '=' in env_str:
            name = env_str.split('=', 1)[0]
            if name in ('LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH'):
                value = env_str.split('=', 1)[1] if '=' in env_str else ""
                self._notify_technique(name, value)

        return claripy.BVV(0, self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory at pointer."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        if ptr == 0:
            return None

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"putenv: Error reading string: {e}")
            return None

    def _notify_technique(self, name: str, value: str) -> None:
        """Notify technique about security-relevant env change."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_env_change'):
            try:
                technique._record_env_change(
                    state=self.state,
                    name=name,
                    value=value,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.env_tracker = None
        cls.technique = None


class DynUnsetenv(angr.SimProcedure):
    """
    SimProcedure for unsetenv() that tracks environment changes.

    Signature: int unsetenv(const char *name)
    """

    # Class-level configuration (set by DynPathResolver)
    env_tracker: "EnvironmentTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_env_tracker(self):
        """Get env_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_env_tracker', self.__class__.env_tracker)
        return self.__class__.env_tracker

    def run(self, name):
        """
        Simulate unsetenv(name).

        Args:
            name: Pointer to variable name

        Returns:
            0 on success, -1 on error
        """
        # Extract name
        name_str = self._get_string(name)
        if name_str is None:
            log.warning("unsetenv: Could not resolve name")
            return claripy.BVV(-1, self.state.arch.bits)

        log.debug(f"unsetenv: {name_str}")

        # Record in environment tracker
        env_tracker = self._get_env_tracker()
        if env_tracker:
            env_tracker.record_unsetenv(
                state=self.state,
                name=name_str,
            )

        return claripy.BVV(0, self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory at pointer."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        if ptr == 0:
            return None

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"unsetenv: Error reading string: {e}")
            return None

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.env_tracker = None
        cls.technique = None


class DynGetenv(angr.SimProcedure):
    """
    SimProcedure for getenv() that tracks environment access.

    Signature: char *getenv(const char *name)

    Note: This is primarily for tracking which env vars are accessed.
    """

    # Class-level configuration (set by DynPathResolver)
    env_tracker: "EnvironmentTracker | None" = None
    technique: "object | None" = None

    # Simulated environment for returning values
    _env_values: dict[str, int] = {}  # name -> allocated string address
    _alloc_base: int = ENV_ALLOC_BASE

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_env_tracker(self):
        """Get env_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_env_tracker', self.__class__.env_tracker)
        return self.__class__.env_tracker

    def run(self, name):
        """
        Simulate getenv(name).

        Args:
            name: Pointer to variable name

        Returns:
            Pointer to value string, or NULL (0)
        """
        # Extract name
        name_str = self._get_string(name)
        if name_str is None:
            return claripy.BVV(0, self.state.arch.bits)

        log.debug(f"getenv: {name_str}")

        # Check if we have a tracked value
        env_tracker = self._get_env_tracker()
        if env_tracker and name_str in env_tracker.variables:
            var = env_tracker.variables[name_str]
            # Return a pointer to the value
            # In reality, we'd need to allocate memory for this
            return self._get_value_ptr(name_str, var.value)

        # Return NULL for unknown variables
        return claripy.BVV(0, self.state.arch.bits)

    def _get_string(self, ptr) -> str | None:
        """Extract string from memory at pointer."""
        if self.state.solver.symbolic(ptr):
            if self.state.solver.satisfiable():
                ptr = self.state.solver.eval(ptr)
            else:
                return None

        if ptr == 0:
            return None

        try:
            string_bytes = self.state.mem[ptr].string.concrete
            if isinstance(string_bytes, bytes):
                return string_bytes.decode('utf-8', errors='ignore')
            return str(string_bytes)
        except Exception as e:
            log.debug(f"getenv: Error reading string: {e}")
            return None

    @classmethod
    def _get_value_ptr(cls, name: str, value: str) -> "claripy.ast.BV":
        """Get or allocate a pointer for an env value."""
        if name not in cls._env_values:
            # Allocate space for the value
            ptr = cls._alloc_base
            cls._alloc_base += len(value) + 1 + 0x100  # Value + null + padding
            cls._env_values[name] = ptr

        # Note: We should actually write the value to memory here
        # For now, just return the pointer
        return claripy.BVV(cls._env_values[name], 64)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.env_tracker = None
        cls.technique = None
        cls._env_values.clear()
        cls._alloc_base = ENV_ALLOC_BASE
