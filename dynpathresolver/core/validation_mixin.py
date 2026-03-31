"""Validation mixin for DynPathResolver — path candidate recording and validation."""

import logging
from typing import TYPE_CHECKING

from dynpathresolver.validation.validator import PathCandidate, ValidationResult

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class ValidationMixin:
    """Mixin providing path candidate recording and hybrid validation."""

    def _record_mmap_load(
        self,
        state: "angr.SimState",
        addr: int,
        size: int,
        filepath: str,
    ) -> None:
        """Record an mmap-based library load for validation."""
        if self.validation_mode == 'none':
            return

        # Create a path candidate for mmap-based loading
        try:
            constraints = list(state.solver.constraints)
        except Exception:
            constraints = []

        candidate = PathCandidate(
            library=filepath,
            symbol=None,
            dlopen_addr=addr,  # Using mmap addr as "dlopen" addr
            path_constraints=constraints,
            input_variables=[],
        )

        self.path_candidates.append(candidate)
        log.debug(f"Recorded mmap load candidate: {filepath} at 0x{addr:x}")

    def _record_path_candidate(
        self,
        state: "angr.SimState",
        library: str,
        symbol: str | None,
        dlopen_addr: int,
    ) -> None:
        """
        Record a path candidate from the current state.

        Creates a PathCandidate from the state's constraints for later validation.

        Args:
            state: The angr state at the time of dlopen/dlsym
            library: The library being loaded
            symbol: The symbol being resolved (if dlsym), or None
            dlopen_addr: The address of the dlopen/LoadLibrary call
        """
        # Only record if validation is enabled
        if self.validation_mode == 'none':
            return

        # Extract constraints from state
        try:
            constraints = list(state.solver.constraints)
        except Exception as e:
            log.debug(f"Could not extract constraints: {e}")
            constraints = []

        # Extract input variables (symbolic variables in constraints)
        try:
            input_vars = list(state.solver.all_variables)
        except Exception as e:
            log.debug(f"Could not extract input variables: {e}")
            input_vars = []

        candidate = PathCandidate(
            library=library,
            symbol=symbol,
            dlopen_addr=dlopen_addr,
            path_constraints=constraints,
            input_variables=input_vars,
        )

        self.path_candidates.append(candidate)
        log.debug(f"Recorded path candidate: {library} at 0x{dlopen_addr:x}")

    def run_validation(self) -> None:
        """
        Run hybrid validation on all collected path candidates.

        This method validates each path candidate by generating concrete inputs
        and running dynamic execution to verify the path is reachable.

        Results are stored in self.validation_results.
        """
        if self.validation_mode != 'validate' or self.validator is None:
            log.debug("Validation skipped: validation_mode is not 'validate'")
            return

        if not self.path_candidates:
            log.debug("No path candidates to validate")
            return

        log.info(f"Running validation on {len(self.path_candidates)} path candidates")
        self.validation_results = self.validator.validate_all(self.path_candidates)
        log.info(f"Validation complete: {len(self.validation_results)} results")

    def get_validation_results(self) -> list[ValidationResult]:
        """
        Get the validation results.

        Returns:
            List of ValidationResult objects
        """
        return self.validation_results
