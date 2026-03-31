"""
SimProcedure for dlclose() - minimal implementation.

dlclose typically just decrements a reference count. For our purposes,
we'll just return success and optionally track the close.
"""

import logging

import angr
import claripy

log = logging.getLogger(__name__)


class DynDlclose(angr.SimProcedure):
    """
    SimProcedure for dlclose.

    This is a minimal implementation that just returns success (0).
    In a more complete implementation, we could track reference counts
    and potentially unmap libraries.
    """

    def run(self, handle):
        """
        Simulate dlclose(handle).

        Args:
            handle: Library handle from dlopen

        Returns:
            0 on success
        """
        # Concretize handle for logging
        if not self.state.solver.symbolic(handle):
            handle_val = self.state.solver.eval(handle)
            log.debug(f"dlclose: Closing handle 0x{handle_val:x}")
        else:
            log.debug("dlclose: Closing symbolic handle")

        # Always succeed - we don't actually unload libraries during analysis
        return claripy.BVV(0, self.state.arch.bits)
