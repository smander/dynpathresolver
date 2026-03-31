"""SimProcedure for GetProcAddress."""
import logging
import angr
import claripy
from .loadlibrary import DynLoadLibraryA

log = logging.getLogger(__name__)

class DynGetProcAddress(angr.SimProcedure):
    """SimProcedure for GetProcAddress."""
    resolved_symbols: dict[tuple[int, str], int] = {}

    @classmethod
    def reset(cls):
        cls.resolved_symbols = {}

    def _get_loaded_libraries(self):
        if self.state is not None:
            return self.state.globals.get('dpr_win_loaded_libraries', {})
        from .loadlibrary import DynLoadLibraryA
        return DynLoadLibraryA.loaded_libraries

    def run(self, hModule, lpProcName):
        """
        Simulate GetProcAddress(hModule, lpProcName).

        Args:
            hModule: Handle to the loaded module
            lpProcName: Pointer to function name string (or ordinal)

        Returns:
            Address of the exported function, or NULL (0) if not found
        """
        if self.state.solver.symbolic(hModule):
            return claripy.BVV(0, self.state.arch.bits)
        handle = self.state.solver.eval(hModule)

        proc_name = self._get_proc_name(lpProcName)
        if not proc_name:
            return claripy.BVV(0, self.state.arch.bits)

        lib = self._get_loaded_libraries().get(handle)
        if not lib:
            return claripy.BVV(0, self.state.arch.bits)

        if proc_name.startswith('#'):
            return claripy.BVV(0, self.state.arch.bits)  # Ordinal not supported

        try:
            sym = lib.get_symbol(proc_name)
            if sym:
                addr = sym.rebased_addr
                self.resolved_symbols[(handle, proc_name)] = addr
                return claripy.BVV(addr, self.state.arch.bits)
        except Exception:
            pass
        return claripy.BVV(0, self.state.arch.bits)

    def _get_proc_name(self, ptr) -> str | None:
        if self.state.solver.symbolic(ptr):
            return None
        try:
            val = self.state.solver.eval(ptr)
            if val < 0x10000:
                return f"#{val}"  # Ordinal
            s = self.state.mem[val].string.concrete
            return s.decode('ascii', errors='ignore') if isinstance(s, bytes) else str(s)
        except Exception:
            return None
