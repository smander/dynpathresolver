"""
SimProcedures for process_vm_readv() and process_vm_writev() syscalls.

These procedures intercept cross-process memory operations to detect
code injection to other processes.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

if TYPE_CHECKING:
    from ...security_tracker import SecurityPolicyTracker

log = logging.getLogger(__name__)


class DynProcessVmReadv(angr.SimProcedure):
    """
    SimProcedure for process_vm_readv() that tracks cross-process reads.

    Signature: ssize_t process_vm_readv(pid_t pid,
                                         const struct iovec *local_iov,
                                         unsigned long liovcnt,
                                         const struct iovec *remote_iov,
                                         unsigned long riovcnt,
                                         unsigned long flags)

    This procedure tracks reading memory from other processes.
    """

    # Class-level configuration (set by DynPathResolver)
    security_tracker: "SecurityPolicyTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_security_tracker(self):
        """Get security_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_security_tracker', self.__class__.security_tracker)
        return self.__class__.security_tracker

    def run(self, pid, local_iov, liovcnt, remote_iov, riovcnt, flags):
        """
        Simulate process_vm_readv().

        Args:
            pid: Target process ID
            local_iov: Local iovec array
            liovcnt: Number of local iovecs
            remote_iov: Remote iovec array
            riovcnt: Number of remote iovecs
            flags: Operation flags (currently unused)

        Returns:
            Number of bytes read, or -1 on error
        """
        # Concretize arguments
        pid_val = self._concretize(pid, 0)
        liovcnt_val = self._concretize(liovcnt, 0)
        riovcnt_val = self._concretize(riovcnt, 0)
        flags_val = self._concretize(flags, 0)

        log.info(f"process_vm_readv: pid={pid_val}, "
                f"liovcnt={liovcnt_val}, riovcnt={riovcnt_val}")

        # Extract remote addresses if possible
        remote_addrs = self._extract_iovecs(remote_iov, riovcnt_val)
        if remote_addrs:
            log.debug(f"process_vm_readv: remote addresses = {remote_addrs}")

        # Notify technique
        self._notify_technique(pid_val, remote_addrs, "read")

        # Return a symbolic value for bytes read
        return claripy.BVS("process_vm_readv_result", self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _extract_iovecs(self, iov_ptr, count: int) -> list[tuple[int, int]]:
        """Extract (base, len) pairs from iovec array."""
        result = []
        if count == 0 or count > 100:
            return result

        iov_ptr_val = self._concretize(iov_ptr, 0)
        if iov_ptr_val == 0:
            return result

        try:
            ptr_size = self.state.arch.bytes
            iovec_size = ptr_size * 2  # iov_base + iov_len

            for i in range(count):
                iov_addr = iov_ptr_val + (i * iovec_size)

                if ptr_size == 8:
                    base = self.state.mem[iov_addr].uint64_t.concrete
                    length = self.state.mem[iov_addr + ptr_size].uint64_t.concrete
                else:
                    base = self.state.mem[iov_addr].uint32_t.concrete
                    length = self.state.mem[iov_addr + ptr_size].uint32_t.concrete

                result.append((base, length))
        except Exception as e:
            log.debug(f"Error extracting iovecs: {e}")

        return result

    def _notify_technique(self, pid: int, addrs: list[tuple[int, int]],
                         op: str) -> None:
        """Notify about cross-process memory access."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_process_vm_op'):
            try:
                technique._record_process_vm_op(
                    state=self.state,
                    pid=pid,
                    addresses=addrs,
                    operation=op,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.security_tracker = None
        cls.technique = None


class DynProcessVmWritev(angr.SimProcedure):
    """
    SimProcedure for process_vm_writev() that tracks cross-process writes.

    Signature: ssize_t process_vm_writev(pid_t pid,
                                          const struct iovec *local_iov,
                                          unsigned long liovcnt,
                                          const struct iovec *remote_iov,
                                          unsigned long riovcnt,
                                          unsigned long flags)

    This is a strong indicator of code injection - writing to another
    process's memory space.
    """

    # Class-level configuration (set by DynPathResolver)
    security_tracker: "SecurityPolicyTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_security_tracker(self):
        """Get security_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_security_tracker', self.__class__.security_tracker)
        return self.__class__.security_tracker

    def run(self, pid, local_iov, liovcnt, remote_iov, riovcnt, flags):
        """
        Simulate process_vm_writev().

        Args:
            pid: Target process ID
            local_iov: Local iovec array (source data)
            liovcnt: Number of local iovecs
            remote_iov: Remote iovec array (destination in target)
            riovcnt: Number of remote iovecs
            flags: Operation flags (currently unused)

        Returns:
            Number of bytes written, or -1 on error
        """
        # Concretize arguments
        pid_val = self._concretize(pid, 0)
        liovcnt_val = self._concretize(liovcnt, 0)
        riovcnt_val = self._concretize(riovcnt, 0)
        flags_val = self._concretize(flags, 0)

        log.warning(f"process_vm_writev: CROSS-PROCESS WRITE to pid={pid_val}")

        # Extract remote addresses
        remote_addrs = self._extract_iovecs(remote_iov, riovcnt_val)
        if remote_addrs:
            for base, length in remote_addrs:
                log.warning(f"process_vm_writev: writing to 0x{base:x}, "
                           f"length={length}")

        # This is a strong indicator of code injection
        self._notify_technique(pid_val, remote_addrs, "write")

        # Return a symbolic value for bytes written
        return claripy.BVS("process_vm_writev_result", self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    def _extract_iovecs(self, iov_ptr, count: int) -> list[tuple[int, int]]:
        """Extract (base, len) pairs from iovec array."""
        result = []
        if count == 0 or count > 100:
            return result

        iov_ptr_val = self._concretize(iov_ptr, 0)
        if iov_ptr_val == 0:
            return result

        try:
            ptr_size = self.state.arch.bytes
            iovec_size = ptr_size * 2

            for i in range(count):
                iov_addr = iov_ptr_val + (i * iovec_size)

                if ptr_size == 8:
                    base = self.state.mem[iov_addr].uint64_t.concrete
                    length = self.state.mem[iov_addr + ptr_size].uint64_t.concrete
                else:
                    base = self.state.mem[iov_addr].uint32_t.concrete
                    length = self.state.mem[iov_addr + ptr_size].uint32_t.concrete

                result.append((base, length))
        except Exception as e:
            log.debug(f"Error extracting iovecs: {e}")

        return result

    def _notify_technique(self, pid: int, addrs: list[tuple[int, int]],
                         op: str) -> None:
        """Notify about cross-process code injection."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_process_vm_op'):
            try:
                technique._record_process_vm_op(
                    state=self.state,
                    pid=pid,
                    addresses=addrs,
                    operation=op,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

        # Also record as code injection event
        if hasattr(technique, '_record_code_injection'):
            try:
                technique._record_code_injection(
                    state=self.state,
                    method='process_vm_writev',
                    target_pid=pid,
                    addresses=addrs,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.security_tracker = None
        cls.technique = None
