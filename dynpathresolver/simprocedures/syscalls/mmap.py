"""
SimProcedures for mmap() and munmap() syscalls.

These procedures intercept memory mapping operations to detect library loading
that bypasses dlopen, such as manual ELF loading via mmap.
"""

import logging
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
    MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS, MAP_FAILED,
    MMAP_ALLOC_BASE, PAGE_SIZE,
)

if TYPE_CHECKING:
    from ...memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynMmap(angr.SimProcedure):
    """
    SimProcedure for mmap() that tracks memory mappings.

    Signature: void *mmap(void *addr, size_t length, int prot,
                          int flags, int fd, off_t offset)

    This procedure:
    1. Extracts mapping parameters from arguments
    2. Records the mapping in MemoryRegionTracker
    3. Correlates with open() calls via file descriptor
    4. Detects PROT_EXEC mappings (potential code loading)
    5. Returns a mapped address
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # Address allocation counter for anonymous mappings
    _alloc_base: int = MMAP_ALLOC_BASE

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_memory_tracker(self):
        """Get memory_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_memory_tracker', self.__class__.memory_tracker)
        return self.__class__.memory_tracker

    def run(self, addr, length, prot, flags, fd, offset):
        """
        Simulate mmap(addr, length, prot, flags, fd, offset).

        Args:
            addr: Requested address (hint, or fixed if MAP_FIXED)
            length: Size of mapping
            prot: Protection flags
            flags: Mapping flags
            fd: File descriptor for file-backed mapping
            offset: Offset into file

        Returns:
            Mapped address, or MAP_FAILED (-1) on error
        """
        # Concretize arguments
        addr_val = self._concretize(addr, 0)
        length_val = self._concretize(length, 4096)
        prot_val = self._concretize(prot, PROT_READ)
        flags_val = self._concretize(flags, MAP_PRIVATE | MAP_ANONYMOUS)
        fd_val = self._concretize(fd, -1)
        offset_val = self._concretize(offset, 0)

        log.debug(f"mmap: addr=0x{addr_val:x}, length={length_val}, "
                  f"prot=0x{prot_val:x}, flags=0x{flags_val:x}, "
                  f"fd={fd_val}, offset={offset_val}")

        # Allocate address if not specified or not MAP_FIXED
        if addr_val == 0 or not (flags_val & MAP_FIXED):
            addr_val = self._allocate_address(length_val)

        # Page-align the address
        addr_val = (addr_val // PAGE_SIZE) * PAGE_SIZE

        # Page-align the length (round up)
        length_val = ((length_val + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            region = memory_tracker.record_mmap(
                state=self.state,
                addr=addr_val,
                size=length_val,
                prot=prot_val,
                flags=flags_val,
                fd=fd_val,
                offset=offset_val,
            )

            # Log if executable mapping detected
            if region.is_executable:
                filepath = region.filepath or "anonymous"
                log.info(f"mmap: Executable mapping detected - "
                        f"addr=0x{addr_val:x}, path={filepath}")

                # Notify technique if available
                self._notify_technique(addr_val, length_val, filepath)

        # Record in predictor's LoadBehaviorDetector if available
        self._record_to_predictor(addr_val, length_val, prot_val, flags_val, fd_val)

        return claripy.BVV(addr_val, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_address(cls, size: int) -> int:
        """Allocate an address for anonymous mapping."""
        addr = cls._alloc_base
        # Align size to page boundary and add guard page
        aligned_size = ((size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE + PAGE_SIZE
        cls._alloc_base += aligned_size
        return addr

    def _notify_technique(self, addr: int, size: int, filepath: str) -> None:
        """Notify the technique about executable mapping."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, '_record_mmap_load'):
            try:
                technique._record_mmap_load(
                    state=self.state,
                    addr=addr,
                    size=size,
                    filepath=filepath,
                )
            except Exception as e:
                log.debug(f"Failed to notify technique: {e}")

    def _record_to_predictor(self, addr: int, length: int, prot: int,
                             flags: int, fd: int) -> None:
        """Record mmap to predictor's LoadBehaviorDetector."""
        technique = self._get_technique()
        if technique is None:
            return

        if hasattr(technique, 'heuristic_predictor'):
            predictor = technique.heuristic_predictor
            if hasattr(predictor, 'load_detector'):
                try:
                    predictor.load_detector.record_mmap(
                        self.state, addr, length, prot, flags, fd
                    )
                except Exception as e:
                    log.debug(f"Failed to record to predictor: {e}")

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._alloc_base = MMAP_ALLOC_BASE


class DynMunmap(angr.SimProcedure):
    """
    SimProcedure for munmap() that tracks unmapping.

    Signature: int munmap(void *addr, size_t length)

    This procedure:
    1. Extracts address and length from arguments
    2. Removes the mapping from MemoryRegionTracker
    3. Returns 0 on success
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    def _get_technique(self):
        """Get technique from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_technique', self.__class__.technique)
        return self.__class__.technique

    def _get_memory_tracker(self):
        """Get memory_tracker from state.globals with class-level fallback."""
        if self.state is not None:
            return self.state.globals.get('dpr_memory_tracker', self.__class__.memory_tracker)
        return self.__class__.memory_tracker

    def run(self, addr, length):
        """
        Simulate munmap(addr, length).

        Args:
            addr: Start address of mapping to remove
            length: Size of mapping to remove

        Returns:
            0 on success, -1 on error
        """
        # Concretize arguments
        addr_val = self._concretize(addr, 0)
        length_val = self._concretize(length, 0)

        log.debug(f"munmap: addr=0x{addr_val:x}, length={length_val}")

        # Record in memory tracker if available
        memory_tracker = self._get_memory_tracker()
        if memory_tracker:
            memory_tracker.record_munmap(self.state, addr_val, length_val)

        return claripy.BVV(0, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
