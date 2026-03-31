"""
Central memory region tracking for syscall-level library loading detection.

This module provides tracking for memory mappings (mmap, mprotect, VirtualAlloc)
to detect library loading that bypasses standard dlopen/LoadLibrary APIs.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dynpathresolver.config.constants import (
    PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
    MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


@dataclass
class MappedRegion:
    """Represents a memory-mapped region tracked during symbolic execution."""

    addr: int
    size: int
    prot: int
    flags: int
    fd: int | None = None
    filepath: str | None = None
    is_executable: bool = False
    is_writable: bool = False
    created_at_step: int = 0
    source: str = "mmap"  # 'mmap', 'mprotect', 'VirtualAlloc', etc.
    state_addr: int = 0  # Address in program where mapping occurred

    def __post_init__(self):
        """Update executable/writable flags based on protection."""
        self._update_flags()

    def _update_flags(self):
        """Update is_executable and is_writable based on prot field."""
        # Reset flags first
        self.is_executable = False
        self.is_writable = False

        # Handle POSIX-style flags
        if self.prot & PROT_EXEC:
            self.is_executable = True
        if self.prot & PROT_WRITE:
            self.is_writable = True

        # Handle Windows-style flags
        if self.prot in (PAGE_EXECUTE, PAGE_EXECUTE_READ,
                         PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
            self.is_executable = True
        if self.prot in (PAGE_READWRITE, PAGE_WRITECOPY,
                         PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
            self.is_writable = True

    def update_protection(self, new_prot: int):
        """Update protection flags (e.g., from mprotect)."""
        self.prot = new_prot
        self._update_flags()

    def contains(self, addr: int) -> bool:
        """Check if an address falls within this region."""
        return self.addr <= addr < (self.addr + self.size)

    def overlaps(self, other_addr: int, other_size: int) -> bool:
        """Check if this region overlaps with another address range."""
        return not (self.addr + self.size <= other_addr or
                    other_addr + other_size <= self.addr)


@dataclass
class OpenFile:
    """Tracks an open file descriptor for correlation with mmap."""

    fd: int
    path: str
    flags: int
    state_addr: int = 0
    step: int = 0


@dataclass
class SocketInfo:
    """Tracks a socket file descriptor."""

    fd: int
    domain: int
    sock_type: int
    protocol: int
    state_addr: int = 0
    step: int = 0
    is_connected: bool = False
    is_bound: bool = False
    is_listening: bool = False
    remote_addr: str | None = None
    local_addr: str | None = None


@dataclass
class NetworkBuffer:
    """Tracks data received on a socket."""

    fd: int
    addr: int
    size: int
    step: int = 0
    source_addr: str | None = None


class MemoryRegionTracker:
    """
    Central tracker for memory mappings during symbolic execution.

    This class:
    1. Records mmap/VirtualAlloc calls with their protection flags
    2. Tracks mprotect/VirtualProtect permission changes
    3. Correlates file descriptors with open() calls
    4. Identifies dynamically mapped executable regions
    5. Detects W->X transitions (common in code injection)
    """

    def __init__(self, project: "angr.Project"):
        self.project = project

        # Core tracking structures
        self.regions: dict[int, MappedRegion] = {}  # addr -> MappedRegion
        self.open_files: dict[int, OpenFile] = {}   # fd -> OpenFile
        self.memfd_files: dict[int, str] = {}       # fd -> name (for memfd_create)
        self.socket_fds: dict[int, SocketInfo] = {}  # fd -> SocketInfo
        self.network_buffers: list[NetworkBuffer] = []

        # Detection results
        self.executable_mappings: list[MappedRegion] = []
        self.wx_transitions: list[tuple[int, int, int]] = []  # (addr, old_prot, new_prot)

        # Statistics
        self.total_mmaps: int = 0
        self.total_mprotects: int = 0
        self.total_opens: int = 0
        self.total_socket_ops: int = 0
        self.total_recvs: int = 0

    def record_open(self, state: "angr.SimState", path: str,
                    flags: int, fd: int) -> None:
        """
        Record an open() or openat() syscall.

        Args:
            state: Current symbolic state
            path: File path being opened
            flags: Open flags (O_RDONLY, O_RDWR, etc.)
            fd: Returned file descriptor
        """
        self.total_opens += 1

        open_file = OpenFile(
            fd=fd,
            path=path,
            flags=flags,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.open_files[fd] = open_file

        log.debug(f"Tracked open: fd={fd}, path={path}")

    def record_memfd_create(self, state: "angr.SimState",
                            name: str, fd: int) -> None:
        """
        Record a memfd_create() syscall.

        Args:
            state: Current symbolic state
            name: Name for the memory-backed file
            fd: Returned file descriptor
        """
        self.memfd_files[fd] = name

        # Also record as a pseudo-open for correlation
        pseudo_path = f"/proc/self/fd/{fd}"
        self.record_open(state, pseudo_path, 0, fd)

        log.info(f"Tracked memfd_create: fd={fd}, name={name}")

    def record_mmap(self, state: "angr.SimState", addr: int, size: int,
                    prot: int, flags: int, fd: int = -1,
                    offset: int = 0) -> MappedRegion:
        """
        Record an mmap() syscall.

        Args:
            state: Current symbolic state
            addr: Mapped address (may be 0 if kernel chooses)
            size: Size of mapping
            prot: Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
            flags: Mapping flags (MAP_PRIVATE, MAP_SHARED, etc.)
            fd: File descriptor for file-backed mapping (-1 for anonymous)
            offset: Offset into file

        Returns:
            The created MappedRegion
        """
        self.total_mmaps += 1

        # Resolve filepath from fd
        filepath = None
        if fd >= 0 and fd in self.open_files:
            filepath = self.open_files[fd].path
        elif fd >= 0 and fd in self.memfd_files:
            filepath = f"memfd:{self.memfd_files[fd]}"

        region = MappedRegion(
            addr=addr,
            size=size,
            prot=prot,
            flags=flags,
            fd=fd if fd >= 0 else None,
            filepath=filepath,
            created_at_step=state.history.depth if state.history else 0,
            source='mmap',
            state_addr=state.addr,
        )

        self.regions[addr] = region

        # Track executable mappings
        if region.is_executable:
            self.executable_mappings.append(region)
            log.info(f"Detected executable mmap: addr=0x{addr:x}, "
                     f"size={size}, path={filepath}")

        return region

    def record_mprotect(self, state: "angr.SimState", addr: int,
                        size: int, new_prot: int) -> bool:
        """
        Record an mprotect() syscall.

        Args:
            state: Current symbolic state
            addr: Start address of region to modify
            size: Size of region
            new_prot: New protection flags

        Returns:
            True if an existing region was updated
        """
        self.total_mprotects += 1

        # Find the region containing this address
        region = self.get_region(addr)

        if region:
            old_prot = region.prot
            was_executable = region.is_executable

            region.update_protection(new_prot)

            # Detect W->X transition (code injection indicator)
            if not was_executable and region.is_executable:
                self.wx_transitions.append((addr, old_prot, new_prot))
                log.warning(f"W->X transition detected at 0x{addr:x}: "
                           f"prot 0x{old_prot:x} -> 0x{new_prot:x}")

            # Track newly executable regions
            if region.is_executable and region not in self.executable_mappings:
                self.executable_mappings.append(region)

            return True
        else:
            # Create a new region for this mprotect
            # This happens when mprotect is called on statically mapped memory
            region = MappedRegion(
                addr=addr,
                size=size,
                prot=new_prot,
                flags=0,
                created_at_step=state.history.depth if state.history else 0,
                source='mprotect',
                state_addr=state.addr,
            )
            self.regions[addr] = region

            if region.is_executable:
                self.executable_mappings.append(region)
                log.info(f"mprotect created executable region: addr=0x{addr:x}")

            return False

    def record_munmap(self, state: "angr.SimState", addr: int,
                      size: int) -> bool:
        """
        Record a munmap() syscall.

        Args:
            state: Current symbolic state
            addr: Start address of region to unmap
            size: Size of region

        Returns:
            True if a region was removed
        """
        if addr in self.regions:
            region = self.regions.pop(addr)
            if region in self.executable_mappings:
                self.executable_mappings.remove(region)
            log.debug(f"Removed mapping at 0x{addr:x}")
            return True
        return False

    def record_mremap(self, state: "angr.SimState", old_addr: int,
                      old_size: int, new_addr: int, new_size: int,
                      flags: int = 0) -> MappedRegion | None:
        """
        Record an mremap() syscall.

        Args:
            state: Current symbolic state
            old_addr: Original address of mapping
            old_size: Original size of mapping
            new_addr: New address (may be same as old_addr)
            new_size: New size of mapping
            flags: mremap flags (MREMAP_MAYMOVE, etc.)

        Returns:
            The updated MappedRegion, or None if no region found
        """
        # Find the original region
        region = self.get_region(old_addr)

        if region:
            # Remove old entry
            if old_addr in self.regions:
                del self.regions[old_addr]

            # Update region properties
            was_executable = region.is_executable
            region.addr = new_addr
            region.size = new_size

            # Add at new address
            self.regions[new_addr] = region

            # Log code relocation
            if was_executable and old_addr != new_addr:
                log.warning(f"mremap: Executable code relocated from "
                           f"0x{old_addr:x} to 0x{new_addr:x}")

            log.debug(f"mremap: 0x{old_addr:x} -> 0x{new_addr:x}, "
                     f"size {old_size} -> {new_size}")
            return region
        else:
            # No existing region - create a new one
            region = MappedRegion(
                addr=new_addr,
                size=new_size,
                prot=0,  # Unknown protection
                flags=flags,
                created_at_step=state.history.depth if state.history else 0,
                source='mremap',
                state_addr=state.addr,
            )
            self.regions[new_addr] = region
            log.debug(f"mremap: created new region at 0x{new_addr:x}")
            return region

    def record_close(self, fd: int) -> bool:
        """
        Record a close() syscall.

        Args:
            fd: File descriptor being closed

        Returns:
            True if we were tracking this fd
        """
        if fd in self.open_files:
            del self.open_files[fd]
            return True
        if fd in self.memfd_files:
            del self.memfd_files[fd]
            return True
        return False

    # === Socket Tracking Methods ===

    def record_socket(self, state: "angr.SimState", fd: int,
                      domain: int, sock_type: int, protocol: int) -> None:
        """Record a socket() syscall."""
        self.total_socket_ops += 1
        info = SocketInfo(
            fd=fd,
            domain=domain,
            sock_type=sock_type,
            protocol=protocol,
            state_addr=state.addr,
            step=state.history.depth if state.history else 0,
        )
        self.socket_fds[fd] = info
        log.debug(f"Tracked socket: fd={fd}, domain={domain}, type={sock_type}")

    def record_connect(self, state: "angr.SimState", fd: int,
                       remote_addr: str | None = None) -> None:
        """Record a connect() syscall."""
        self.total_socket_ops += 1
        if fd in self.socket_fds:
            self.socket_fds[fd].is_connected = True
            self.socket_fds[fd].remote_addr = remote_addr

    def record_bind(self, state: "angr.SimState", fd: int,
                    local_addr: str | None = None) -> None:
        """Record a bind() syscall."""
        self.total_socket_ops += 1
        if fd in self.socket_fds:
            self.socket_fds[fd].is_bound = True
            self.socket_fds[fd].local_addr = local_addr

    def record_listen(self, state: "angr.SimState", fd: int) -> None:
        """Record a listen() syscall."""
        self.total_socket_ops += 1
        if fd in self.socket_fds:
            self.socket_fds[fd].is_listening = True

    def record_accept(self, state: "angr.SimState", listen_fd: int,
                      new_fd: int) -> None:
        """Record an accept() syscall."""
        self.total_socket_ops += 1
        if listen_fd in self.socket_fds:
            parent = self.socket_fds[listen_fd]
            info = SocketInfo(
                fd=new_fd,
                domain=parent.domain,
                sock_type=parent.sock_type,
                protocol=parent.protocol,
                state_addr=state.addr,
                step=state.history.depth if state.history else 0,
                is_connected=True,
            )
            self.socket_fds[new_fd] = info

    def record_recv(self, state: "angr.SimState", fd: int,
                    addr: int, size: int,
                    source_addr: str | None = None) -> None:
        """Record a recv()/recvfrom() syscall."""
        self.total_recvs += 1
        buf = NetworkBuffer(
            fd=fd,
            addr=addr,
            size=size,
            step=state.history.depth if state.history else 0,
            source_addr=source_addr,
        )
        self.network_buffers.append(buf)
        log.debug(f"Tracked recv: fd={fd}, addr=0x{addr:x}, size={size}")

    def is_socket_fd(self, fd: int) -> bool:
        """Check if a file descriptor is a tracked socket."""
        return fd in self.socket_fds

    def get_socket_info(self, fd: int) -> SocketInfo | None:
        """Get the SocketInfo for a file descriptor."""
        return self.socket_fds.get(fd)

    # === Query Methods ===

    def is_executable(self, addr: int) -> bool:
        """Check if an address is in an executable dynamically-mapped region."""
        for region in self.executable_mappings:
            if region.contains(addr):
                return True
        return False

    def is_dynamically_mapped(self, addr: int) -> bool:
        """Check if an address is in any dynamically-mapped region."""
        for region in self.regions.values():
            if region.contains(addr):
                return True
        return False

    def get_region(self, addr: int) -> MappedRegion | None:
        """Get the MappedRegion containing an address, if any."""
        # First check exact match
        if addr in self.regions:
            return self.regions[addr]

        # Then check if addr falls within any region
        for region in self.regions.values():
            if region.contains(addr):
                return region

        return None

    def find_region_containing(self, addr: int) -> MappedRegion | None:
        """Alias for get_region — finds the region containing an address."""
        return self.get_region(addr)

    def get_executable_regions(self) -> list[MappedRegion]:
        """Get all executable dynamically-mapped regions."""
        return self.executable_mappings.copy()

    def get_file_backed_regions(self) -> list[MappedRegion]:
        """Get all file-backed mapped regions."""
        return [r for r in self.regions.values() if r.filepath]

    def get_wx_transitions(self) -> list[tuple[int, int, int]]:
        """Get all W->X protection transitions (possible code injection)."""
        return self.wx_transitions.copy()

    def get_filepath_for_fd(self, fd: int) -> str | None:
        """Get the filepath associated with a file descriptor."""
        if fd in self.open_files:
            return self.open_files[fd].path
        if fd in self.memfd_files:
            return f"memfd:{self.memfd_files[fd]}"
        return None

    # === Analysis Methods ===

    def find_library_loads(self) -> list[MappedRegion]:
        """
        Find regions that look like manually loaded libraries.

        Returns regions that are:
        - File-backed (have a filepath)
        - Executable
        - Have .so or similar extension
        """
        library_exts = ('.so', '.dll', '.dylib')
        libraries = []

        for region in self.executable_mappings:
            if region.filepath:
                # Check extension
                if any(ext in region.filepath.lower() for ext in library_exts):
                    libraries.append(region)
                # Check for memfd-based loading
                elif region.filepath.startswith('memfd:'):
                    libraries.append(region)
                # Check for /proc/self/fd/ paths (fileless loading)
                elif '/proc/self/fd/' in region.filepath:
                    libraries.append(region)

        return libraries

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_mmaps': self.total_mmaps,
            'total_mprotects': self.total_mprotects,
            'total_opens': self.total_opens,
            'total_socket_ops': self.total_socket_ops,
            'total_recvs': self.total_recvs,
            'tracked_regions': len(self.regions),
            'executable_regions': len(self.executable_mappings),
            'wx_transitions': len(self.wx_transitions),
            'open_fds': len(self.open_files),
            'memfd_count': len(self.memfd_files),
            'socket_fds': len(self.socket_fds),
            'network_buffers': len(self.network_buffers),
        }

    def reset(self):
        """Reset all tracking state."""
        self.regions.clear()
        self.open_files.clear()
        self.memfd_files.clear()
        self.socket_fds.clear()
        self.network_buffers.clear()
        self.executable_mappings.clear()
        self.wx_transitions.clear()
        self.total_mmaps = 0
        self.total_mprotects = 0
        self.total_opens = 0
        self.total_socket_ops = 0
        self.total_recvs = 0
