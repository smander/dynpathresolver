"""
SimProcedures for socket/network syscalls.

These procedures intercept socket operations to enable tracking of
network-received data that flows into dlopen() or similar loading calls.
"""

import logging
import struct
from typing import TYPE_CHECKING

import angr
import claripy

from dynpathresolver.config.constants import (
    AF_INET, AF_INET6,
    SOCK_STREAM, SOCK_DGRAM,
    SOCKET_FD_BASE,
)

if TYPE_CHECKING:
    from ...tracking.memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


class DynSocket(angr.SimProcedure):
    """
    SimProcedure for socket() that tracks socket creation.

    Signature: int socket(int domain, int type, int protocol)

    This procedure:
    1. Allocates a file descriptor for the socket
    2. Records the socket in MemoryRegionTracker
    3. Returns the fd for use in connect/recv/etc.
    """

    # Class-level configuration (set by DynPathResolver)
    memory_tracker: "MemoryRegionTracker | None" = None
    technique: "object | None" = None

    # File descriptor allocation counter
    _fd_counter: int = SOCKET_FD_BASE

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

    def run(self, domain, sock_type, protocol):
        """
        Simulate socket(domain, type, protocol).

        Args:
            domain: Address family (AF_INET, AF_INET6, etc.)
            sock_type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
            protocol: Protocol number (IPPROTO_TCP, etc.)

        Returns:
            File descriptor on success
        """
        domain_val = self._concretize(domain, AF_INET)
        type_val = self._concretize(sock_type, SOCK_STREAM)
        proto_val = self._concretize(protocol, 0)

        fd = self._allocate_fd()

        log.info(f"socket: domain={domain_val}, type={type_val}, "
                 f"protocol={proto_val} -> fd={fd}")

        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_socket(self.state, fd, domain_val, type_val, proto_val)

        return claripy.BVV(fd, self.state.arch.bits)

    def _concretize(self, value, default: int) -> int:
        """Concretize a potentially symbolic value."""
        if self.state.solver.symbolic(value):
            if self.state.solver.satisfiable():
                return self.state.solver.eval(value)
            return default
        return self.state.solver.eval(value)

    @classmethod
    def _allocate_fd(cls) -> int:
        """Allocate a new socket file descriptor."""
        fd = cls._fd_counter
        cls._fd_counter += 1
        return fd

    @classmethod
    def reset(cls):
        """Reset class state (for testing)."""
        cls.memory_tracker = None
        cls.technique = None
        cls._fd_counter = SOCKET_FD_BASE


class DynConnect(angr.SimProcedure):
    """
    SimProcedure for connect() that tracks socket connections.

    Signature: int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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

    def run(self, sockfd, addr_ptr, addrlen):
        """
        Simulate connect(sockfd, addr, addrlen).

        Returns:
            0 on success
        """
        fd_val = self._concretize(sockfd, 0)
        addr_val = self._concretize(addr_ptr, 0)

        # Try to extract IP:port from sockaddr struct
        remote_addr = self._extract_sockaddr(addr_val)

        log.info(f"connect: fd={fd_val}, remote={remote_addr}")

        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_connect(self.state, fd_val, remote_addr)

        return claripy.BVV(0, self.state.arch.bits)

    def _extract_sockaddr(self, addr_ptr: int) -> str | None:
        """Extract IP:port from a sockaddr_in struct in memory."""
        try:
            # sockaddr_in: sa_family (2 bytes), sin_port (2 bytes), sin_addr (4 bytes)
            data = self.state.memory.load(addr_ptr, 8)
            if self.state.solver.symbolic(data):
                return None
            raw = self.state.solver.eval(data, cast_to=bytes)
            family = struct.unpack('<H', raw[0:2])[0]
            if family == AF_INET:
                port = struct.unpack('!H', raw[2:4])[0]
                ip = '.'.join(str(b) for b in raw[4:8])
                return f"{ip}:{port}"
        except Exception:
            pass
        return None

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


class DynBind(angr.SimProcedure):
    """
    SimProcedure for bind() that tracks socket binding.

    Signature: int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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

    def run(self, sockfd, addr_ptr, addrlen):
        """
        Simulate bind(sockfd, addr, addrlen).

        Returns:
            0 on success
        """
        fd_val = self._concretize(sockfd, 0)

        log.info(f"bind: fd={fd_val}")

        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_bind(self.state, fd_val)

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


class DynListen(angr.SimProcedure):
    """
    SimProcedure for listen() that tracks socket state.

    Signature: int listen(int sockfd, int backlog)
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

    def run(self, sockfd, backlog):
        """
        Simulate listen(sockfd, backlog).

        Returns:
            0 on success
        """
        fd_val = self._concretize(sockfd, 0)

        log.info(f"listen: fd={fd_val}")

        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_listen(self.state, fd_val)

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


class DynAccept(angr.SimProcedure):
    """
    SimProcedure for accept()/accept4() that tracks new connections.

    Signature: int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
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

    def run(self, sockfd, addr_ptr, addrlen_ptr):
        """
        Simulate accept(sockfd, addr, addrlen).

        Returns:
            New file descriptor for the accepted connection
        """
        fd_val = self._concretize(sockfd, 0)

        new_fd = DynSocket._allocate_fd()

        log.info(f"accept: listen_fd={fd_val} -> new_fd={new_fd}")

        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_accept(self.state, fd_val, new_fd)

        return claripy.BVV(new_fd, self.state.arch.bits)

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


class DynRecv(angr.SimProcedure):
    """
    SimProcedure for recv() — the key procedure for network-loaded libraries.

    Signature: ssize_t recv(int sockfd, void *buf, size_t len, int flags)

    This procedure:
    1. Looks up network_payloads in state.globals for concrete data
    2. Writes payload (or zeros) to the buffer
    3. Taints the buffer as network-sourced data
    4. Records the recv in the memory tracker
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

    def run(self, sockfd, buf, length, flags):
        """
        Simulate recv(sockfd, buf, len, flags).

        Args:
            sockfd: Socket file descriptor
            buf: Buffer to write received data into
            length: Maximum number of bytes to receive
            flags: Receive flags (MSG_PEEK, etc.)

        Returns:
            Number of bytes received
        """
        fd_val = self._concretize(sockfd, 0)
        buf_val = self._concretize(buf, 0)
        len_val = self._concretize(length, 0)

        # Look up payload for this fd
        payloads = self.state.globals.get('dpr_network_payloads') or {}
        payload = payloads.get(fd_val, None)

        if payload is not None:
            # Write concrete payload data to buffer
            data = payload[:len_val]
            bytes_written = len(data)
            self.state.memory.store(buf_val, claripy.BVV(data))
            log.info(f"recv: fd={fd_val}, wrote {bytes_written} bytes of payload "
                     f"to 0x{buf_val:x}")
        else:
            # No payload provided — write zeros to prevent symbolic explosion
            bytes_written = len_val
            if bytes_written > 0:
                self.state.memory.store(buf_val, claripy.BVV(b'\x00' * bytes_written))
            log.info(f"recv: fd={fd_val}, wrote {bytes_written} zero bytes "
                     f"to 0x{buf_val:x}")

        # Taint tracking
        technique = self._get_technique()
        if technique and hasattr(technique, 'taint_tracker') and technique.taint_tracker:
            try:
                technique.taint_tracker.taint_network_data(
                    self.state, buf_val, bytes_written, fd_val
                )
            except Exception as e:
                log.debug(f"recv: taint tracking failed: {e}")

        # Stage tracking
        if technique and hasattr(technique, 'stage_tracker') and technique.stage_tracker:
            try:
                technique.stage_tracker.record_network_stage(
                    self.state, fd_val, buf_val, bytes_written
                )
            except Exception as e:
                log.debug(f"recv: stage tracking failed: {e}")

        # Memory tracker
        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_recv(self.state, fd_val, buf_val, bytes_written)

        return claripy.BVV(bytes_written, self.state.arch.bits)

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


class DynRecvfrom(angr.SimProcedure):
    """
    SimProcedure for recvfrom() — recv with source address.

    Signature: ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                                 struct sockaddr *src_addr, socklen_t *addrlen)
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

    def run(self, sockfd, buf, length, flags, src_addr, addrlen):
        """
        Simulate recvfrom(sockfd, buf, len, flags, src_addr, addrlen).

        Returns:
            Number of bytes received
        """
        fd_val = self._concretize(sockfd, 0)
        buf_val = self._concretize(buf, 0)
        len_val = self._concretize(length, 0)
        src_addr_val = self._concretize(src_addr, 0)

        # Look up payload for this fd
        payloads = self.state.globals.get('dpr_network_payloads') or {}
        payload = payloads.get(fd_val, None)

        if payload is not None:
            data = payload[:len_val]
            bytes_written = len(data)
            self.state.memory.store(buf_val, claripy.BVV(data))
            log.info(f"recvfrom: fd={fd_val}, wrote {bytes_written} bytes of payload")
        else:
            bytes_written = len_val
            if bytes_written > 0:
                self.state.memory.store(buf_val, claripy.BVV(b'\x00' * bytes_written))
            log.info(f"recvfrom: fd={fd_val}, wrote {bytes_written} zero bytes")

        # Fill src_addr with dummy 127.0.0.1:4444
        if src_addr_val != 0:
            try:
                # sockaddr_in: AF_INET(2) + port(4444) + ip(127.0.0.1) + zero(8)
                dummy_addr = struct.pack(
                    '<HH4s8s',
                    AF_INET,
                    struct.unpack('<H', struct.pack('!H', 4444))[0],
                    bytes([127, 0, 0, 1]),
                    b'\x00' * 8,
                )
                self.state.memory.store(src_addr_val, claripy.BVV(dummy_addr))
            except Exception as e:
                log.debug(f"recvfrom: failed to fill src_addr: {e}")

        # Taint tracking
        technique = self._get_technique()
        if technique and hasattr(technique, 'taint_tracker') and technique.taint_tracker:
            try:
                technique.taint_tracker.taint_network_data(
                    self.state, buf_val, bytes_written, fd_val
                )
            except Exception as e:
                log.debug(f"recvfrom: taint tracking failed: {e}")

        # Stage tracking
        if technique and hasattr(technique, 'stage_tracker') and technique.stage_tracker:
            try:
                technique.stage_tracker.record_network_stage(
                    self.state, fd_val, buf_val, bytes_written
                )
            except Exception as e:
                log.debug(f"recvfrom: stage tracking failed: {e}")

        # Memory tracker
        tracker = self._get_memory_tracker()
        if tracker:
            tracker.record_recv(
                self.state, fd_val, buf_val, bytes_written,
                source_addr="127.0.0.1:4444",
            )

        return claripy.BVV(bytes_written, self.state.arch.bits)

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


class DynSend(angr.SimProcedure):
    """
    SimProcedure for send() — no-op that returns len.

    Signature: ssize_t send(int sockfd, const void *buf, size_t len, int flags)
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

    def run(self, sockfd, buf, length, flags):
        """
        Simulate send(sockfd, buf, len, flags).

        Returns:
            Number of bytes "sent" (always len)
        """
        fd_val = self._concretize(sockfd, 0)
        len_val = self._concretize(length, 0)

        log.info(f"send: fd={fd_val}, len={len_val}")

        return claripy.BVV(len_val, self.state.arch.bits)

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


class DynSendto(angr.SimProcedure):
    """
    SimProcedure for sendto() — no-op that returns len.

    Signature: ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                               const struct sockaddr *dest_addr, socklen_t addrlen)
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

    def run(self, sockfd, buf, length, flags, dest_addr, addrlen):
        """
        Simulate sendto(sockfd, buf, len, flags, dest_addr, addrlen).

        Returns:
            Number of bytes "sent" (always len)
        """
        fd_val = self._concretize(sockfd, 0)
        len_val = self._concretize(length, 0)

        log.info(f"sendto: fd={fd_val}, len={len_val}")

        return claripy.BVV(len_val, self.state.arch.bits)

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
