"""
Shadow memory for per-byte metadata tracking.

This module provides a sparse shadow memory implementation that stores
metadata for each byte of memory, enabling taint tracking, origin tracking,
and decryption detection.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


@dataclass
class ByteMetadata:
    """Metadata associated with a single byte of memory."""

    taint_label: str | None = None
    origin_addr: int | None = None
    written_at_step: int | None = None
    is_decrypted: bool = False
    decryption_key: bytes | None = None
    source_type: str | None = None  # 'network', 'file', 'user_input', 'env'

    def copy(self) -> "ByteMetadata":
        """Create a copy of this metadata."""
        return ByteMetadata(
            taint_label=self.taint_label,
            origin_addr=self.origin_addr,
            written_at_step=self.written_at_step,
            is_decrypted=self.is_decrypted,
            decryption_key=self.decryption_key,
            source_type=self.source_type,
        )


@dataclass
class TaintSource:
    """Represents a source of tainted data."""

    label: str
    origin_addr: int
    size: int
    step: int
    source_type: str  # 'network', 'file', 'user_input', 'env'


class ShadowMemory:
    """
    Sparse shadow memory for per-byte metadata storage.

    Uses a page-based approach for memory efficiency - only allocates
    metadata for pages that have been accessed.
    """

    DEFAULT_PAGE_SIZE = 4096

    def __init__(self, page_size: int = DEFAULT_PAGE_SIZE):
        """
        Initialize shadow memory.

        Args:
            page_size: Size of each shadow page (default 4096 bytes)
        """
        self.page_size = page_size
        self._pages: dict[int, dict[int, ByteMetadata]] = {}
        self._taint_sources: list[TaintSource] = []
        self._total_bytes_tracked = 0

    def _get_page_and_offset(self, addr: int) -> tuple[int, int]:
        """Get page number and offset within page for an address."""
        page = addr // self.page_size
        offset = addr % self.page_size
        return page, offset

    def _ensure_page(self, page: int) -> dict[int, ByteMetadata]:
        """Ensure a page exists and return it."""
        if page not in self._pages:
            self._pages[page] = {}
        return self._pages[page]

    def set_metadata(self, addr: int, meta: ByteMetadata) -> None:
        """
        Set metadata for a single byte.

        Args:
            addr: Memory address
            meta: Metadata to associate with the byte
        """
        page, offset = self._get_page_and_offset(addr)
        page_data = self._ensure_page(page)

        if offset not in page_data:
            self._total_bytes_tracked += 1

        page_data[offset] = meta

    def get_metadata(self, addr: int) -> ByteMetadata | None:
        """
        Get metadata for a single byte.

        Args:
            addr: Memory address

        Returns:
            ByteMetadata if set, None otherwise
        """
        page, offset = self._get_page_and_offset(addr)

        if page not in self._pages:
            return None

        return self._pages[page].get(offset)

    def get_range(self, start: int, size: int) -> list[ByteMetadata | None]:
        """
        Get metadata for a range of bytes.

        Args:
            start: Start address
            size: Number of bytes

        Returns:
            List of ByteMetadata (None for bytes without metadata)
        """
        result = []
        for i in range(size):
            result.append(self.get_metadata(start + i))
        return result

    def set_range(self, start: int, size: int, meta: ByteMetadata) -> None:
        """
        Set the same metadata for a range of bytes.

        Args:
            start: Start address
            size: Number of bytes
            meta: Metadata to set for all bytes
        """
        for i in range(size):
            self.set_metadata(start + i, meta.copy())

    def mark_tainted(
        self,
        addr: int,
        size: int,
        label: str,
        source_type: str = "unknown",
        step: int | None = None,
    ) -> None:
        """
        Mark a range of bytes as tainted.

        Args:
            addr: Start address
            size: Number of bytes
            label: Taint label (e.g., 'network', 'user_input')
            source_type: Type of taint source
            step: Execution step when tainted
        """
        for i in range(size):
            existing = self.get_metadata(addr + i)
            if existing:
                existing.taint_label = label
                existing.source_type = source_type
                if step is not None:
                    existing.written_at_step = step
            else:
                meta = ByteMetadata(
                    taint_label=label,
                    origin_addr=addr,
                    source_type=source_type,
                    written_at_step=step,
                )
                self.set_metadata(addr + i, meta)

        # Record taint source
        self._taint_sources.append(TaintSource(
            label=label,
            origin_addr=addr,
            size=size,
            step=step or 0,
            source_type=source_type,
        ))

        log.debug(f"Marked {size} bytes as tainted at 0x{addr:x} with label '{label}'")

    def clear_taint(self, addr: int, size: int) -> None:
        """
        Clear taint from a range of bytes.

        Args:
            addr: Start address
            size: Number of bytes
        """
        for i in range(size):
            meta = self.get_metadata(addr + i)
            if meta:
                meta.taint_label = None
                meta.source_type = None

    def is_tainted(self, addr: int) -> bool:
        """
        Check if a single byte is tainted.

        Args:
            addr: Memory address

        Returns:
            True if tainted, False otherwise
        """
        meta = self.get_metadata(addr)
        return meta is not None and meta.taint_label is not None

    def is_range_tainted(self, addr: int, size: int) -> bool:
        """
        Check if any byte in a range is tainted.

        Args:
            addr: Start address
            size: Number of bytes

        Returns:
            True if any byte is tainted
        """
        for i in range(size):
            if self.is_tainted(addr + i):
                return True
        return False

    def get_taint_label(self, addr: int) -> str | None:
        """
        Get the taint label for a byte.

        Args:
            addr: Memory address

        Returns:
            Taint label or None
        """
        meta = self.get_metadata(addr)
        return meta.taint_label if meta else None

    def mark_decrypted(
        self,
        addr: int,
        size: int,
        key: bytes | None = None,
        step: int | None = None,
    ) -> None:
        """
        Mark a range of bytes as decrypted.

        Args:
            addr: Start address
            size: Number of bytes
            key: Decryption key if known
            step: Execution step when decrypted
        """
        for i in range(size):
            existing = self.get_metadata(addr + i)
            if existing:
                existing.is_decrypted = True
                existing.decryption_key = key
                if step is not None:
                    existing.written_at_step = step
            else:
                meta = ByteMetadata(
                    is_decrypted=True,
                    decryption_key=key,
                    origin_addr=addr,
                    written_at_step=step,
                )
                self.set_metadata(addr + i, meta)

        log.debug(f"Marked {size} bytes as decrypted at 0x{addr:x}")

    def is_decrypted(self, addr: int) -> bool:
        """
        Check if a byte was decrypted at runtime.

        Args:
            addr: Memory address

        Returns:
            True if marked as decrypted
        """
        meta = self.get_metadata(addr)
        return meta is not None and meta.is_decrypted

    def get_decrypted_ranges(self) -> list[tuple[int, int]]:
        """
        Get all decrypted memory ranges.

        Returns:
            List of (start_addr, size) tuples
        """
        decrypted_addrs = []

        for page_num, page_data in self._pages.items():
            for offset, meta in page_data.items():
                if meta.is_decrypted:
                    addr = page_num * self.page_size + offset
                    decrypted_addrs.append(addr)

        if not decrypted_addrs:
            return []

        # Coalesce into ranges
        decrypted_addrs.sort()
        ranges = []
        start = decrypted_addrs[0]
        end = start

        for addr in decrypted_addrs[1:]:
            if addr == end + 1:
                end = addr
            else:
                ranges.append((start, end - start + 1))
                start = addr
                end = addr

        ranges.append((start, end - start + 1))
        return ranges

    def get_tainted_ranges(self) -> list[tuple[int, int, str]]:
        """
        Get all tainted memory ranges.

        Returns:
            List of (start_addr, size, label) tuples
        """
        tainted = []

        for page_num, page_data in self._pages.items():
            for offset, meta in page_data.items():
                if meta.taint_label:
                    addr = page_num * self.page_size + offset
                    tainted.append((addr, meta.taint_label))

        if not tainted:
            return []

        # Sort by address
        tainted.sort(key=lambda x: x[0])

        # Coalesce into ranges with same label
        ranges = []
        start = tainted[0][0]
        end = start
        label = tainted[0][1]

        for addr, lbl in tainted[1:]:
            if addr == end + 1 and lbl == label:
                end = addr
            else:
                ranges.append((start, end - start + 1, label))
                start = addr
                end = addr
                label = lbl

        ranges.append((start, end - start + 1, label))
        return ranges

    def propagate_taint(self, src_addr: int, dst_addr: int, size: int) -> None:
        """
        Propagate taint from source to destination.

        Args:
            src_addr: Source address
            dst_addr: Destination address
            size: Number of bytes to propagate
        """
        for i in range(size):
            src_meta = self.get_metadata(src_addr + i)
            if src_meta and src_meta.taint_label:
                dst_meta = self.get_metadata(dst_addr + i)
                if dst_meta:
                    dst_meta.taint_label = src_meta.taint_label
                    dst_meta.source_type = src_meta.source_type
                    dst_meta.origin_addr = src_meta.origin_addr
                else:
                    self.set_metadata(dst_addr + i, src_meta.copy())

    def get_taint_sources(self) -> list[TaintSource]:
        """Get all recorded taint sources."""
        return self._taint_sources.copy()

    def get_statistics(self) -> dict[str, int]:
        """
        Get shadow memory statistics.

        Returns:
            Dictionary with statistics
        """
        tainted_count = 0
        decrypted_count = 0

        for page_data in self._pages.values():
            for meta in page_data.values():
                if meta.taint_label:
                    tainted_count += 1
                if meta.is_decrypted:
                    decrypted_count += 1

        return {
            'total_pages': len(self._pages),
            'total_bytes_tracked': self._total_bytes_tracked,
            'tainted_bytes': tainted_count,
            'decrypted_bytes': decrypted_count,
            'taint_sources': len(self._taint_sources),
        }

    def reset(self) -> None:
        """Reset all shadow memory state."""
        self._pages.clear()
        self._taint_sources.clear()
        self._total_bytes_tracked = 0
