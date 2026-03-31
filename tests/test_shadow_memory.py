"""Tests for shadow memory."""

import pytest
from unittest.mock import MagicMock


class TestByteMetadata:
    """Test ByteMetadata dataclass."""

    def test_default_values(self):
        """Test default metadata values."""
        from dynpathresolver.tracking.shadow_memory import ByteMetadata

        meta = ByteMetadata()

        assert meta.taint_label is None
        assert meta.origin_addr is None
        assert meta.written_at_step is None
        assert not meta.is_decrypted
        assert meta.decryption_key is None
        assert meta.source_type is None

    def test_with_values(self):
        """Test metadata with values."""
        from dynpathresolver.tracking.shadow_memory import ByteMetadata

        meta = ByteMetadata(
            taint_label="network",
            origin_addr=0x1000,
            written_at_step=5,
            is_decrypted=True,
            source_type="file",
        )

        assert meta.taint_label == "network"
        assert meta.origin_addr == 0x1000
        assert meta.written_at_step == 5
        assert meta.is_decrypted
        assert meta.source_type == "file"

    def test_copy(self):
        """Test metadata copy."""
        from dynpathresolver.tracking.shadow_memory import ByteMetadata

        meta = ByteMetadata(
            taint_label="network",
            origin_addr=0x1000,
            is_decrypted=True,
        )

        copy = meta.copy()

        assert copy.taint_label == meta.taint_label
        assert copy.origin_addr == meta.origin_addr
        assert copy.is_decrypted == meta.is_decrypted
        assert copy is not meta


class TestShadowMemory:
    """Test ShadowMemory class."""

    def test_initialization(self):
        """Test shadow memory initialization."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        assert shadow.page_size == 4096
        assert len(shadow._pages) == 0
        assert shadow._total_bytes_tracked == 0

    def test_custom_page_size(self):
        """Test custom page size."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory(page_size=1024)

        assert shadow.page_size == 1024

    def test_set_get_metadata(self):
        """Test setting and getting metadata."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory, ByteMetadata

        shadow = ShadowMemory()

        meta = ByteMetadata(taint_label="test")
        shadow.set_metadata(0x1000, meta)

        result = shadow.get_metadata(0x1000)
        assert result is not None
        assert result.taint_label == "test"

    def test_get_nonexistent(self):
        """Test getting metadata for untracked address."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        result = shadow.get_metadata(0x2000)
        assert result is None

    def test_get_range(self):
        """Test getting metadata for a range."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory, ByteMetadata

        shadow = ShadowMemory()

        shadow.set_metadata(0x1000, ByteMetadata(taint_label="a"))
        shadow.set_metadata(0x1001, ByteMetadata(taint_label="b"))
        # 0x1002 not set

        result = shadow.get_range(0x1000, 3)

        assert len(result) == 3
        assert result[0].taint_label == "a"
        assert result[1].taint_label == "b"
        assert result[2] is None

    def test_set_range(self):
        """Test setting metadata for a range."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory, ByteMetadata

        shadow = ShadowMemory()

        meta = ByteMetadata(taint_label="test")
        shadow.set_range(0x1000, 4, meta)

        for i in range(4):
            result = shadow.get_metadata(0x1000 + i)
            assert result is not None
            assert result.taint_label == "test"

    def test_mark_tainted(self):
        """Test marking memory as tainted."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "network", "network", step=5)

        for i in range(10):
            assert shadow.is_tainted(0x1000 + i)
            assert shadow.get_taint_label(0x1000 + i) == "network"

        # Check taint source was recorded
        sources = shadow.get_taint_sources()
        assert len(sources) == 1
        assert sources[0].label == "network"
        assert sources[0].origin_addr == 0x1000
        assert sources[0].size == 10

    def test_clear_taint(self):
        """Test clearing taint."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "network")
        shadow.clear_taint(0x1000, 5)

        # First 5 bytes should be untainted
        for i in range(5):
            assert not shadow.is_tainted(0x1000 + i)

        # Last 5 should still be tainted
        for i in range(5, 10):
            assert shadow.is_tainted(0x1000 + i)

    def test_is_range_tainted(self):
        """Test checking if range is tainted."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1005, 1, "test")

        assert shadow.is_range_tainted(0x1000, 10)
        assert not shadow.is_range_tainted(0x2000, 10)

    def test_mark_decrypted(self):
        """Test marking memory as decrypted."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_decrypted(0x1000, 16, key=b'\x42', step=10)

        for i in range(16):
            assert shadow.is_decrypted(0x1000 + i)

    def test_get_decrypted_ranges(self):
        """Test getting decrypted ranges."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_decrypted(0x1000, 10)
        shadow.mark_decrypted(0x2000, 5)

        ranges = shadow.get_decrypted_ranges()

        assert len(ranges) == 2
        assert (0x1000, 10) in ranges
        assert (0x2000, 5) in ranges

    def test_get_tainted_ranges(self):
        """Test getting tainted ranges."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "label1")
        shadow.mark_tainted(0x2000, 5, "label2")

        ranges = shadow.get_tainted_ranges()

        assert len(ranges) == 2
        labels = [r[2] for r in ranges]
        assert "label1" in labels
        assert "label2" in labels

    def test_propagate_taint(self):
        """Test taint propagation."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "source")
        shadow.propagate_taint(0x1000, 0x2000, 10)

        for i in range(10):
            assert shadow.is_tainted(0x2000 + i)
            assert shadow.get_taint_label(0x2000 + i) == "source"

    def test_get_statistics(self):
        """Test statistics."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "test")
        shadow.mark_decrypted(0x2000, 5)

        stats = shadow.get_statistics()

        assert stats['total_bytes_tracked'] == 15
        assert stats['tainted_bytes'] == 10
        assert stats['decrypted_bytes'] == 5
        assert stats['taint_sources'] == 1

    def test_reset(self):
        """Test reset."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()

        shadow.mark_tainted(0x1000, 10, "test")

        shadow.reset()

        assert len(shadow._pages) == 0
        assert shadow._total_bytes_tracked == 0
        assert not shadow.is_tainted(0x1000)

    def test_cross_page_operations(self):
        """Test operations that span page boundaries."""
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory(page_size=16)

        # Mark range that spans two pages
        shadow.mark_tainted(0x10, 20, "cross_page")

        # Should span pages 1 and 2
        assert len(shadow._pages) == 2
        for i in range(20):
            assert shadow.is_tainted(0x10 + i)


class TestTaintSource:
    """Test TaintSource dataclass."""

    def test_creation(self):
        """Test creating TaintSource."""
        from dynpathresolver.tracking.shadow_memory import TaintSource

        source = TaintSource(
            label="network",
            origin_addr=0x1000,
            size=100,
            step=5,
            source_type="network",
        )

        assert source.label == "network"
        assert source.origin_addr == 0x1000
        assert source.size == 100
        assert source.step == 5
        assert source.source_type == "network"
