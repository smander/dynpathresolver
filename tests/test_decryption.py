"""Tests for decryption detection."""

import pytest
from unittest.mock import MagicMock


class TestDecryptionDetector:
    """Test DecryptionDetector class."""

    def test_initialization(self):
        """Test detector initialization."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        assert detector.shadow is not None
        assert len(detector.events) == 0
        assert len(detector.xor_patterns) == 0
        assert len(detector.string_constructions) == 0

    def test_initialization_with_shadow(self):
        """Test initialization with existing shadow memory."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector
        from dynpathresolver.tracking.shadow_memory import ShadowMemory

        shadow = ShadowMemory()
        detector = DecryptionDetector(shadow=shadow)

        assert detector.shadow is shadow

    def test_record_write_small(self):
        """Test recording small writes (no detection)."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 1

        result = detector.record_write(state, 0x1000, b"AB")

        assert result is None
        assert len(detector.events) == 0

    def test_record_write_string_construction(self):
        """Test tracking string construction."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 1

        # Write character by character
        detector.record_write(state, 0x1000, b"H")
        state.history.depth = 2
        detector.record_write(state, 0x1001, b"e")
        state.history.depth = 3
        detector.record_write(state, 0x1002, b"l")
        state.history.depth = 4
        detector.record_write(state, 0x1003, b"l")
        state.history.depth = 5
        detector.record_write(state, 0x1004, b"o")

        # Should have tracked construction
        assert 0x1000 in detector.string_constructions
        assert detector.string_constructions[0x1000].current_size == 5

    def test_get_constructed_strings(self):
        """Test getting constructed strings."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 1

        # Write "Hello" character by character
        for i, char in enumerate(b"Hello"):
            state.history.depth = i + 1
            detector.record_write(state, 0x1000 + i, bytes([char]))

        strings = detector.get_constructed_strings(min_length=4)

        assert len(strings) == 1
        assert strings[0][0] == 0x1000
        assert strings[0][1] == "Hello"

    def test_detect_xor_loop(self):
        """Test recording XOR loop pattern."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 10

        pattern = detector.detect_xor_loop(
            state,
            loop_addr=0x401000,
            iterations=16,
            output_addr=0x500000,
            output_size=16,
            key=b'\x42',
        )

        assert pattern is not None
        assert pattern.loop_addr == 0x401000
        assert pattern.key_byte == 0x42
        assert len(detector.xor_patterns) == 1

        # Check shadow memory was updated
        assert detector.shadow.is_decrypted(0x500000)

    def test_calculate_entropy_low(self):
        """Test entropy calculation for low-entropy data."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        # Repeated pattern - low entropy
        data = b"AAAAAAAAAAAAAAAA"
        entropy = detector._calculate_entropy(data)

        assert entropy < 1.0

    def test_calculate_entropy_high(self):
        """Test entropy calculation for high-entropy data."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        # Random-looking data - high entropy
        data = bytes(range(256))
        entropy = detector._calculate_entropy(data)

        assert entropy > 7.0

    def test_is_printable_string(self):
        """Test printable string detection."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        assert detector._is_printable_string(b"Hello, World!")
        assert detector._is_printable_string(b"/lib/libc.so.6\x00")
        assert not detector._is_printable_string(b"\x00\x01\x02\x03")
        assert not detector._is_printable_string(b"")

    def test_try_decode_string(self):
        """Test string decoding."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        assert detector._try_decode_string(b"Hello\x00") == "Hello"
        assert detector._try_decode_string(b"Test") == "Test"
        assert detector._try_decode_string(b"\x00\x00") is None

    def test_get_decrypted_strings(self):
        """Test getting decryption events with strings."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector, DecryptionEvent

        detector = DecryptionDetector()

        # Add some events
        detector.events.append(DecryptionEvent(
            addr=0x1000,
            size=10,
            decrypted_data=b"Hello\x00\x00\x00\x00\x00",
            decrypted_string="Hello",
            method='xor',
            key=b'\x42',
            step=5,
        ))
        detector.events.append(DecryptionEvent(
            addr=0x2000,
            size=4,
            decrypted_data=b"\x00\x01\x02\x03",
            decrypted_string=None,
            method='unknown',
            key=None,
            step=6,
        ))

        strings = detector.get_decrypted_strings()

        assert len(strings) == 1
        assert strings[0].decrypted_string == "Hello"

    def test_get_statistics(self):
        """Test statistics."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 1

        # Record some writes
        detector.record_write(state, 0x1000, b"A")
        detector.record_write(state, 0x2000, b"BBBB")

        stats = detector.get_statistics()

        assert stats['total_events'] >= 0
        assert stats['string_constructions'] >= 0
        assert stats['write_history_size'] == 2

    def test_reset(self):
        """Test reset."""
        from dynpathresolver.detection.decryption_detector import DecryptionDetector

        detector = DecryptionDetector()

        state = MagicMock()
        state.history.depth = 1

        detector.record_write(state, 0x1000, b"Test")
        detector.xor_patterns.append(MagicMock())

        detector.reset()

        assert len(detector.events) == 0
        assert len(detector.xor_patterns) == 0
        assert len(detector.string_constructions) == 0
        assert len(detector._write_history) == 0


class TestDecryptionEvent:
    """Test DecryptionEvent dataclass."""

    def test_creation(self):
        """Test creating DecryptionEvent."""
        from dynpathresolver.detection.decryption_detector import DecryptionEvent

        event = DecryptionEvent(
            addr=0x1000,
            size=16,
            decrypted_data=b"decrypted text\x00\x00",
            decrypted_string="decrypted text",
            method='xor',
            key=b'\x42',
            step=10,
            loop_addr=0x401000,
        )

        assert event.addr == 0x1000
        assert event.size == 16
        assert event.decrypted_string == "decrypted text"
        assert event.method == 'xor'
        assert event.key == b'\x42'
        assert event.loop_addr == 0x401000


class TestXorPattern:
    """Test XorPattern dataclass."""

    def test_creation_single_byte(self):
        """Test creating XorPattern with single byte key."""
        from dynpathresolver.detection.decryption_detector import XorPattern

        pattern = XorPattern(
            loop_addr=0x401000,
            key_byte=0x42,
            key_bytes=None,
            iterations=16,
            output_addr=0x500000,
            output_size=16,
        )

        assert pattern.key_byte == 0x42
        assert pattern.key_bytes is None

    def test_creation_multi_byte(self):
        """Test creating XorPattern with multi-byte key."""
        from dynpathresolver.detection.decryption_detector import XorPattern

        pattern = XorPattern(
            loop_addr=0x401000,
            key_byte=None,
            key_bytes=b'\x41\x42\x43\x44',
            iterations=16,
            output_addr=0x500000,
            output_size=16,
        )

        assert pattern.key_byte is None
        assert pattern.key_bytes == b'\x41\x42\x43\x44'


class TestStringConstruction:
    """Test StringConstruction dataclass."""

    def test_creation(self):
        """Test creating StringConstruction."""
        from dynpathresolver.detection.decryption_detector import StringConstruction

        construction = StringConstruction(
            start_addr=0x1000,
            current_size=5,
            bytes_written=[(0, 0x48, 1), (1, 0x65, 2), (2, 0x6c, 3)],
            first_step=1,
            last_step=3,
        )

        assert construction.start_addr == 0x1000
        assert construction.current_size == 5
        assert len(construction.bytes_written) == 3
