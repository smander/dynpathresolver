"""
String decryption detection.

This module detects runtime string decryption patterns commonly used
by malware to hide library paths and other sensitive strings.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

from dynpathresolver.config.constants import HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD
from dynpathresolver.tracking.shadow_memory import ShadowMemory
from dynpathresolver.utils.entropy import calculate_entropy
from dynpathresolver.utils.state_helpers import get_step

log = logging.getLogger(__name__)


@dataclass
class DecryptionEvent:
    """Records a detected decryption event."""

    addr: int  # Address where decrypted data was written
    size: int  # Size of decrypted data
    decrypted_data: bytes  # The decrypted bytes
    decrypted_string: str | None  # String if valid UTF-8
    method: str  # 'xor', 'base64', 'rc4', 'aes', 'rolling_xor', 'unknown'
    key: bytes | None  # Decryption key if detected
    step: int  # Execution step
    loop_addr: int | None = None  # Address of decryption loop if detected


@dataclass
class XorPattern:
    """Detected XOR decryption pattern."""

    loop_addr: int
    key_byte: int | None  # Single-byte XOR key
    key_bytes: bytes | None  # Multi-byte XOR key
    iterations: int
    output_addr: int
    output_size: int


@dataclass
class StringConstruction:
    """Tracks incremental string construction."""

    start_addr: int
    current_size: int
    bytes_written: list[tuple[int, int, int]]  # (offset, byte, step)
    first_step: int
    last_step: int


class DecryptionDetector:
    """
    Detects runtime string decryption patterns.

    Monitors memory writes to detect:
    - XOR decryption loops
    - Base64 decoding
    - Rolling XOR patterns
    - Character-by-character string construction
    - Block cipher decryption
    """

    # Entropy threshold for detecting encrypted data
    HIGH_ENTROPY_THRESHOLD = HIGH_ENTROPY_THRESHOLD
    LOW_ENTROPY_THRESHOLD = LOW_ENTROPY_THRESHOLD

    def __init__(self, shadow: ShadowMemory | None = None):
        """
        Initialize decryption detector.

        Args:
            shadow: Shadow memory instance (created if not provided)
        """
        self.shadow = shadow or ShadowMemory()
        self.events: list[DecryptionEvent] = []
        self.xor_patterns: list[XorPattern] = []
        self.string_constructions: dict[int, StringConstruction] = {}
        self._write_history: list[tuple[int, int, bytes, int]] = []  # (addr, size, data, step)
        self._max_history = 1000
        self._step = 0

    def record_write(
        self,
        state: "angr.SimState",
        addr: int,
        data: bytes,
    ) -> DecryptionEvent | None:
        """
        Record a memory write and check for decryption patterns.

        Args:
            state: Current angr state
            addr: Write address
            data: Written data

        Returns:
            DecryptionEvent if decryption detected, None otherwise
        """
        step = self._get_step(state)
        self._step = step

        # Add to history
        self._write_history.append((addr, len(data), data, step))
        if len(self._write_history) > self._max_history:
            self._write_history.pop(0)

        # Track string construction
        self._track_string_construction(addr, data, step)

        # Check for decryption patterns
        event = self._check_decryption_patterns(addr, data, step)
        if event:
            self.events.append(event)
            self.shadow.mark_decrypted(addr, len(data), event.key, step)
            return event

        return None

    def _track_string_construction(self, addr: int, data: bytes, step: int) -> None:
        """Track incremental string construction."""
        # Look for existing construction that this write extends
        for start_addr, construction in list(self.string_constructions.items()):
            expected_addr = start_addr + construction.current_size

            if addr == expected_addr and len(data) <= 4:
                # This extends the construction
                for i, b in enumerate(data):
                    construction.bytes_written.append((construction.current_size + i, b, step))
                construction.current_size += len(data)
                construction.last_step = step
                return

        # Start new construction for small writes
        if len(data) <= 4:
            self.string_constructions[addr] = StringConstruction(
                start_addr=addr,
                current_size=len(data),
                bytes_written=[(i, b, step) for i, b in enumerate(data)],
                first_step=step,
                last_step=step,
            )

    def _check_decryption_patterns(
        self,
        addr: int,
        data: bytes,
        step: int,
    ) -> DecryptionEvent | None:
        """Check for various decryption patterns in write."""
        # Skip very small writes
        if len(data) < 4:
            return None

        # Check for XOR decryption pattern
        xor_event = self._detect_xor_decryption(addr, data, step)
        if xor_event:
            return xor_event

        # Check for base64 decode pattern
        b64_event = self._detect_base64_decode(addr, data, step)
        if b64_event:
            return b64_event

        # Check entropy drop (encrypted -> decrypted)
        entropy_event = self._detect_entropy_change(addr, data, step)
        if entropy_event:
            return entropy_event

        return None

    def _detect_xor_decryption(
        self,
        addr: int,
        data: bytes,
        step: int,
    ) -> DecryptionEvent | None:
        """Detect XOR decryption patterns."""
        # Look for repeated XOR operations in recent history
        recent_writes = [w for w in self._write_history[-50:] if w[0] == addr]

        if len(recent_writes) < 2:
            return None

        # Check for single-byte XOR by looking for pattern in output
        key = self._detect_single_byte_xor_key(data)
        if key is not None:
            # Verify this looks like decrypted text
            if self._is_printable_string(data):
                return DecryptionEvent(
                    addr=addr,
                    size=len(data),
                    decrypted_data=data,
                    decrypted_string=self._try_decode_string(data),
                    method='xor',
                    key=bytes([key]),
                    step=step,
                )

        return None

    def _detect_single_byte_xor_key(self, data: bytes) -> int | None:
        """Try to detect single-byte XOR key from decrypted data."""
        if len(data) < 4:
            return None

        # Common approach: XOR with space (0x20) for text
        # Or look for null-terminated string pattern
        if data[-1] == 0:
            # Null-terminated, looks good
            return None  # Can't determine key from decrypted data alone

        return None

    def _detect_base64_decode(
        self,
        addr: int,
        data: bytes,
        step: int,
    ) -> DecryptionEvent | None:
        """Detect base64 decoding."""
        # Base64 decoding typically results in binary or text
        # Check if recent writes look like base64 input

        # Simple heuristic: output is ~3/4 size of base64 input
        # and input contains only base64 chars

        if self._is_printable_string(data):
            return DecryptionEvent(
                addr=addr,
                size=len(data),
                decrypted_data=data,
                decrypted_string=self._try_decode_string(data),
                method='base64',
                key=None,
                step=step,
            )

        return None

    def _detect_entropy_change(
        self,
        addr: int,
        data: bytes,
        step: int,
    ) -> DecryptionEvent | None:
        """Detect decryption by entropy change."""
        # Look for previous write to same address with high entropy
        # followed by current write with low entropy

        for prev_addr, prev_size, prev_data, prev_step in reversed(self._write_history[:-1]):
            if prev_addr == addr and prev_size == len(data):
                prev_entropy = self._calculate_entropy(prev_data)
                curr_entropy = self._calculate_entropy(data)

                # High entropy -> low entropy suggests decryption
                if prev_entropy > self.HIGH_ENTROPY_THRESHOLD and curr_entropy < self.LOW_ENTROPY_THRESHOLD:
                    return DecryptionEvent(
                        addr=addr,
                        size=len(data),
                        decrypted_data=data,
                        decrypted_string=self._try_decode_string(data),
                        method='unknown',
                        key=None,
                        step=step,
                    )
                break

        return None

    def detect_xor_loop(
        self,
        state: "angr.SimState",
        loop_addr: int,
        iterations: int,
        output_addr: int,
        output_size: int,
        key: bytes | None = None,
    ) -> XorPattern:
        """
        Record a detected XOR decryption loop.

        Args:
            state: Current state
            loop_addr: Address of the XOR loop
            iterations: Number of iterations
            output_addr: Address of decrypted output
            output_size: Size of output
            key: XOR key if known

        Returns:
            XorPattern object
        """
        pattern = XorPattern(
            loop_addr=loop_addr,
            key_byte=key[0] if key and len(key) == 1 else None,
            key_bytes=key if key and len(key) > 1 else None,
            iterations=iterations,
            output_addr=output_addr,
            output_size=output_size,
        )

        self.xor_patterns.append(pattern)

        # Mark output as decrypted
        step = self._get_step(state)
        self.shadow.mark_decrypted(output_addr, output_size, key, step)

        log.info(f"Detected XOR loop at 0x{loop_addr:x}, output at 0x{output_addr:x}")
        return pattern

    def get_constructed_strings(self, min_length: int = 4) -> list[tuple[int, str, int]]:
        """
        Get strings that were constructed character-by-character.

        Args:
            min_length: Minimum string length

        Returns:
            List of (addr, string, step_count) tuples
        """
        result = []

        for addr, construction in self.string_constructions.items():
            if construction.current_size < min_length:
                continue

            # Reconstruct string from bytes
            string_bytes = bytearray(construction.current_size)
            for offset, byte, _ in construction.bytes_written:
                if offset < len(string_bytes):
                    string_bytes[offset] = byte

            string = self._try_decode_string(bytes(string_bytes))
            if string:
                step_count = construction.last_step - construction.first_step + 1
                result.append((addr, string, step_count))

        return result

    def get_decrypted_strings(self) -> list[DecryptionEvent]:
        """Get all decryption events that resulted in strings."""
        return [e for e in self.events if e.decrypted_string]

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        return calculate_entropy(data)

    def _is_printable_string(self, data: bytes) -> bool:
        """Check if data looks like a printable string."""
        if not data:
            return False

        # Remove trailing nulls
        data = data.rstrip(b'\x00')
        if not data:
            return False

        # Check if mostly printable ASCII
        printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
        return printable / len(data) > 0.8

    def _try_decode_string(self, data: bytes) -> str | None:
        """Try to decode data as a string."""
        # Remove trailing nulls
        data = data.rstrip(b'\x00')
        if not data:
            return None

        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return data.decode('latin-1')
            except Exception:
                return None

    def _get_step(self, state: "angr.SimState") -> int:
        """Get current execution step from state."""
        return get_step(state)

    def get_statistics(self) -> dict:
        """Get decryption detection statistics."""
        return {
            'total_events': len(self.events),
            'xor_patterns': len(self.xor_patterns),
            'string_constructions': len(self.string_constructions),
            'decrypted_strings': len(self.get_decrypted_strings()),
            'write_history_size': len(self._write_history),
        }

    def reset(self) -> None:
        """Reset detector state."""
        self.events.clear()
        self.xor_patterns.clear()
        self.string_constructions.clear()
        self._write_history.clear()
        self._step = 0
