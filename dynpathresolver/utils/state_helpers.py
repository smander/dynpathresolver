"""Shared angr state helper utilities."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr


def get_step(state: angr.SimState) -> int:
    """Get current execution step from an angr state."""
    try:
        return state.history.depth
    except Exception:
        return 0


def extract_from_bytes(
    data: bytes,
    strings: set[str],
    min_length: int,
    printable: set[int],
) -> None:
    """Extract printable strings from raw bytes into a set."""
    current = []
    for byte_val in data:
        if byte_val in printable:
            current.append(chr(byte_val))
        else:
            if len(current) >= min_length:
                strings.add(''.join(current))
            current = []
    if len(current) >= min_length:
        strings.add(''.join(current))
