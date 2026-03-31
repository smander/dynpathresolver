"""Obfuscation detection components."""

from .guards import GuardType, Guard, GuardDetector, GuardPatcher
from .unpacking import UnpackingDetector, UnpackingHandler
from .decryption_detector import (
    DecryptionEvent,
    XorPattern,
    StringConstruction,
    DecryptionDetector,
)

__all__ = [
    # Guards
    "GuardType",
    "Guard",
    "GuardDetector",
    "GuardPatcher",
    # Unpacking
    "UnpackingDetector",
    "UnpackingHandler",
    # Decryption detection
    "DecryptionEvent",
    "XorPattern",
    "StringConstruction",
    "DecryptionDetector",
]
