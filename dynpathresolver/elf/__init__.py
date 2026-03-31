"""ELF and binary handling components."""

from .relocation import (
    X86_64_Reloc,
    X86_Reloc,
    GOTEntry,
    PLTEntry,
    RelocationEntry,
    GOTTracker,
    RelocationProcessor,
    LazyBindingSimulator,
)
from .vtable import VtableResolver
from .preloader import LibraryPreloader
from .patcher import CFGPatcher
from .platform import PlatformDetector

__all__ = [
    # Relocation
    "X86_64_Reloc",
    "X86_Reloc",
    "GOTEntry",
    "PLTEntry",
    "RelocationEntry",
    "GOTTracker",
    "RelocationProcessor",
    "LazyBindingSimulator",
    # Other
    "VtableResolver",
    "LibraryPreloader",
    "CFGPatcher",
    "PlatformDetector",
]
