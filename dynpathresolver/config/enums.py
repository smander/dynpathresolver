"""Consolidated enum types for DynPathResolver.

Defines enums for loading methods, validation modes, platforms,
guard types, suspicious indicators, CFG edge types, and relocations.
"""

from enum import Enum, IntEnum, auto


class LoadingMethod(Enum):
    """Method used to load a library."""
    DLOPEN = 'dlopen'
    DLMOPEN = 'dlmopen'
    LOADLIBRARY = 'loadlibrary'
    MANUAL_ELF = 'manual_elf'
    MEMFD_CREATE = 'memfd_create'
    MMAP_EXEC = 'mmap_exec'
    LD_PRELOAD = 'ld_preload'
    INIT_ARRAY = 'init_array'
    IFUNC = 'ifunc'
    UNKNOWN = 'unknown'


class ValidationMode(Enum):
    """Validation mode for the analysis technique."""
    NONE = 'none'
    DETECT = 'detect'
    VALIDATE = 'validate'


class Platform(Enum):
    """Target platform for analysis."""
    AUTO = 'auto'
    LINUX = 'linux'
    WINDOWS = 'windows'


class ValidationStatus(Enum):
    """Status of path validation."""

    VERIFIED = 'verified'
    UNVERIFIED = 'unverified'
    UNREACHABLE = 'unreachable'
    GUARDED = 'guarded'
    FILE_EXISTS = 'file_exists'


class GuardType(Enum):
    """Types of anti-analysis guards."""

    ANTI_DEBUG = 'anti_debug'
    VM_DETECTION = 'vm_detection'
    TIMING_CHECK = 'timing_check'
    ENVIRONMENT_CHECK = 'environment_check'


class SuspiciousIndicator(Enum):
    """Categories of suspicious library loading behavior."""
    TEMP_DIRECTORY = auto()
    HIDDEN_DIRECTORY = auto()
    MEMORY_BACKED = auto()
    PATH_TRAVERSAL = auto()
    RANDOM_NAME = auto()
    WORLD_WRITABLE = auto()
    USER_WRITABLE = auto()
    NETWORK_DERIVED = auto()
    DECRYPTED_PATH = auto()
    ENVIRONMENT_DEPENDENT = auto()
    COMPUTED_AT_RUNTIME = auto()
    CONDITIONAL_LOAD = auto()


class StageSource(Enum):
    """Source of a payload stage."""

    NETWORK = auto()
    FILE = auto()
    DECRYPTED = auto()
    UNPACKED = auto()
    EMBEDDED = auto()
    GENERATED = auto()


class EdgeType(Enum):
    """Type of CFG edge."""
    DIRECT_JUMP = auto()
    DIRECT_CALL = auto()
    CONDITIONAL_TRUE = auto()
    CONDITIONAL_FALSE = auto()
    INDIRECT_JUMP = auto()
    INDIRECT_CALL = auto()
    RETURN = auto()
    FALLTHROUGH = auto()
    SYSCALL = auto()
    DYNAMIC_LOAD = auto()
    VTABLE_CALL = auto()
    PLT_STUB = auto()
    EXCEPTION = auto()


class X86_64_Reloc(IntEnum):
    """x86_64 relocation types."""
    R_X86_64_NONE = 0
    R_X86_64_64 = 1
    R_X86_64_PC32 = 2
    R_X86_64_GOT32 = 3
    R_X86_64_PLT32 = 4
    R_X86_64_COPY = 5
    R_X86_64_GLOB_DAT = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE = 8
    R_X86_64_GOTPCREL = 9
    R_X86_64_32 = 10
    R_X86_64_32S = 11
    R_X86_64_16 = 12
    R_X86_64_PC16 = 13
    R_X86_64_8 = 14
    R_X86_64_PC8 = 15
    R_X86_64_DTPMOD64 = 16
    R_X86_64_DTPOFF64 = 17
    R_X86_64_TPOFF64 = 18
    R_X86_64_TLSGD = 19
    R_X86_64_TLSLD = 20
    R_X86_64_IRELATIVE = 37


class X86_Reloc(IntEnum):
    """x86 (32-bit) relocation types."""
    R_386_NONE = 0
    R_386_32 = 1
    R_386_PC32 = 2
    R_386_GOT32 = 3
    R_386_PLT32 = 4
    R_386_COPY = 5
    R_386_GLOB_DAT = 6
    R_386_JMP_SLOT = 7
    R_386_RELATIVE = 8
    R_386_TLS_TPOFF = 14
    R_386_TLS_DTPMOD32 = 35
    R_386_TLS_DTPOFF32 = 36
    R_386_IRELATIVE = 42
