"""Centralized constants for DynPathResolver.

All magic numbers, thresholds, and configuration defaults live here.
"""

import math

# Handle generation
DEFAULT_HANDLE_BASE = 0x7F000000

# Memory
PAGE_SIZE = 0x1000
PAGE_ALIGNMENT_GAP = 0x10000

# Protection flags (from mman.h)
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

# Entropy thresholds (Shannon entropy, 0.0 - 8.0 scale)
HIGH_ENTROPY_THRESHOLD = 7.0
MEDIUM_ENTROPY_THRESHOLD = 6.0
LOW_ENTROPY_THRESHOLD = 4.0

# Analysis limits
MAX_PATH_READ_SIZE = 256
MAX_LIBRARY_SIZE = 0x100000
MAX_ENTRY_POINTS = 10
MAX_ACTIVE_STATES = 8

# Step intervals
PERIODIC_CHECK_INTERVAL = 5
DEEP_CHECK_INTERVAL = 10

# Sentinel values
UNREACHABLE_DISTANCE = math.inf

# Library search paths
LINUX_LIB_PATHS = [
    '/lib', '/lib64', '/usr/lib', '/usr/lib64', '/usr/local/lib',
]

WINDOWS_LIB_PATHS = [
    'C:\\Windows\\System32', 'C:\\Windows',
]

# Common libraries (Linux)
COMMON_LINUX_LIBS = [
    'libc.so.6', 'libpthread.so.0', 'libdl.so.2',
    'libm.so.6', 'librt.so.1', 'libcrypt.so.1',
    'libutil.so.1', 'libnsl.so.1', 'libresolv.so.2',
]

# ---------------------------------------------------------------------------
# Memory constants
# ---------------------------------------------------------------------------

# Protection flags (POSIX) - extended
PROT_NONE = 0x0

# Mapping flags (POSIX)
MAP_SHARED = 0x01
MAP_PRIVATE = 0x02
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x20
MAP_FAILED = -1

# Windows protection flags
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

# ---------------------------------------------------------------------------
# Simulated address space bases
# ---------------------------------------------------------------------------

MMAP_ALLOC_BASE = 0x7f0000000000
MREMAP_ALLOC_BASE = 0x7f1000000000
ENV_ALLOC_BASE = 0x7f2000000000
TLS_BASE = 0x7ffc0000
DLADDR_STRING_BASE = 0x7ffe0000
DLINFO_LINKMAP_BASE = 0x7ffd0000
DLERROR_BUFFER_BASE = 0x7fff0000
DEFAULT_TLS_BLOCK_SIZE = 0x100
DLERROR_BUFFER_SIZE = 256

# ---------------------------------------------------------------------------
# Ptrace constants
# ---------------------------------------------------------------------------

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SEIZE = 0x4206

# ---------------------------------------------------------------------------
# Prctl constants
# ---------------------------------------------------------------------------

PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 5
PR_SET_SECCOMP = 22
PR_GET_SECCOMP = 21
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_SET_NAME = 15
PR_GET_NAME = 16

# ---------------------------------------------------------------------------
# Signal constants
# ---------------------------------------------------------------------------

# Signal numbers (Linux)
SIGHUP = 1
SIGINT = 2
SIGQUIT = 3
SIGILL = 4
SIGTRAP = 5
SIGABRT = 6
SIGBUS = 7
SIGFPE = 8
SIGKILL = 9
SIGUSR1 = 10
SIGSEGV = 11
SIGUSR2 = 12
SIGPIPE = 13
SIGALRM = 14
SIGTERM = 15
SIGCHLD = 17
SIGCONT = 18
SIGSTOP = 19
SIGTSTP = 20

# Signal names for logging
SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 17: "SIGCHLD",
    18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
}

# Special handler values
SIG_DFL = 0
SIG_IGN = 1

# ---------------------------------------------------------------------------
# Sigaction flags
# ---------------------------------------------------------------------------

SA_NOCLDSTOP = 1
SA_NOCLDWAIT = 2
SA_SIGINFO = 4
SA_RESTART = 0x10000000
SA_NODEFER = 0x40000000
SA_RESETHAND = 0x80000000

# ---------------------------------------------------------------------------
# Seccomp modes
# ---------------------------------------------------------------------------

SECCOMP_MODE_DISABLED = 0
SECCOMP_MODE_STRICT = 1
SECCOMP_MODE_FILTER = 2

# ---------------------------------------------------------------------------
# Clone flags
# ---------------------------------------------------------------------------

CLONE_VM = 0x00000100
CLONE_FS = 0x00000200
CLONE_FILES = 0x00000400
CLONE_SIGHAND = 0x00000800
CLONE_PTRACE = 0x00002000
CLONE_VFORK = 0x00004000
CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000
CLONE_NEWNS = 0x00020000
CLONE_SYSVSEM = 0x00040000
CLONE_SETTLS = 0x00080000
CLONE_PARENT_SETTID = 0x00100000
CLONE_CHILD_CLEARTID = 0x00200000
CLONE_DETACHED = 0x00400000
CLONE_CHILD_SETTID = 0x01000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_IO = 0x80000000

# ---------------------------------------------------------------------------
# Socket constants
# ---------------------------------------------------------------------------

AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3

IPPROTO_TCP = 6
IPPROTO_UDP = 17

MSG_PEEK = 0x2
MSG_WAITALL = 0x100
MSG_DONTWAIT = 0x40

SOCKET_FD_BASE = 200

# ---------------------------------------------------------------------------
# File operation constants
# ---------------------------------------------------------------------------

# Open flags
O_RDONLY = 0x0
O_WRONLY = 0x1
O_RDWR = 0x2
O_CREAT = 0x40
O_EXCL = 0x80
O_TRUNC = 0x200
O_APPEND = 0x400

# Special fd value for openat()
AT_FDCWD = -100

# execveat flags
AT_EMPTY_PATH = 0x1000
AT_SYMLINK_NOFOLLOW = 0x100

# memfd_create flags
MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002

# mremap flags
MREMAP_MAYMOVE = 0x1
MREMAP_FIXED = 0x2
MREMAP_DONTUNMAP = 0x4

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

# ELF dynamic tags
DT_INIT = 12
DT_FINI = 13
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

# ELF symbol types
STT_GNU_IFUNC = 10

# ---------------------------------------------------------------------------
# CPU flag bitmasks
# ---------------------------------------------------------------------------

FLAG_MASKS = {
    'cf': 0x0001,
    'pf': 0x0004,
    'af': 0x0010,
    'zf': 0x0040,
    'sf': 0x0080,
    'tf': 0x0100,
    'if': 0x0200,
    'df': 0x0400,
    'of': 0x0800,
}

# ---------------------------------------------------------------------------
# RTLD constants
# ---------------------------------------------------------------------------

# dlinfo request codes
RTLD_DI_LMID = 1
RTLD_DI_LINKMAP = 2
RTLD_DI_SERINFO = 4
RTLD_DI_SERINFOSIZE = 5
RTLD_DI_ORIGIN = 6
RTLD_DI_TLS_MODID = 9
RTLD_DI_TLS_DATA = 10

# dlsym special handles
RTLD_DEFAULT = 0
RTLD_NEXT = -1

# Namespace identifiers
LM_ID_BASE = 0
LM_ID_NEWLM = -1

