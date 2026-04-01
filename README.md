# DynPathResolver

**Safe, Execution-Free Binary Analysis for Dynamic Code Discovery**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-537%20passed-brightgreen.svg)]()
[![Benchmarks](https://img.shields.io/badge/benchmarks-15%2F15-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![angr](https://img.shields.io/badge/built%20with-angr-red.svg)](https://angr.io/)

## Overview

DynPathResolver is a comprehensive binary analysis framework that discovers dynamically loaded code **without executing the target binary**. Unlike dynamic instrumentation tools (Frida, DynamoRIO) that run malware natively—risking system compromise—DynPathResolver uses symbolic execution to safely analyze even the most sophisticated malware.

### Key Advantages

| Feature | DynPathResolver | Frida/Dynamic Tools |
|---------|-----------------|---------------------|
| **Executes malware code** | No (safe) | Yes (dangerous) |
| **Per-sample customization** | Not needed | Required for each case |
| **Anti-debug bypass** | Automatic | Manual scripting |
| **Path coverage** | All feasible paths | Only executed paths |
| **Fileless/manual loading** | Detected | Requires custom hooks |

## Features

### Detection Capabilities
- **39 SimProcedures** intercepting dynamic loading, memory operations, process execution, and security syscalls
- **Instruction-level tracking** of indirect control flow (call/jmp/ret) via VEX IR
- **Unified string extraction** across all intercepted functions
- **Shadow memory** with per-byte taint tracking
- **Decryption detection** via entropy analysis
- **Multi-stage payload tracking**

### Obfuscation Detection
- Control flow flattening (CFF)
- VM-based protection
- Self-modifying code (SMC)
- Polymorphic engines
- Opaque predicates

### Supported Platforms
- Linux ELF (x86_64, ARM64)
- Windows PE (x86_64)

---

## Installation

### Requirements
- Python 3.10+
- angr 9.2+
- Docker (for benchmarks and Frida validation)

### Install from Source

```bash
git clone https://github.com/yourusername/DynPathResolver.git
cd DynPathResolver
pip install -e .
```

### Install with Development Dependencies

```bash
pip install -e ".[dev]"
```

### Docker Setup (for benchmarks)

```bash
# Build and start Docker container
docker-compose up -d

# Or use the pre-built image
docker pull dynpathresolver:latest
docker run -it --privileged dynpathresolver
```

---

## Quick Start

### Two-Phase Workflow

DynPathResolver uses a two-phase approach:

1. **Phase 1: Discovery** - Analyze binary to find all dynamic code loading (dlopen, mmap, manual ELF, etc.)
2. **Phase 2: Full CFG** - Build complete CFG with edges into discovered libraries

This separation is important because you often don't know what libraries a binary loads until you analyze it.

### Phase 1: Discovery (Find Dynamic Code)

```python
import angr
from dynpathresolver import DynPathResolver

# Load binary
project = angr.Project("./target_binary", auto_load_libs=False)

# Create DynPathResolver - NO library_paths needed for discovery
dpr = DynPathResolver(
    handle_syscall_loading=True,  # Detect mmap, memfd_create, etc.
    track_indirect_flow=True,     # Track indirect calls/jumps
)

# Run symbolic analysis
state = project.factory.entry_state()
simgr = project.factory.simgr(state)
simgr.use_technique(dpr)
simgr.run(n=1000)
dpr.complete(simgr)

# Get discovered libraries and dynamic code
for event in dpr.get_library_load_events():
    print(f"Found: {event.library_path}")
    print(f"  Method: {event.loading_method}")  # DLOPEN, MANUAL_ELF, MMAP_EXEC
    print(f"  Call site: 0x{event.call_site:x}")

# Export discoveries
dpr.export_json("discoveries.json")
```

**Output example:**
```
Found: /opt/plugins/libcrypto.so
  Method: DLOPEN
  Call site: 0x401234

Found: <anonymous_mmap>
  Method: MMAP_EXEC
  Call site: 0x401456
```

### Phase 2: Build Full CFG (With Library Edges)

After discovering what libraries are loaded, build a complete CFG that includes edges into those libraries:

```python
from dynpathresolver.core import CompleteCFGBuilder

project = angr.Project("./target", auto_load_libs=False)

# Now provide paths where discovered libraries can be found
builder = CompleteCFGBuilder(
    project,
    library_paths=["./extracted_libs/", "/opt/plugins/"],
)

# Build unified CFG: main binary + all discovered libraries
cfg = builder.build_with_libraries(max_steps=500)

print(f"Total blocks: {cfg.total_basic_blocks}")
print(f"Static edges: {cfg.static_edges}")
print(f"Dynamic edges: {cfg.dynamic_edges}")  # Edges INTO loaded libraries
print(f"Libraries included: {cfg.discovered_libraries}")

# Export for visualization
cfg.export_dot("combined_cfg.dot")
cfg.export_json("combined_cfg.json")
```

### With Recursive Analysis

```python
from dynpathresolver import DynPathResolver
from dynpathresolver.core import RecursiveLibraryAnalyzer

project = angr.Project("./target", auto_load_libs=False)

dpr = DynPathResolver(library_paths=["./libs"])
analyzer = RecursiveLibraryAnalyzer(project, dpr)

# Analyze chained library loading (A loads B loads C)
chain = analyzer.analyze()

for lib in chain.discovered_libraries:
    print(f"{lib.path} (depth: {lib.depth})")
```

### Advanced Configuration

```python
dpr = DynPathResolver(
    # Library search paths
    library_paths=["/opt/plugins", "./libs"],

    # Preload common libraries (libc, pthread, etc.)
    preload_common=True,

    # Syscall-level detection (mmap, memfd_create, etc.)
    handle_syscall_loading=True,

    # Control flow tracking
    track_indirect_flow=True,
    detect_rop=True,
    detect_jop=True,

    # Signal handler tracking
    track_signals=True,

    # Environment variable tracking
    track_environment=True,

    # Obfuscation detection
    detect_opaque_predicates=True,
    detect_cff=True,  # Control flow flattening
    detect_vm_obfuscation=True,
    track_smc=True,   # Self-modifying code

    # Taint tracking
    enable_taint_tracking=True,
    enable_decryption_detection=True,

    # Validation mode: 'none', 'record', or 'validate'
    validation_mode='none',
)
```

---

## When to Use `library_paths`

The `library_paths` parameter tells DynPathResolver where to find library files for **Phase 2 (Full CFG building)**. It is NOT needed for Phase 1 (Discovery).

### Discovery vs. Full CFG

| Phase | Purpose | Needs `library_paths`? |
|-------|---------|------------------------|
| **Phase 1: Discovery** | Find what dynamic code is loaded | No |
| **Phase 2: Full CFG** | Build CFG with edges into libraries | Yes |

### Handling Dynamic/Computed Paths

Malware often uses paths that vary at runtime. DynPathResolver discovers them all:

| Path Type | Example | What DynPathResolver Reports |
|-----------|---------|------------------------------|
| Static | `/opt/plugins/libcrypto.so` | Exact path |
| Random filename | `/tmp/x8f3k2.so` | Computed/symbolic path |
| Fileless | `/dev/shm/.hidden.so` | Memory location |
| Decrypted | `<from_xor_decrypt>` | Decrypted string value |
| Environment-based | `$LD_LIBRARY_PATH/lib.so` | Resolved or symbolic |

### Complete Workflow Example

```python
import angr
from dynpathresolver import DynPathResolver
from dynpathresolver.core import CompleteCFGBuilder

# ============================================
# PHASE 1: Discovery - find all dynamic code
# ============================================
project = angr.Project("./malware_sample", auto_load_libs=False)

dpr = DynPathResolver(
    handle_syscall_loading=True,
    track_indirect_flow=True,
)

state = project.factory.entry_state()
simgr = project.factory.simgr(state)
simgr.use_technique(dpr)
simgr.run(n=500)
dpr.complete(simgr)

# See what was discovered
print("=== Discovered Dynamic Code ===")
for event in dpr.get_library_load_events():
    print(f"{event.library_path} via {event.loading_method}")

# Export discoveries
dpr.export_json("discoveries.json")

# ============================================
# PHASE 2: Full CFG - after obtaining libraries
# ============================================
# Now that we know what libraries are needed, we can:
# 1. Extract them from the malware sample bundle
# 2. Download them from a repository
# 3. Use them from the analysis environment

builder = CompleteCFGBuilder(
    project,
    library_paths=["./extracted_libs/"],  # Where we put the libraries
)

cfg = builder.build_with_libraries(max_steps=500)

print(f"\n=== Complete CFG ===")
print(f"Static edges (main binary): {cfg.static_edges}")
print(f"Dynamic edges (into libraries): {cfg.dynamic_edges}")
print(f"Total coverage: {cfg.total_basic_blocks} blocks")

cfg.export_dot("complete_cfg.dot")
```

### Recursive Loading (Library A → B → C)

For chained library loading where one library loads another:

```python
from dynpathresolver.core import RecursiveLibraryAnalyzer

analyzer = RecursiveLibraryAnalyzer(project, dpr)
chain = analyzer.analyze()

for lib in chain.discovered_libraries:
    print(f"{lib.path} (loaded by: {lib.loaded_by}, depth: {lib.depth})")
```

### Quick Reference

| Scenario | Phase 1 (Discovery) | Phase 2 (Full CFG) |
|----------|--------------------|--------------------|
| Unknown malware | Run without `library_paths` | Add paths after extracting libs |
| Known plugin system | Optional | Provide plugin directories |
| Just need loading events | Run without `library_paths` | Skip Phase 2 |
| Need complete CFG | Run first | Provide all library paths |

---

## Frida Validation

DynPathResolver includes FridaValidator for ground-truth confirmation of symbolic discoveries.

### Running Frida Validation

```bash
# In Docker container (required for Frida)
docker exec -it dynpathresolver bash

# Run all benchmark validations
python3 /app/examples/benchmarks/test_frida_all_benchmarks.py
```

### Output
```
======================================================================
FridaValidator Comprehensive Benchmark Test
======================================================================

Testing 01_simple_dlopen... ✓ VERIFIED via dlopen (5.16s)
Testing 02_environment_path... ✓ VERIFIED via dlopen (5.14s)
Testing 03_xor_encrypted... ✓ VERIFIED via dlopen (5.14s)
...
Testing 12_manual_elf_load... ✓ VERIFIED via manual_elf (3.13s)
Testing 13_mmap_exec... ✓ VERIFIED via mmap_exec (3.15s)
Testing 14_rop_chain... ✓ VERIFIED via dlopen (5.15s)
Testing 16_signal_handler... ✓ VERIFIED via dlopen (3.13s)

======================================================================
SUMMARY: 15/15 VERIFIED
======================================================================
```

### Using FridaValidator Programmatically

```python
from dynpathresolver.validation import FridaValidator

validator = FridaValidator(
    binary_path="./target",
    timeout=30,
    library_paths=["./plugins"],
)

# Validate specific library
result = validator.validate_library("libplugin.so")
print(f"Status: {result.status}")  # VERIFIED, NOT_DETECTED, ERROR
print(f"Method: {result.loading_method}")  # dlopen, manual_elf, mmap_exec
print(f"Details: {result.details}")
```

### Frida Detection Methods

| Method | Description |
|--------|-------------|
| `dlopen` | Standard dynamic loading via dlopen() |
| `manual_elf` | Manual ELF parsing (mmap + custom loader) |
| `mmap_exec` | Executable memory mapping (shellcode) |

---

## Benchmarks

### Benchmark Suite (15 benchmarks)

| ID | Benchmark | Technique | Difficulty |
|----|-----------|-----------|------------|
| 01 | simple_dlopen | Direct dlopen() call | Easy |
| 02 | environment_path | Path from $LD_LIBRARY_PATH | Easy |
| 03 | xor_encrypted | XOR-encrypted library path | Medium |
| 04 | computed_path | Runtime path computation | Medium |
| 05 | multi_stage | Chained library loading (A→B→C) | Medium |
| 06 | stack_strings | Character-by-character construction | Medium |
| 07 | time_triggered | Time-based conditional loading | Hard |
| 08 | anti_debug | ptrace + /proc/self/status checks | Hard |
| 09 | memfd_create | Fileless loading via memory fd | Hard |
| 10 | indirect_call | dlopen via function pointer | Hard |
| 11 | multi_encoding | Base64 → XOR → reverse encoding | Medium |
| 12 | manual_elf_load | Manual ELF parsing (no dlopen) | Very Hard |
| 13 | mmap_exec | Shellcode via mmap(PROT_EXEC) | Hard |
| 14 | rop_chain | ROP gadget chain invoking dlopen | Very Hard |
| 16 | signal_handler | Loading triggered by signal handler | Hard |

### Running Benchmarks

```bash
# Enter Docker container
docker exec -it dynpathresolver bash

# Run DynPathResolver analysis on all benchmarks
python3 /app/examples/benchmarks/run_analysis_safe.py

# Run Frida validation on all benchmarks
python3 /app/examples/benchmarks/test_frida_all_benchmarks.py

# Run specific benchmark
python3 -c "
import angr
from dynpathresolver import DynPathResolver

project = angr.Project('/app/examples/benchmarks/03_xor_encrypted/test_binary', auto_load_libs=False)
dpr = DynPathResolver(library_paths=['/app/examples/benchmarks/03_xor_encrypted/'])

state = project.factory.entry_state()
simgr = project.factory.simgr(state)
simgr.use_technique(dpr)
simgr.run(n=100)
dpr.complete(simgr)

for event in dpr.get_library_load_events():
    print(f'Found: {event.library_path}')
"
```

### Building Benchmarks

```bash
# Inside Docker container
cd /app/examples/benchmarks
make all

# Or compile individually
cd 01_simple_dlopen
make
```

### Results

| Metric | Value |
|--------|-------|
| Total Benchmarks | 15 |
| DynPathResolver Detection | 15/15 (100%) |
| Frida Validation | 15/15 VERIFIED |
| Average Analysis Time | 4.66s |
| Median Analysis Time | 0.31s |

---

## Module Architecture

```
dynpathresolver/
├── __init__.py                 # Public API exports
├── core/                       # Core analysis engine
│   ├── technique.py            # DynPathResolver main class
│   ├── resolver.py             # SpeculativeResolver
│   ├── interceptor.py          # Event interception
│   ├── discovery_log.py        # DiscoveryLog
│   ├── recursive_analyzer.py   # Multi-stage analysis
│   ├── directed.py             # Directed exploration
│   ├── cfg_builder.py          # CompleteCFGBuilder
│   └── library_load_event.py   # LibraryLoadEvent, RegisterSnapshot
├── validation/                 # Frida validation
│   └── validator.py            # FridaValidator, HybridValidator
├── analysis/                   # Analysis components
│   ├── predictor.py            # HeuristicPredictor
│   └── control_flow.py         # ROP/JOP detection
├── tracking/                   # State tracking
│   ├── memory_tracker.py       # Memory region tracking
│   ├── taint_tracker.py        # Taint propagation
│   ├── shadow_memory.py        # Shadow memory
│   ├── signal_handler.py       # Signal tracking
│   └── ...
├── detection/                  # Obfuscation detection
│   ├── opaque_predicate_detector.py
│   ├── cff_detector.py         # Control flow flattening
│   ├── vm_detector.py          # VM obfuscation
│   ├── smc_tracker.py          # Self-modifying code
│   └── ...
├── elf/                        # ELF/binary handling
│   ├── preloader.py            # LibraryPreloader
│   ├── relocation.py           # GOT/PLT tracking
│   └── ...
└── simprocedures/              # angr SimProcedures (39 total)
    ├── dlopen.py, dlsym.py, dlclose.py
    ├── syscalls/               # mmap, memfd_create, etc.
    └── windows/                # LoadLibrary, GetProcAddress
```

---

## API Reference

### Core Classes

#### `DynPathResolver`
Main analysis engine (angr ExplorationTechnique).

```python
DynPathResolver(
    max_forks: int = 8,
    preload_common: bool = True,
    library_paths: list[str] = None,
    handle_syscall_loading: bool = False,
    track_indirect_flow: bool = False,
    detect_rop: bool = False,
    detect_jop: bool = False,
    track_signals: bool = False,
    validation_mode: str = 'none',  # 'none', 'record', 'validate'
    ...
)
```

**Key Methods:**
- `complete(simgr)` - Finalize analysis
- `get_library_load_events()` - Get LibraryLoadEvent list
- `get_discovered_libraries()` - Get library paths
- `get_executable_regions()` - Get mmap'd executable regions
- `get_rop_chains()` / `get_jop_chains()` - Get detected chains
- `export_json(path)` - Export results to JSON

#### `CompleteCFGBuilder`
Builds unified CFG with dynamic library edges.

```python
CompleteCFGBuilder(
    project: angr.Project,
    library_paths: list[str] = None,
    context_sensitivity_level: int = 1,
    keep_state: bool = True,
)
```

**Key Methods:**
- `build()` - Build CFG using CFGEmulated
- `build_with_libraries(max_steps)` - Build combined CFG with library edges
- `build_with_exploration(max_steps)` - Full symbolic exploration CFG

#### `FridaValidator`
Dynamic validation using Frida instrumentation.

```python
FridaValidator(
    binary_path: str,
    timeout: int = 30,
    library_paths: list[str] = None,
)
```

**Key Methods:**
- `validate_library(lib_name)` - Validate single library
- `validate_all()` - Validate all discovered libraries
- `run()` - Execute binary with Frida instrumentation

### Data Classes

#### `LibraryLoadEvent`
Complete state snapshot at library load.

```python
@dataclass
class LibraryLoadEvent:
    library_path: str
    library_name: str
    loading_method: LoadingMethod  # DLOPEN, MANUAL_ELF, MMAP_EXEC
    handle: int | None
    call_site: int | None
    register_snapshot: RegisterSnapshot | None
    arguments: dict[str, Any]
    constraints: list[str]
    call_stack: list[int]
```

#### `CompleteCFG`
Unified CFG with static and dynamic edges.

```python
@dataclass
class CompleteCFG:
    nodes: dict[int, CompleteCFGNode]
    edges: list[CompleteCFGEdge]
    discovered_libraries: list[str]

    @property
    def static_edges(self) -> int
    @property
    def dynamic_edges(self) -> int

    def export_dot(self, path: str)
    def export_json(self, path: str)
```

---

## Testing

### Running Tests

```bash
# All tests (537 tests)
pytest tests/ -v

# Specific test file
pytest tests/test_technique.py -v

# With coverage
pytest tests/ --cov=dynpathresolver --cov-report=html

# Run tests in Docker
docker exec dynpathresolver pytest /app/tests/ -v
```

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| Core | 150+ | DynPathResolver, CFGBuilder |
| SimProcedures | 100+ | dlopen, dlsym, mmap, etc. |
| Detection | 80+ | Obfuscation detection |
| Tracking | 100+ | Memory, taint, signals |
| Validation | 50+ | Frida integration |

---

## Docker Commands

```bash
# Start container
docker-compose up -d

# Enter container
docker exec -it dynpathresolver bash

# Run benchmarks
docker exec dynpathresolver python3 /app/examples/benchmarks/run_analysis_safe.py

# Run Frida validation
docker exec dynpathresolver python3 /app/examples/benchmarks/test_frida_all_benchmarks.py

# Run tests
docker exec dynpathresolver pytest /app/tests/ -v

# Compile paper
docker exec dynpathresolver bash -c "cd /app/paper && pdflatex enhanced_main.tex"

# Stop container
docker-compose down
```
---

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [angr](https://angr.io/) - Binary analysis framework
- [Frida](https://frida.re/) - Dynamic instrumentation (for validation only)
- [Z3](https://github.com/Z3Prover/z3) - SMT solver

## Contact

For questions or issues, please open a GitHub issue.
