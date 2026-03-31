# DynPathResolver Examples

This directory contains example binaries that demonstrate DynPathResolver's ability to discover dynamic control flow paths that static analysis misses.

## Complex Loader Example

The `complex_loader/` directory contains a sophisticated example that uses multiple techniques to hide its true behavior from static analysis:

### What It Demonstrates

1. **Encrypted Library Names**
   - Library name (`libsecret.so`) is XOR-encrypted in the binary
   - Decrypted at runtime before `dlopen()`
   - Static strings analysis won't find the library name

2. **Runtime-Computed Paths**
   - Library paths are constructed dynamically
   - Symbol names are built from string pieces
   - Defeats simple pattern matching

3. **Conditional Loading**
   - Different execution modes based on command-line args, environment, or PID
   - Static analysis sees all paths but can't determine which are taken

4. **Indirect Calls via Function Pointers**
   - All loaded functions called through pointers
   - Vtable-style dispatch pattern
   - Static analysis can't resolve the targets

5. **Plugin Architecture**
   - Separate plugin library loaded based on configuration
   - Factory pattern with dynamically resolved symbols

### Files

```
complex_loader/
├── loader.c        # Main executable with dynamic loading
├── libsecret.so    # "Hidden" library with sensitive functions
├── libplugin.so    # Plugin library for plugin mode
└── Makefile        # Build configuration for Linux
```

### Building (Linux)

```bash
cd examples/complex_loader
make all

# Optional: show what static analysis misses
make test-static

# Run the example
make run
```

### Building with Docker

```bash
# Build and enter container
docker-compose run dynpathresolver bash

# Inside container:
cd examples/complex_loader
make all
make run
```

## Running Analysis

Use the `run_analysis.py` script to analyze binaries with DynPathResolver:

```bash
# Activate virtual environment
source .venv/bin/activate

# Basic analysis
python examples/run_analysis.py examples/complex_loader/loader \
    --lib-path examples/complex_loader \
    --output output/complex_loader

# Compare static vs dynamic
python examples/run_analysis.py examples/complex_loader/loader \
    --lib-path examples/complex_loader \
    -o output/analysis
```

### Analysis Output

The analysis produces:

- `discoveries.json` - Human-readable list of discovered paths
- `discoveries.db` - SQLite database for querying results

Example JSON output:
```json
[
  {
    "source": 4198400,
    "target": 4259840,
    "type": "indirect_jump",
    "confidence": 1.0,
    "solver_solutions": [4259840, 4259856]
  }
]
```

## What Static Analysis Misses

Running `objdump` or angr's CFGFast on the loader binary reveals:

1. **No reference to `libsecret.so`** - The name is XOR-encrypted
2. **No `secret_*` function symbols** - They're in the dynamically loaded library
3. **No direct calls to sensitive functions** - All calls go through function pointers

### Verification

```bash
# Check for library references (none found)
strings loader | grep libsecret
# (empty)

# Check for function names (none found)
strings loader | grep "secret_"
# (empty)

# Check dynamic dependencies
objdump -p loader | grep NEEDED
# Only shows libc and libdl, not libsecret
```

But running the binary reveals the hidden functionality:

```bash
$ ./loader 0
[loader] Decrypted library: libsecret.so
[loader] Loading library: ./libsecret.so
[libsecret] Initialization complete
[libsecret] Computing secret value...
[libsecret] EXFILTRATING: SECRET_57050
[libsecret] Cleanup complete
```

## Creating Your Own Examples

To create a new example:

1. Create a subdirectory under `examples/`
2. Write your source code with dynamic loading
3. Create a Makefile targeting Linux x86-64
4. Add a section to this README

Key patterns to demonstrate:
- `dlopen()` / `dlsym()` usage
- Function pointer tables
- Computed/obfuscated strings
- Conditional library loading
- Plugin architectures
