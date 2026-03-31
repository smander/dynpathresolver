"""
Tests for complex dynamic loader scenarios.

These tests verify that DynPathResolver can handle:
- XOR-encrypted library names
- Runtime-computed paths
- Function pointer dispatch
- Plugin architectures

Note: These tests require the example binaries to be built.
Run `make all` in examples/complex_loader/ first, or use Docker.
"""

import pytest
import os
import subprocess
import json
from pathlib import Path


# Path to examples directory
EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "complex_loader"


@pytest.fixture(scope="module")
def complex_loader_binaries(tmp_path_factory):
    """
    Build the complex loader example binaries for testing.

    This fixture builds the binaries from source if gcc is available.
    """
    build_dir = tmp_path_factory.mktemp("complex_loader")

    # Write the source files
    # loader.c
    loader_src = build_dir / "loader.c"
    loader_src.write_text('''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define XOR_KEY 0x5A

/* Encrypted "libsecret.so" - XOR'd with 0x5A */
static unsigned char encrypted_lib[] = {
    0x36, 0x33, 0x38, 0x29, 0x3f, 0x39, 0x28, 0x3f,
    0x2e, 0x74, 0x29, 0x35, 0x00
};

typedef void (*init_fn)(void);
typedef int (*compute_fn)(int, int);

static char* decrypt_libname(unsigned char* encrypted, size_t len) {
    char* decrypted = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ XOR_KEY;
    }
    decrypted[len] = 0;
    return decrypted;
}

int main(int argc, char** argv) {
    char* lib_dir = getenv("LIB_DIR");
    if (!lib_dir) lib_dir = ".";

    char* libname = decrypt_libname(encrypted_lib, sizeof(encrypted_lib) - 1);
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", lib_dir, libname);
    free(libname);

    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\\n", dlerror());
        return 1;
    }

    init_fn init = (init_fn)dlsym(handle, "secret_init");
    compute_fn compute = (compute_fn)dlsym(handle, "secret_compute");

    if (init && compute) {
        init();
        int result = compute(0x1337, 0xBEEF);
        printf("Result: 0x%x\\n", result);
    }

    dlclose(handle);
    return 0;
}
''')

    # libsecret.c
    libsecret_src = build_dir / "libsecret.c"
    libsecret_src.write_text('''
#include <stdio.h>

__attribute__((visibility("default")))
void secret_init(void) {
    printf("[secret] init\\n");
}

__attribute__((visibility("default")))
int secret_compute(int a, int b) {
    printf("[secret] computing\\n");
    return (a ^ b) + 0xDEAD;
}
''')

    # Build
    loader_bin = build_dir / "loader"
    libsecret_so = build_dir / "libsecret.so"

    # Try to build
    try:
        # Build library
        result = subprocess.run(
            ["gcc", "-fPIC", "-shared", "-fvisibility=hidden",
             "-o", str(libsecret_so), str(libsecret_src)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"Failed to build libsecret.so: {result.stderr.decode()}")

        # Build loader
        result = subprocess.run(
            ["gcc", "-Wall", "-g", "-O0", "-no-pie",
             "-o", str(loader_bin), str(loader_src), "-ldl"],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"Failed to build loader: {result.stderr.decode()}")

        if not loader_bin.exists() or not libsecret_so.exists():
            pytest.skip("Build produced no output")

    except FileNotFoundError:
        pytest.skip("gcc not available")
    except subprocess.TimeoutExpired:
        pytest.skip("Build timed out")

    return {
        'loader': str(loader_bin),
        'libsecret': str(libsecret_so),
        'lib_dir': str(build_dir),
    }


class TestComplexLoader:
    """Tests for complex dynamic loader scenarios."""

    def test_loader_runs_correctly(self, complex_loader_binaries):
        """Verify the test binary runs correctly."""
        import platform

        result = subprocess.run(
            [complex_loader_binaries['loader']],
            capture_output=True,
            env={**os.environ, 'LIB_DIR': complex_loader_binaries['lib_dir']},
            timeout=10,
        )

        stdout = result.stdout.decode()
        stderr = result.stderr.decode()

        # On macOS, dlopen may fail due to library loading restrictions
        if platform.system() == "Darwin" and "dlopen failed" in stderr:
            pytest.skip("dlopen restrictions on macOS (use Docker for full test)")

        assert result.returncode == 0, f"Loader failed: {stderr}"
        assert "[secret] init" in stdout
        assert "[secret] computing" in stdout
        assert "Result: 0x" in stdout

    def test_static_analysis_misses_library(self, complex_loader_binaries):
        """Verify that static string analysis misses the encrypted library name."""
        try:
            result = subprocess.run(
                ["strings", complex_loader_binaries['loader']],
                capture_output=True,
                timeout=10,
            )
        except FileNotFoundError:
            pytest.skip("strings command not available")

        strings_output = result.stdout.decode()

        # The encrypted library name should NOT appear in plaintext
        # This is the key demonstration - the library name is XOR encrypted
        assert "libsecret.so" not in strings_output

        # Note: symbol names (secret_init, secret_compute) ARE in the binary
        # because they're passed to dlsym(). In the full example (loader.c),
        # these are also computed at runtime from pieces.

    def test_dynpathresolver_analyzes_without_crash(self, complex_loader_binaries, tmp_path):
        """Test that DynPathResolver can analyze the complex loader."""
        import angr
        from dynpathresolver import DynPathResolver

        proj = angr.Project(
            complex_loader_binaries['loader'],
            auto_load_libs=False,
        )

        state = proj.factory.entry_state()
        simgr = proj.factory.simgr(state)

        output_dir = str(tmp_path / "output")
        dpr = DynPathResolver(
            max_forks=4,
            preload_common=False,
            library_paths=[complex_loader_binaries['lib_dir']],
            output_dir=output_dir,
        )
        simgr.use_technique(dpr)

        # Run limited exploration
        for _ in range(200):
            if not simgr.active:
                break
            simgr.step()

        # Export results
        dpr.complete(simgr)

        # Verify output files created
        assert os.path.exists(os.path.join(output_dir, "discoveries.json"))
        assert os.path.exists(os.path.join(output_dir, "discoveries.db"))

    def test_preloader_finds_library_strings(self, complex_loader_binaries):
        """Test that preloader can scan for library patterns."""
        import angr
        from dynpathresolver import LibraryPreloader

        proj = angr.Project(
            complex_loader_binaries['loader'],
            auto_load_libs=False,
        )

        preloader = LibraryPreloader(proj)

        # Scan for library strings
        libs = preloader.scan_for_library_strings()

        # The encrypted name won't be found, but this shouldn't crash
        assert isinstance(libs, set)

    def test_resolver_handles_symbolic_targets(self, complex_loader_binaries):
        """Test that resolver handles symbolic jump targets."""
        import angr
        import claripy
        from dynpathresolver import SpeculativeResolver

        proj = angr.Project(
            complex_loader_binaries['loader'],
            auto_load_libs=False,
        )

        resolver = SpeculativeResolver(proj, max_forks=4)
        state = proj.factory.blank_state()

        # Create symbolic target
        target = claripy.BVS('target', 64)

        # Get executable ranges
        ranges = resolver._get_executable_ranges()
        assert len(ranges) > 0

        # Constrain to valid range
        start, end = ranges[0]
        state.solver.add(target >= start)
        state.solver.add(target <= min(start + 0x100, end))

        # Resolve
        solutions = resolver.resolve(state, target)

        assert len(solutions) > 0
        assert all(start <= s <= end for s in solutions)


class TestLibraryPreloading:
    """Tests for library preloading functionality."""

    def test_add_library_directory(self, complex_loader_binaries):
        """Test adding a directory of libraries."""
        import angr
        from dynpathresolver import LibraryPreloader

        proj = angr.Project(
            complex_loader_binaries['loader'],
            auto_load_libs=False,
        )

        preloader = LibraryPreloader(proj)
        preloader.add_library_paths([complex_loader_binaries['lib_dir']])

        # Should find libsecret.so
        assert any("libsecret.so" in p for p in preloader.pending_libs)

    def test_common_libs_on_linux(self, complex_loader_binaries):
        """Test that common library list is reasonable."""
        import angr
        from dynpathresolver import LibraryPreloader

        proj = angr.Project(
            complex_loader_binaries['loader'],
            auto_load_libs=False,
        )

        preloader = LibraryPreloader(proj)

        assert "libc.so.6" in preloader.COMMON_LIBS
        assert "libdl.so.2" in preloader.COMMON_LIBS
