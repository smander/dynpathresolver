"""Pytest fixtures for DynPathResolver tests."""

import pytest
import angr
import tempfile
import os


@pytest.fixture
def simple_binary(tmp_path):
    """Create a minimal ELF binary for testing."""
    # Minimal x86-64 ELF that just exits
    src = tmp_path / "simple.c"
    src.write_text("""
int main() {
    return 0;
}
""")
    binary = tmp_path / "simple"
    os.system(f"gcc -o {binary} {src} 2>/dev/null || echo 'gcc not available'")
    if binary.exists():
        return str(binary)
    return None


@pytest.fixture
def angr_project(simple_binary):
    """Create an angr project from the simple binary."""
    if simple_binary is None:
        pytest.skip("gcc not available for building test binary")
    return angr.Project(simple_binary, auto_load_libs=False)
