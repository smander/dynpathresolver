"""Integration tests for DynPathResolver."""

import pytest
import os
import subprocess


@pytest.fixture(scope="module")
def indirect_jump_binary(tmp_path_factory):
    """Build the indirect_jump test binary."""
    build_dir = tmp_path_factory.mktemp("binaries")

    # Write source
    src = build_dir / "indirect_jump.c"
    src.write_text('''
#include <stdio.h>

void target_a(void) {
    printf("Target A\\n");
}

void target_b(void) {
    printf("Target B\\n");
}

int main(int argc, char *argv[]) {
    void (*func_ptr)(void);

    if (argc > 1) {
        func_ptr = target_a;
    } else {
        func_ptr = target_b;
    }

    func_ptr();
    return 0;
}
''')

    binary = build_dir / "indirect_jump"
    result = subprocess.run(
        ["gcc", "-Wall", "-g", "-O0", "-no-pie", "-o", str(binary), str(src)],
        capture_output=True,
    )

    if result.returncode != 0 or not binary.exists():
        pytest.skip("gcc not available or compilation failed")

    return str(binary)


class TestIntegration:
    def test_resolve_indirect_call(self, indirect_jump_binary, tmp_path):
        """Test that DynPathResolver resolves the indirect call."""
        import angr
        from dynpathresolver import DynPathResolver

        proj = angr.Project(indirect_jump_binary, auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simgr(state)

        output_dir = str(tmp_path / "output")
        dpr = DynPathResolver(
            max_forks=4,
            preload_common=False,
            output_dir=output_dir,
        )
        simgr.use_technique(dpr)

        # Run for a limited number of steps
        for _ in range(100):
            if not simgr.active:
                break
            simgr.step()

        # Trigger export
        dpr.complete(simgr)

        # Check that output was created
        assert os.path.exists(os.path.join(output_dir, "discoveries.json"))
        assert os.path.exists(os.path.join(output_dir, "discoveries.db"))

    def test_technique_does_not_crash(self, indirect_jump_binary):
        """Test that the technique doesn't crash during exploration."""
        import angr
        from dynpathresolver import DynPathResolver

        proj = angr.Project(indirect_jump_binary, auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simgr(state)

        dpr = DynPathResolver(max_forks=2, preload_common=False)
        simgr.use_technique(dpr)

        # Should not raise
        for _ in range(50):
            if not simgr.active:
                break
            simgr.step()
