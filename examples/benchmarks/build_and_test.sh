#!/bin/bash
# Build and test all benchmarks (including new ones) using Docker
# Supports both ARM64 and x86_64 architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    DOCKER_PLATFORM="linux/arm64"
else
    DOCKER_PLATFORM="linux/amd64"
fi

echo "=== DynPathResolver Benchmark Builder ==="
echo "Architecture: $ARCH"
echo "Docker platform: $DOCKER_PLATFORM"
echo "Benchmarks directory: $SCRIPT_DIR"
echo ""

# All benchmarks to build
BENCHMARKS=(
    "01_simple_dlopen"
    "02_environment_path"
    "03_xor_encrypted"
    "04_computed_path"
    "05_multi_stage"
    "06_stack_strings"
    "07_time_triggered"
    "08_anti_debug"
    "09_memfd_create"
    "10_indirect_call"
    "11_multi_encoding"
    "12_manual_elf_load"
    "13_mmap_exec"
    "14_rop_chain"
    "16_signal_handler"
)

# Build all benchmarks in Docker
echo "=== Building benchmarks in Docker ==="
docker run --rm -v "$SCRIPT_DIR:/benchmarks" -w /benchmarks \
    --platform "$DOCKER_PLATFORM" \
    gcc:14 \
    bash -c '
        for dir in '"${BENCHMARKS[*]}"'; do
            if [ -d "$dir" ] && [ -f "$dir/Makefile" ]; then
                echo ""
                echo "=== Building $dir ==="
                cd "$dir"
                make clean 2>/dev/null || true
                make CC=gcc CFLAGS="-Wall -g" LDFLAGS="-ldl" 2>&1 || echo "Build failed for $dir"
                if [ -f test_binary ]; then
                    echo "✓ Built: $dir/test_binary"
                    file test_binary
                else
                    echo "✗ No test_binary created for $dir"
                fi
                cd ..
            else
                echo "⚠ Skipping $dir (no Makefile found)"
            fi
        done
        echo ""
        echo "=== Build Summary ==="
        ls -la */test_binary 2>/dev/null || echo "No binaries found"
    '

echo ""
echo "=== Running benchmarks in Docker ==="

# Run each benchmark and capture output
docker run --rm -v "$SCRIPT_DIR:/benchmarks" -w /benchmarks \
    --platform "$DOCKER_PLATFORM" \
    gcc:14 \
    bash -c '
        PASSED=0
        FAILED=0
        SKIPPED=0

        for dir in '"${BENCHMARKS[*]}"'; do
            if [ -d "$dir" ] && [ -f "$dir/test_binary" ]; then
                echo ""
                echo "=== Running $dir ==="
                cd "$dir"

                # Run with timeout
                timeout 10s ./test_binary 2>&1 || {
                    EXIT_CODE=$?
                    if [ $EXIT_CODE -eq 124 ]; then
                        echo "⚠ Timeout (10s)"
                    else
                        echo "✗ Exit code: $EXIT_CODE"
                    fi
                }

                cd ..
            else
                echo "⚠ Skipping $dir (no test_binary)"
                ((SKIPPED++))
            fi
        done

        echo ""
        echo "=== Benchmark Execution Complete ==="
    '

echo ""
echo "=== Done ==="
