#!/bin/bash
# Cross-compile benchmarks for Linux ARM64 using Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Build all benchmarks using Docker with Linux ARM64
docker run --rm -v "$SCRIPT_DIR:/benchmarks" -w /benchmarks \
    --platform linux/arm64 \
    gcc:14 \
    bash -c '
        for dir in 06_stack_strings 07_time_triggered 08_anti_debug 09_memfd_create 10_indirect_call 11_multi_encoding 12_manual_elf_load; do
            if [ -d "$dir" ] && [ -f "$dir/Makefile" ]; then
                echo "=== Building $dir ==="
                cd "$dir"
                make clean 2>/dev/null || true
                make CC=gcc CFLAGS="-Wall -g" LDFLAGS="-ldl" 2>&1
                file test_binary 2>/dev/null || echo "No test_binary created"
                cd ..
            fi
        done
    '

echo "Done!"
