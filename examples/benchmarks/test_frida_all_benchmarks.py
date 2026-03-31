#!/usr/bin/env python3
"""Test FridaValidator on all benchmarks in Docker."""

import os
import sys
import time

# Force unbuffered output
os.environ['PYTHONUNBUFFERED'] = '1'

sys.path.insert(0, '/app')

from dynpathresolver.validation.validator import FridaValidator, LoadingMethod

# Actual benchmark configurations matching the directory structure
BENCHMARKS = {
    "01_simple_dlopen": {"expected": "libplugin.so"},
    "02_environment_path": {"expected": "libplugin.so"},
    "03_xor_encrypted": {"expected": "libhidden.so"},
    "04_computed_path": {"expected": "libcomputed.so"},
    "05_multi_stage": {"expected": "libstage1.so"},
    "06_stack_strings": {"expected": "libstack.so"},
    "07_time_triggered": {"expected": "libtimed.so"},
    "08_anti_debug": {"expected": "libprotected.so"},
    "09_memfd_create": {"expected": "libmemfd_payload.so"},
    "10_indirect_call": {"expected": "libindirect.so"},
    "11_multi_encoding": {"expected": "libmulti.so"},
    "12_manual_elf_load": {"expected": "libmanual.so"},
    "13_mmap_exec": {"expected": "libmmap_payload.so"},
    "14_rop_chain": {"expected": "librop_payload.so"},
    "16_signal_handler": {"expected": "libsignal_payload.so"},
}

def test_benchmark(name, config):
    """Test a single benchmark with FridaValidator."""
    benchmark_dir = f"/app/examples/benchmarks/{name}"
    binary = f"{benchmark_dir}/test_binary"
    expected = config["expected"]

    if not os.path.exists(binary):
        return {"status": "SKIP", "reason": "Binary not found", "time": 0}

    validator = FridaValidator(binary)

    start = time.time()
    try:
        loaded, method = validator.check_library_loaded(
            inputs=b'',
            expected_lib=expected,
            timeout=10,
        )
        elapsed = time.time() - start

        if loaded:
            return {
                "status": "VERIFIED",
                "method": method.value,
                "time": elapsed,
            }
        else:
            return {
                "status": "NOT_DETECTED",
                "method": method.value if method else "unknown",
                "time": elapsed,
            }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "status": "ERROR",
            "error": str(e),
            "time": elapsed,
        }

def main():
    print("=" * 70)
    print("FridaValidator Comprehensive Benchmark Test")
    print("=" * 70)
    print()

    results = {}
    verified = 0
    not_detected = 0
    errors = 0
    skipped = 0

    for name, config in BENCHMARKS.items():
        print(f"Testing {name}...", end=" ", flush=True)
        result = test_benchmark(name, config)
        results[name] = result

        if result["status"] == "VERIFIED":
            print(f"✓ VERIFIED via {result['method']} ({result['time']:.2f}s)")
            verified += 1
        elif result["status"] == "NOT_DETECTED":
            print(f"✗ NOT DETECTED ({result['time']:.2f}s)")
            not_detected += 1
        elif result["status"] == "ERROR":
            print(f"✗ ERROR: {result['error'][:50]}")
            errors += 1
        elif result["status"] == "SKIP":
            print(f"- SKIPPED: {result['reason']}")
            skipped += 1

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total benchmarks: {len(BENCHMARKS)}")
    print(f"Verified (via Frida): {verified}")
    print(f"Not detected: {not_detected}")
    print(f"Errors: {errors}")
    print(f"Skipped: {skipped}")
    print()

    # Show detailed results for non-verified benchmarks
    if not_detected > 0 or errors > 0:
        print("Benchmarks NOT verified via Frida:")
        for name, result in results.items():
            if result["status"] in ("NOT_DETECTED", "ERROR"):
                print(f"  - {name}: {result}")

    return verified == len(BENCHMARKS) - skipped

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
