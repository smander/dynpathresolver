#!/usr/bin/env python3
"""Test FridaValidator on first 3 benchmarks."""

import os
import sys
import time

# Force unbuffered output
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None
os.environ['PYTHONUNBUFFERED'] = '1'

sys.path.insert(0, '/app')

from dynpathresolver.validator import FridaValidator, LoadingMethod

BENCHMARKS = [
    ("01_simple_dlopen", "./libplugin.so"),
    ("02_conditional_load", "./libfeature.so"),
    ("03_path_from_env", "./libfromenv.so"),
]

def main():
    print("Testing first 3 benchmarks with FridaValidator", flush=True)
    print("=" * 50, flush=True)

    for name, expected_lib in BENCHMARKS:
        binary = f"/app/examples/benchmarks/{name}/test_binary"
        print(f"\n{name}:")
        print(f"  Binary: {binary}")
        print(f"  Expected: {expected_lib}")
        print(f"  Exists: {os.path.exists(binary)}")

        if not os.path.exists(binary):
            print("  SKIP: Binary not found")
            continue

        print("  Creating validator...", flush=True)
        validator = FridaValidator(binary)
        print(f"  Frida available: {validator._frida_available}", flush=True)

        start = time.time()
        print("  Calling check_library_loaded...", flush=True)
        try:
            loaded, method = validator.check_library_loaded(
                inputs=b'',
                expected_lib=expected_lib,
                timeout=5,
            )
            print("  Returned from check_library_loaded", flush=True)
            elapsed = time.time() - start

            if loaded:
                print(f"  VERIFIED via {method.value} ({elapsed:.2f}s)")
            else:
                print(f"  NOT DETECTED ({elapsed:.2f}s)")
        except Exception as e:
            elapsed = time.time() - start
            print(f"  ERROR after {elapsed:.2f}s: {e}")

    print("\n" + "=" * 50)
    print("Done")

if __name__ == "__main__":
    main()
