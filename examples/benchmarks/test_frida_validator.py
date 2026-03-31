#!/usr/bin/env python3
"""Test FridaValidator integration in Docker."""

import os
import sys
import time

# Add project root to path
sys.path.insert(0, '/app')

from dynpathresolver.validator import FridaValidator, LoadingMethod

def test_frida_validator():
    """Test FridaValidator with the simple dlopen benchmark."""
    binary = "/app/examples/benchmarks/01_simple_dlopen/test_binary"
    expected_lib = "./libplugin.so"

    print(f"Testing FridaValidator")
    print(f"Binary: {binary}")
    print(f"Binary exists: {os.path.exists(binary)}")
    print(f"Expected lib: {expected_lib}")
    print()

    validator = FridaValidator(binary)
    print(f"Frida available: {validator._frida_available}")

    print("\nCalling check_library_loaded (timeout=10s)...")
    start = time.time()

    try:
        loaded, method = validator.check_library_loaded(
            inputs=b'',
            expected_lib=expected_lib,
            timeout=10,
        )
        elapsed = time.time() - start

        print(f"\nResult:")
        print(f"  Loaded: {loaded}")
        print(f"  Method: {method}")
        print(f"  Time: {elapsed:.2f}s")

        if loaded:
            print("\n*** SUCCESS: FridaValidator detected library loading ***")
            return True
        else:
            print("\n*** FAILED: FridaValidator did not detect library loading ***")
            return False

    except Exception as e:
        elapsed = time.time() - start
        print(f"\nError after {elapsed:.2f}s: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Enable debug logging
    import logging
    logging.basicConfig(level=logging.DEBUG)

    success = test_frida_validator()
    sys.exit(0 if success else 1)
