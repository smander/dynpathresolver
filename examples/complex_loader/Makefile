# Makefile for Complex Dynamic Loader Example
#
# This builds:
# - libsecret.so   : Dynamically loaded "secret" library
# - libplugin.so   : Plugin library loaded based on config
# - loader         : Main executable that loads libraries at runtime
#
# Build for Linux x86-64

CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-pie
LDFLAGS = -no-pie -ldl

# Shared library flags
SO_CFLAGS = -fPIC -shared -fvisibility=hidden
SO_LDFLAGS = -shared

# Targets
LOADER = loader
LIBS = libsecret.so libplugin.so

.PHONY: all clean run test

all: $(LIBS) $(LOADER)

# Build the main loader executable
$(LOADER): loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[+] Built loader executable"

# Build libsecret.so
libsecret.so: libsecret.c
	$(CC) $(SO_CFLAGS) -o $@ $< $(SO_LDFLAGS)
	@echo "[+] Built libsecret.so"

# Build libplugin.so
libplugin.so: libplugin.c
	$(CC) $(SO_CFLAGS) -o $@ $< $(SO_LDFLAGS)
	@echo "[+] Built libplugin.so"

# Run the loader with different modes
run: all
	@echo "\n=== Running Mode 0 (Direct) ==="
	LIB_DIR=. ./$(LOADER) 0
	@echo "\n=== Running Mode 1 (Vtable) ==="
	LIB_DIR=. ./$(LOADER) 1
	@echo "\n=== Running Mode 2 (Plugin) ==="
	LIB_DIR=. ./$(LOADER) 2

# Test that static analysis misses the dynamic paths
test-static: all
	@echo "=== Static Analysis Test ==="
	@echo "This demonstrates what static analysis misses:"
	@echo ""
	@echo "Strings in binary (looking for function names):"
	@strings $(LOADER) | grep -E "(secret_|exfiltrate)" || echo "  [!] No direct function references found (expected)"
	@echo ""
	@echo "Library references:"
	@objdump -p $(LOADER) | grep NEEDED || echo "  [!] No NEEDED entries for libsecret (expected)"
	@echo ""
	@echo "But at runtime we see:"
	@LIB_DIR=. ./$(LOADER) 0 2>&1 | head -10

clean:
	rm -f $(LOADER) $(LIBS)
	rm -f *.o

# Show info about the binaries
info: all
	@echo "=== Binary Information ==="
	@echo ""
	@echo "Loader:"
	@file $(LOADER)
	@echo ""
	@echo "Libraries:"
	@file $(LIBS)
	@echo ""
	@echo "Symbols in libsecret.so:"
	@nm -D libsecret.so | grep -E "^[0-9a-f]+ T"
	@echo ""
	@echo "Symbols in libplugin.so:"
	@nm -D libplugin.so | grep -E "^[0-9a-f]+ T"
