# Makefile for network_triggered_loader example
#
# Builds:
#   - loader: Main binary with network-triggered dynamic loading
#   - libpayload.so: Hidden payload library (never referenced statically)

CC = gcc
CFLAGS = -Wall -Wextra -g -O0
LDFLAGS = -ldl

# Platform-specific flags
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
    CFLAGS += -fno-pie
    LDFLAGS += -no-pie
    LIB_FLAGS = -fPIC -shared -fvisibility=hidden
else
    # macOS
    LIB_FLAGS = -dynamiclib -fvisibility=hidden
endif

.PHONY: all clean test

all: libpayload.so loader
	@echo "[+] Build complete"
	@echo "    - loader: Main binary"
	@echo "    - libpayload.so: Hidden payload library"

libpayload.so: libpayload.c
	$(CC) $(LIB_FLAGS) -o $@ $<
	@echo "[+] Built libpayload.so (hidden payload)"

loader: loader.c protocol.h crypto.h anti_analysis.h
	$(CC) $(CFLAGS) -o $@ loader.c $(LDFLAGS)
	@echo "[+] Built loader (network-triggered)"

clean:
	rm -f loader libpayload.so
	rm -f *.o

# Test target - requires two terminals or background processes
test: all
	@echo ""
	@echo "=== Testing Network-Triggered Loader ==="
	@echo ""
	@echo "Run in Terminal 1:"
	@echo "  ./loader --skip-checks"
	@echo ""
	@echo "Run in Terminal 2:"
	@echo "  python3 test_server.py"
	@echo ""

# Automated test (runs both in background)
test-auto: all
	@echo "Starting automated test..."
	@echo "1. Starting loader in background..."
	./loader --skip-checks &
	@sleep 2
	@echo "2. Sending trigger from test server..."
	python3 test_server.py --delay 0
	@echo "Test complete."
