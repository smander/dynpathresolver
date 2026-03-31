/**
 * Benchmark 14: ROP Chain Execution
 *
 * This benchmark demonstrates Return-Oriented Programming:
 * 1. A vulnerable function with a buffer overflow
 * 2. ROP gadgets are chained via return addresses
 * 3. The chain eventually calls dlopen or loads a library
 *
 * For safety, this is a simulated ROP that doesn't require
 * actual exploitation - it manually sets up the ROP chain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// Function pointers for ROP simulation
typedef void (*gadget_func)(void);
typedef void* (*dlopen_func)(const char*, int);

// Gadget-like functions that end in ret
__attribute__((noinline))
void gadget1_pop_rdi(void) {
    // Simulates: pop rdi; ret
    printf("[GADGET1] pop rdi simulation\n");
}

__attribute__((noinline))
void gadget2_pop_rsi(void) {
    // Simulates: pop rsi; ret
    printf("[GADGET2] pop rsi simulation\n");
}

__attribute__((noinline))
void gadget3_nop(void) {
    // Simulates: nop; ret
    printf("[GADGET3] nop gadget\n");
}

// Target function to be called via ROP
__attribute__((noinline))
void load_library_target(const char* path) {
    printf("[ROP TARGET] Loading library: %s\n", path);
    void* handle = dlopen(path, RTLD_NOW);
    if (handle) {
        printf("[ROP TARGET] Library loaded successfully\n");
        void (*func)(void) = dlsym(handle, "rop_payload");
        if (func) {
            func();
        }
        dlclose(handle);
    } else {
        printf("[ROP TARGET] dlopen failed: %s\n", dlerror());
    }
}

// Simulated ROP chain executor
// In real ROP, this would be done via stack manipulation
void execute_rop_chain(void) {
    printf("[ROP] Executing ROP chain...\n");

    // ROP chain: gadget1 -> gadget2 -> gadget3 -> load_library
    // This simulates what would happen with a real stack overflow

    gadget_func chain[] = {
        gadget1_pop_rdi,
        gadget2_pop_rsi,
        gadget3_nop,
        NULL  // End marker
    };

    printf("[ROP] Chain length: %zu gadgets\n",
           sizeof(chain)/sizeof(chain[0]) - 1);

    // Execute gadgets
    for (int i = 0; chain[i] != NULL; i++) {
        printf("[ROP] Executing gadget %d at %p\n", i, (void*)chain[i]);
        chain[i]();
    }

    // Final "gadget" - load the library
    printf("[ROP] Final gadget: calling load_library_target\n");
    load_library_target("./librop_payload.so");
}

// Vulnerable function (simulated)
void vulnerable_function(const char* input) {
    char buffer[64];

    printf("[VULN] Vulnerable function called with input length: %zu\n",
           strlen(input));

    // Simulated overflow - in real exploit, this would overwrite return address
    if (strlen(input) > 128) {
        printf("[VULN] Buffer overflow detected! Triggering ROP chain...\n");
        execute_rop_chain();
    } else {
        // Safe path
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        printf("[VULN] Safe execution: %s\n", buffer);
    }
}

int main(int argc, char* argv[]) {
    printf("Benchmark 14: ROP Chain Execution\n");
    printf("==================================\n\n");

    // Trigger the "exploit"
    char payload[256];
    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    printf("[MAIN] Calling vulnerable function with oversized input...\n\n");
    vulnerable_function(payload);

    printf("\n[MAIN] Done.\n");
    return 0;
}
