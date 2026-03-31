/**
 * Benchmark 16: Signal Handler Library Loading
 *
 * Library is loaded inside a signal handler:
 * 1. Register a signal handler for SIGUSR1
 * 2. Signal handler loads a library via dlopen
 * 3. Trigger the signal via raise()
 *
 * This evades tools that only monitor the main execution path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>

// Global to track if handler was called
static volatile int handler_called = 0;

// Signal handler that loads a library
void signal_handler(int signum) {
    printf("[HANDLER] Signal %d received!\n", signum);

    // Load library inside signal handler
    const char* lib_path = "./libsignal_payload.so";
    printf("[HANDLER] Loading library: %s\n", lib_path);

    void* handle = dlopen(lib_path, RTLD_NOW);
    if (handle) {
        printf("[HANDLER] Library loaded successfully\n");

        // Call function from loaded library
        typedef void (*payload_func)(void);
        payload_func func = (payload_func)dlsym(handle, "signal_payload");
        if (func) {
            func();
        } else {
            printf("[HANDLER] dlsym failed: %s\n", dlerror());
        }

        // Note: In real code, dlclose in signal handler is problematic
        // but we do it here for completeness
        dlclose(handle);
    } else {
        printf("[HANDLER] dlopen failed: %s\n", dlerror());
    }

    handler_called = 1;
    printf("[HANDLER] Signal handler complete\n");
}

// Alternative handler using signal() instead of sigaction()
void alt_signal_handler(int signum) {
    printf("[ALT_HANDLER] Signal %d received!\n", signum);

    // Load a different library
    void* handle = dlopen("./libsignal_alt.so", RTLD_NOW);
    if (handle) {
        printf("[ALT_HANDLER] Alt library loaded\n");
        dlclose(handle);
    }
}

int main(int argc, char* argv[]) {
    printf("Benchmark 16: Signal Handler Library Loading\n");
    printf("=============================================\n\n");

    // Method 1: Using sigaction() - preferred modern approach
    printf("[MAIN] Setting up signal handler via sigaction()...\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }
    printf("[MAIN] Handler registered for SIGUSR1\n");

    // Method 2: Using signal() - older approach
    printf("[MAIN] Setting up handler via signal()...\n");
    if (signal(SIGUSR2, alt_signal_handler) == SIG_ERR) {
        perror("signal");
        return 1;
    }
    printf("[MAIN] Handler registered for SIGUSR2\n");

    // Trigger SIGUSR1 - this will cause library loading
    printf("\n[MAIN] Raising SIGUSR1...\n");
    raise(SIGUSR1);

    // Wait for handler to complete
    while (!handler_called) {
        usleep(1000);  // Brief wait
    }

    printf("\n[MAIN] Handler was called, library was loaded.\n");
    printf("[MAIN] Done.\n");

    return 0;
}
