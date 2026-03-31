/**
 * Benchmark 07: Time-triggered payload
 *
 * Library is only loaded after a specific time condition.
 * Simulates malware that activates on a specific date or after delay.
 * Uses symbolic time to test if analyzer can explore time-dependent paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>

// Activation timestamp (set to a past date so it always triggers for testing)
#define ACTIVATION_TIME 1609459200  // 2021-01-01 00:00:00 UTC

int main(int argc, char* argv[]) {
    printf("Benchmark 07: Time-triggered payload\n");

    time_t now = time(NULL);
    printf("Current time: %ld\n", (long)now);
    printf("Activation time: %ld\n", (long)ACTIVATION_TIME);

    // Time-based trigger - only load if past activation time
    if (now >= ACTIVATION_TIME) {
        printf("Activation time reached, loading payload...\n");

        void* handle = dlopen("./libtimed.so", RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }

        typedef void (*func_t)(void);
        func_t func = (func_t)dlsym(handle, "timed_payload");
        if (!func) {
            fprintf(stderr, "dlsym failed: %s\n", dlerror());
            dlclose(handle);
            return 1;
        }

        func();
        dlclose(handle);
    } else {
        printf("Not yet activated, sleeping...\n");
    }

    return 0;
}
