/**
 * Benchmark 05: Multi-stage loading
 *
 * First library loads second library.
 * Creates a chain of dynamic loads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    printf("Benchmark 05: Multi-stage loading\n");

    // Stage 1: Load first library
    void* stage1 = dlopen("./libstage1.so", RTLD_NOW);
    if (!stage1) {
        fprintf(stderr, "Stage 1 dlopen failed: %s\n", dlerror());
        return 1;
    }

    // Get stage1's loader function
    typedef void* (*load_next_t)(void);
    load_next_t load_next = (load_next_t)dlsym(stage1, "load_next_stage");
    if (!load_next) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(stage1);
        return 1;
    }

    // Stage 2: Stage 1 loads Stage 2
    printf("Calling stage1 to load stage2...\n");
    void* stage2 = load_next();
    if (!stage2) {
        fprintf(stderr, "Stage 2 loading failed\n");
        dlclose(stage1);
        return 1;
    }

    // Get final payload from stage2
    typedef void (*payload_t)(void);
    payload_t payload = (payload_t)dlsym(stage2, "final_payload");
    if (!payload) {
        fprintf(stderr, "Final payload not found\n");
        dlclose(stage1);
        return 1;
    }

    // Execute
    payload();

    // Cleanup
    dlclose(stage1);
    return 0;
}
