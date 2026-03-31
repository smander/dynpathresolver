/**
 * Benchmark 04: Computed library path
 *
 * Library path is computed from multiple runtime sources:
 * - Command line argument
 * - Process ID
 * - Current time
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>

static char* compute_library_name(const char* base) {
    static char name[256];

    // Use PID to select variant (for demonstration)
    int variant = getpid() % 3;

    // In real malware, this would be more complex
    // For benchmark, we just use the base name
    (void)variant;

    snprintf(name, sizeof(name), "./%s.so", base);
    return name;
}

int main(int argc, char* argv[]) {
    printf("Benchmark 04: Computed path\n");

    const char* base = (argc > 1) ? argv[1] : "libcomputed";

    // Compute library name at runtime
    char* lib_path = compute_library_name(base);
    printf("Computed path: %s\n", lib_path);

    void* handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    // Also compute symbol name
    char symbol_name[64];
    snprintf(symbol_name, sizeof(symbol_name), "compute_%s", "result");

    typedef int (*compute_func_t)(int, int);
    compute_func_t func = (compute_func_t)dlsym(handle, symbol_name);
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    int result = func(10, 20);
    printf("Result: %d\n", result);

    dlclose(handle);
    return 0;
}
