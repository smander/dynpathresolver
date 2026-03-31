/**
 * Benchmark 01: Simple dlopen
 *
 * The simplest case - hardcoded library path.
 * Even this defeats static analysis because the library
 * is loaded at runtime.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    printf("Benchmark 01: Simple dlopen\n");

    // Hardcoded path - still invisible to static analysis
    void* handle = dlopen("./libplugin.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    // Get function pointer
    typedef int (*plugin_func_t)(int);
    plugin_func_t func = (plugin_func_t)dlsym(handle, "plugin_process");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // Call it
    int result = func(42);
    printf("Result: %d\n", result);

    dlclose(handle);
    return 0;
}
