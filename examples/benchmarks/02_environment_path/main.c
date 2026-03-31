/**
 * Benchmark 02: Environment-derived path
 *
 * Library path is constructed from environment variable.
 * Static analysis cannot know what PLUGIN_DIR contains.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    printf("Benchmark 02: Environment-derived path\n");

    // Get directory from environment
    const char* plugin_dir = getenv("PLUGIN_DIR");
    if (!plugin_dir) {
        plugin_dir = ".";  // Fallback
    }

    // Construct path at runtime
    char path[256];
    snprintf(path, sizeof(path), "%s/libplugin.so", plugin_dir);

    printf("Loading from: %s\n", path);

    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    typedef int (*process_func_t)(const char*);
    process_func_t func = (process_func_t)dlsym(handle, "process_data");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    int result = func("test data");
    printf("Result: %d\n", result);

    dlclose(handle);
    return 0;
}
