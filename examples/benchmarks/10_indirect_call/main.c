/**
 * Benchmark 10: Indirect dlopen call via function pointer
 *
 * dlopen is called through a function pointer, not directly.
 * This makes it harder for static analysis to identify dlopen calls.
 * Common technique to evade simple pattern matching.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Function pointer types
typedef void* (*dlopen_fn)(const char*, int);
typedef void* (*dlsym_fn)(void*, const char*);
typedef int (*dlclose_fn)(void*);

// Global function pointers - assigned at runtime
static dlopen_fn my_dlopen = NULL;
static dlsym_fn my_dlsym = NULL;
static dlclose_fn my_dlclose = NULL;

static void init_dl_functions(void) {
    // Get dlopen/dlsym/dlclose via dlsym from RTLD_DEFAULT
    // This obfuscates which functions we're actually calling
    my_dlopen = (dlopen_fn)dlsym(RTLD_DEFAULT, "dlopen");
    my_dlsym = (dlsym_fn)dlsym(RTLD_DEFAULT, "dlsym");
    my_dlclose = (dlclose_fn)dlsym(RTLD_DEFAULT, "dlclose");
}

int main(int argc, char* argv[]) {
    printf("Benchmark 10: Indirect dlopen via function pointer\n");

    // Initialize function pointers
    init_dl_functions();

    if (!my_dlopen || !my_dlsym || !my_dlclose) {
        fprintf(stderr, "Failed to resolve dl functions\n");
        return 1;
    }

    printf("Resolved dl functions via dlsym\n");

    // Call dlopen through function pointer
    void* handle = my_dlopen("./libindirect.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    // Call dlsym through function pointer
    typedef void (*func_t)(void);
    func_t func = (func_t)my_dlsym(handle, "indirect_function");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        my_dlclose(handle);
        return 1;
    }

    func();

    my_dlclose(handle);
    return 0;
}
