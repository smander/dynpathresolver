/**
 * Benchmark 06: Stack-based string construction
 *
 * Library name is built character-by-character on the stack.
 * No string literal exists in the binary - each character is assigned individually.
 * Common malware technique to avoid string-based detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    printf("Benchmark 06: Stack-based string construction\n");

    // Build "./libstack.so" character by character
    // This avoids having the string as a literal in the binary
    char lib_name[32];
    int i = 0;

    lib_name[i++] = '.';
    lib_name[i++] = '/';
    lib_name[i++] = 'l';
    lib_name[i++] = 'i';
    lib_name[i++] = 'b';
    lib_name[i++] = 's';
    lib_name[i++] = 't';
    lib_name[i++] = 'a';
    lib_name[i++] = 'c';
    lib_name[i++] = 'k';
    lib_name[i++] = '.';
    lib_name[i++] = 's';
    lib_name[i++] = 'o';
    lib_name[i++] = '\0';

    printf("Constructed name: %s\n", lib_name);

    void* handle = dlopen(lib_name, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    typedef void (*func_t)(void);
    func_t func = (func_t)dlsym(handle, "stack_function");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    func();
    dlclose(handle);
    return 0;
}
