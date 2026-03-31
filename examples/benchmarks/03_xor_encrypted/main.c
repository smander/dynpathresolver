/**
 * Benchmark 03: XOR-encrypted library path
 *
 * Library name is XOR-encrypted in the binary.
 * Static analysis sees only encrypted bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define XOR_KEY 0x5A

// "libhidden.so" XOR'd with 0x5A
static const unsigned char encrypted_name[] = {
    0x36, 0x33, 0x38, 0x32, 0x33, 0x3e, 0x3e, 0x3f,
    0x34, 0x74, 0x29, 0x35, 0x00  // null terminator
};

static void decrypt(const unsigned char* enc, char* dec, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dec[i] = enc[i] ^ XOR_KEY;
    }
}

int main(int argc, char* argv[]) {
    printf("Benchmark 03: XOR-encrypted path\n");

    // Decrypt library name at runtime
    char lib_name[64];
    decrypt(encrypted_name, lib_name, sizeof(encrypted_name) - 1);  // Don't decrypt null terminator
    lib_name[sizeof(encrypted_name) - 1] = '\0';  // Add null terminator

    printf("Decrypted name: %s\n", lib_name);

    // Build full path
    char path[256];
    snprintf(path, sizeof(path), "./%s", lib_name);

    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    typedef void (*hidden_func_t)(void);
    hidden_func_t func = (hidden_func_t)dlsym(handle, "hidden_function");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    func();

    dlclose(handle);
    return 0;
}
