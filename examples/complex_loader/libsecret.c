    /*
 * libsecret.c - Secret payload library
 *
 * This library contains the "malicious" functionality that is only
 * loaded at runtime through dynamic loading. Static analysis tools
 * like angr's CFGFast won't see these functions because:
 *
 * 1. The library is loaded via dlopen() at runtime
 * 2. The library name is computed/obfuscated
 * 3. Function pointers are resolved via dlsym()
 *
 * DynPathResolver should be able to resolve these paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported functions that will be called via dlsym */

__attribute__((visibility("default")))
void secret_init(void) {
    printf("[libsecret] Initialization complete\n");
}

__attribute__((visibility("default")))
int secret_compute(int a, int b) {
    /* This is the "hidden" computation that static analysis misses */
    printf("[libsecret] Computing secret value...\n");
    return (a ^ b) + 0xDEAD;
}

__attribute__((visibility("default")))
void secret_exfiltrate(const char *data) {
    /* Simulated data exfiltration - this is what we want to detect */
    printf("[libsecret] EXFILTRATING: %s\n", data);
}

__attribute__((visibility("default")))
void secret_cleanup(void) {
    printf("[libsecret] Cleanup complete\n");
}

/* Hidden vtable for C++ style polymorphism simulation */
typedef struct {
    void (*init)(void);
    int (*compute)(int, int);
    void (*exfil)(const char*);
    void (*cleanup)(void);
} SecretVtable;

__attribute__((visibility("default")))
SecretVtable* get_vtable(void) {
    static SecretVtable vtable = {
        .init = secret_init,
        .compute = secret_compute,
        .exfil = secret_exfiltrate,
        .cleanup = secret_cleanup
    };
    return &vtable;
}
