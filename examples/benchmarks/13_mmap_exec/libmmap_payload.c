/**
 * Payload library for benchmark 13: mmap with PROT_EXEC
 *
 * Simple library with an exported function that will be called
 * after being loaded via mmap.
 */

#include <stdio.h>

__attribute__((visibility("default")))
void mmap_function(void) {
    printf("[PAYLOAD] mmap_function executed successfully!\n");
    printf("[PAYLOAD] This library was loaded via mmap, not dlopen.\n");
}

// Additional exported function for testing
__attribute__((visibility("default")))
int mmap_compute(int a, int b) {
    printf("[PAYLOAD] mmap_compute called with %d, %d\n", a, b);
    return a + b;
}
