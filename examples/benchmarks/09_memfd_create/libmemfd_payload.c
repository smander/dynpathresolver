/**
 * Payload library for memfd_create benchmark
 * This gets loaded from memory without touching filesystem
 */

#include <stdio.h>

__attribute__((visibility("default")))
void memfd_payload(void) {
    printf("[LIBMEMFD] Fileless payload executed from memory!\n");
}
