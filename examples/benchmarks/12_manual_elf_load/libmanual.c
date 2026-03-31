/**
 * Library for manual ELF load benchmark
 * This library is loaded via manual ELF parsing, not dlopen
 */

#include <stdio.h>

__attribute__((visibility("default")))
void manual_function(void) {
    printf("[LIBMANUAL] Loaded via manual ELF parsing - no dlopen!\n");
}
