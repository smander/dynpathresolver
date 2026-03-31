/**
 * Library for indirect call benchmark
 */

#include <stdio.h>

__attribute__((visibility("default")))
void indirect_function(void) {
    printf("[LIBINDIRECT] Called via function pointer!\n");
}
