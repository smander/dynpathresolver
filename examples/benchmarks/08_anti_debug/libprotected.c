/**
 * Protected payload library (loaded only if no debugger)
 */

#include <stdio.h>

__attribute__((visibility("default")))
void protected_function(void) {
    printf("[LIBPROTECTED] Anti-debug protected payload executed!\n");
}
