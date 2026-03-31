/**
 * Network plugin library for benchmark 17.
 * Provides a simple exported function that would be loaded
 * after receiving the library path over a network socket.
 */

#include <stdio.h>

__attribute__((visibility("default")))
int net_process(void) {
    printf("[PLUGIN] net_process called\n");
    return 0x42;
}
