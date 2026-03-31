/**
 * Payload library for benchmark 16: Signal Handler
 *
 * This library is loaded from within a signal handler.
 */

#include <stdio.h>

__attribute__((visibility("default")))
void signal_payload(void) {
    printf("[PAYLOAD] Signal payload executed!\n");
    printf("[PAYLOAD] This library was loaded inside a signal handler.\n");
}

__attribute__((visibility("default")))
int signal_compute(int x) {
    printf("[PAYLOAD] signal_compute called with %d\n", x);
    return x * 2;
}
