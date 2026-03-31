/**
 * Alternative payload library for benchmark 16
 *
 * Loaded via SIGUSR2 handler (using signal() instead of sigaction()).
 */

#include <stdio.h>

__attribute__((visibility("default")))
void alt_payload(void) {
    printf("[ALT_PAYLOAD] Alt payload executed!\n");
}
