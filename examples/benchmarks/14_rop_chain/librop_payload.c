/**
 * Payload library for benchmark 14: ROP Chain
 *
 * This library is loaded as the final action of the ROP chain.
 */

#include <stdio.h>

__attribute__((visibility("default")))
void rop_payload(void) {
    printf("[PAYLOAD] ROP payload executed!\n");
    printf("[PAYLOAD] The ROP chain successfully loaded and called this function.\n");
}

__attribute__((visibility("default")))
void secondary_payload(void) {
    printf("[PAYLOAD] Secondary payload executed!\n");
}
