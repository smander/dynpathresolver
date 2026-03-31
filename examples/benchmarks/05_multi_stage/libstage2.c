/**
 * Stage 2 library - final payload
 */

#include <stdio.h>

__attribute__((visibility("default")))
void final_payload(void) {
    printf("[STAGE2] FINAL PAYLOAD EXECUTED!\n");
    printf("[STAGE2] This function was invisible to static analysis\n");
}

__attribute__((visibility("default")))
void stage2_helper(void) {
    printf("[STAGE2] Helper function\n");
}

__attribute__((visibility("default")))
int stage2_compute(int x) {
    return x * x;
}
