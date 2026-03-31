/**
 * Hidden library for benchmark 03
 */

#include <stdio.h>

__attribute__((visibility("default")))
void hidden_function(void) {
    printf("[HIDDEN] Secret function executed!\n");
}

__attribute__((visibility("default")))
int hidden_compute(int a, int b) {
    return a * b + 42;
}

__attribute__((visibility("default")))
void hidden_backdoor(void) {
    printf("[HIDDEN] BACKDOOR ACTIVATED\n");
}
