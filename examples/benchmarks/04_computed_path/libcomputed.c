/**
 * Computed library for benchmark 04
 */

#include <stdio.h>

__attribute__((visibility("default")))
int compute_result(int a, int b) {
    printf("[COMPUTED] Computing %d + %d\n", a, b);
    return a + b;
}

__attribute__((visibility("default")))
int compute_product(int a, int b) {
    return a * b;
}

__attribute__((visibility("default")))
int compute_difference(int a, int b) {
    return a - b;
}
