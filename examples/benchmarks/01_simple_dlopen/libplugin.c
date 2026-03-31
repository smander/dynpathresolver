/**
 * Simple plugin library for benchmark 01
 */

#include <stdio.h>

__attribute__((visibility("default")))
int plugin_process(int value) {
    printf("[PLUGIN] Processing value: %d\n", value);
    return value * 2;
}

__attribute__((visibility("default")))
int plugin_init(void) {
    printf("[PLUGIN] Initialized\n");
    return 0;
}

__attribute__((visibility("default")))
void plugin_cleanup(void) {
    printf("[PLUGIN] Cleanup\n");
}
