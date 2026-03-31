/**
 * Plugin library for benchmark 02
 */

#include <stdio.h>
#include <string.h>

__attribute__((visibility("default")))
int process_data(const char* data) {
    printf("[PLUGIN] Processing: %s\n", data);
    return (int)strlen(data);
}

__attribute__((visibility("default")))
int validate_input(const char* data) {
    return data != NULL && strlen(data) > 0;
}
