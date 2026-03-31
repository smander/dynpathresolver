/*
 * libplugin.c - Plugin library loaded based on configuration
 *
 * This demonstrates plugin-based architecture where the loaded
 * functionality depends on runtime configuration or user input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Plugin interface */
typedef struct Plugin {
    char name[64];
    int (*process)(const char* input, char* output, size_t out_size);
    void (*destroy)(struct Plugin* self);
} Plugin;

/* Plugin implementation */
static int plugin_process(const char* input, char* output, size_t out_size) {
    printf("[plugin] Processing input: %s\n", input);

    /* Transform input - this logic is hidden from static analysis */
    size_t len = strlen(input);
    if (len >= out_size) len = out_size - 1;

    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ 0x42;  /* Simple XOR "encryption" */
    }
    output[len] = '\0';

    printf("[plugin] Output generated\n");
    return 0;
}

static void plugin_destroy(Plugin* self) {
    printf("[plugin] Destroying plugin: %s\n", self->name);
    free(self);
}

/* Factory function - called via dlsym */
__attribute__((visibility("default")))
Plugin* create_plugin(const char* config) {
    printf("[plugin] Creating plugin with config: %s\n", config);

    Plugin* p = malloc(sizeof(Plugin));
    if (!p) return NULL;

    strncpy(p->name, "XORPlugin", sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
    p->process = plugin_process;
    p->destroy = plugin_destroy;

    return p;
}

/* Alternative entry point for different configurations */
__attribute__((visibility("default")))
Plugin* create_advanced_plugin(const char* config, int flags) {
    printf("[plugin] Creating advanced plugin with flags: 0x%x\n", flags);

    Plugin* p = create_plugin(config);
    if (p && (flags & 0x1)) {
        strncpy(p->name, "AdvancedXORPlugin", sizeof(p->name) - 1);
    }

    return p;
}
