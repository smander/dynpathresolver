/**
 * Stage 1 library - loads stage 2
 */

#include <stdio.h>
#include <dlfcn.h>

static void* stage2_handle = NULL;

__attribute__((visibility("default")))
void* load_next_stage(void) {
    printf("[STAGE1] Loading next stage...\n");

    // Stage 1 loads stage 2
    stage2_handle = dlopen("./libstage2.so", RTLD_NOW);
    if (!stage2_handle) {
        printf("[STAGE1] Failed to load stage2: %s\n", dlerror());
        return NULL;
    }

    printf("[STAGE1] Stage 2 loaded successfully\n");
    return stage2_handle;
}

__attribute__((visibility("default")))
void stage1_function(void) {
    printf("[STAGE1] Stage 1 function called\n");
}
