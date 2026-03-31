/*
 * loader.c - Complex Dynamic Loader
 *
 * This program demonstrates several techniques that defeat static analysis:
 *
 * 1. COMPUTED LIBRARY NAMES
 *    - Library names are constructed at runtime from pieces
 *    - XOR decryption of library path
 *
 * 2. CONDITIONAL LOADING
 *    - Different libraries loaded based on runtime conditions
 *    - Environment variable checks
 *    - Command-line argument parsing
 *
 * 3. INDIRECT FUNCTION CALLS
 *    - All loaded functions called through function pointers
 *    - Vtable-style dispatch
 *
 * 4. OBFUSCATED SYMBOL NAMES
 *    - dlsym lookups with computed strings
 *
 * Static analysis (CFGFast) will miss:
 * - All functions in dynamically loaded libraries
 * - Control flow through function pointers
 * - The conditional loading paths
 *
 * DynPathResolver should catch:
 * - The dlopen calls and load the libraries
 * - The indirect calls through resolved function pointers
 * - The vtable-style dispatch
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

/* XOR key for "decrypting" library names */
#define XOR_KEY 0x5A

/* Encrypted library name: "libsecret.so" XOR'd with 0x5A */
static unsigned char encrypted_lib[] = {
    0x36, 0x33, 0x38, 0x29, 0x3f, 0x39, 0x28, 0x3f,
    0x2e, 0x74, 0x29, 0x35, 0x00
};

/* Function pointer types */
typedef void (*init_fn)(void);
typedef int (*compute_fn)(int, int);
typedef void (*exfil_fn)(const char*);
typedef void (*cleanup_fn)(void);

/* Vtable structure */
typedef struct {
    void (*init)(void);
    int (*compute)(int, int);
    void (*exfil)(const char*);
    void (*cleanup)(void);
} Vtable;

typedef Vtable* (*get_vtable_fn)(void);

/* Plugin interface */
typedef struct Plugin {
    char name[64];
    int (*process)(const char*, char*, size_t);
    void (*destroy)(struct Plugin*);
} Plugin;

typedef Plugin* (*create_plugin_fn)(const char*);

/* Decrypt library name at runtime */
static char* decrypt_libname(unsigned char* encrypted, size_t len) {
    char* decrypted = malloc(len + 1);
    if (!decrypted) return NULL;

    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ XOR_KEY;
    }
    decrypted[len] = '\0';

    return decrypted;
}

/* Build library path dynamically */
static char* build_lib_path(const char* base, const char* name) {
    size_t len = strlen(base) + strlen(name) + 2;
    char* path = malloc(len);
    if (!path) return NULL;

    snprintf(path, len, "%s/%s", base, name);
    return path;
}

/* Compute symbol name from parts (defeats static string analysis) */
static char* build_symbol_name(const char* prefix, const char* suffix) {
    size_t len = strlen(prefix) + strlen(suffix) + 1;
    char* name = malloc(len);
    if (!name) return NULL;

    strcpy(name, prefix);
    strcat(name, suffix);
    return name;
}

/* Mode 1: Direct function pointer loading */
static int run_direct_mode(void* handle) {
    printf("[loader] Running in DIRECT mode\n");

    /* Build symbol names at runtime */
    char* init_name = build_symbol_name("secret", "_init");
    char* compute_name = build_symbol_name("secret", "_compute");
    char* exfil_name = build_symbol_name("secret", "_exfiltrate");
    char* cleanup_name = build_symbol_name("secret", "_cleanup");

    /* Resolve functions - static analysis can't see these targets */
    init_fn init = (init_fn)dlsym(handle, init_name);
    compute_fn compute = (compute_fn)dlsym(handle, compute_name);
    exfil_fn exfil = (exfil_fn)dlsym(handle, exfil_name);
    cleanup_fn cleanup = (cleanup_fn)dlsym(handle, cleanup_name);

    free(init_name);
    free(compute_name);
    free(exfil_name);
    free(cleanup_name);

    if (!init || !compute || !exfil || !cleanup) {
        fprintf(stderr, "[loader] Failed to resolve symbols\n");
        return -1;
    }

    /* Call through function pointers - indirect calls */
    init();

    int result = compute(0x1337, 0xBEEF);
    printf("[loader] Computation result: 0x%x\n", result);

    char secret_data[64];
    snprintf(secret_data, sizeof(secret_data), "SECRET_%d", result);
    exfil(secret_data);

    cleanup();

    return 0;
}

/* Mode 2: Vtable-style dispatch */
static int run_vtable_mode(void* handle) {
    printf("[loader] Running in VTABLE mode\n");

    /* Get vtable via dlsym */
    get_vtable_fn get_vtable = (get_vtable_fn)dlsym(handle, "get_vtable");
    if (!get_vtable) {
        fprintf(stderr, "[loader] Failed to get vtable function\n");
        return -1;
    }

    /* Get vtable pointer */
    Vtable* vtable = get_vtable();
    if (!vtable) {
        fprintf(stderr, "[loader] Failed to get vtable\n");
        return -1;
    }

    /* Dispatch through vtable - mimics C++ virtual calls */
    vtable->init();

    int result = vtable->compute(0xCAFE, 0xBABE);
    printf("[loader] Vtable computation result: 0x%x\n", result);

    vtable->exfil("vtable_secret_data");
    vtable->cleanup();

    return 0;
}

/* Mode 3: Plugin loading based on config */
static int run_plugin_mode(const char* lib_dir) {
    printf("[loader] Running in PLUGIN mode\n");

    /* Build plugin library path */
    char* plugin_path = build_lib_path(lib_dir, "libplugin.so");
    if (!plugin_path) return -1;

    printf("[loader] Loading plugin from: %s\n", plugin_path);

    void* plugin_handle = dlopen(plugin_path, RTLD_NOW);
    free(plugin_path);

    if (!plugin_handle) {
        fprintf(stderr, "[loader] Failed to load plugin: %s\n", dlerror());
        return -1;
    }

    /* Get factory function */
    create_plugin_fn create = (create_plugin_fn)dlsym(plugin_handle, "create_plugin");
    if (!create) {
        fprintf(stderr, "[loader] Failed to get create_plugin\n");
        dlclose(plugin_handle);
        return -1;
    }

    /* Create plugin instance */
    Plugin* plugin = create("default_config");
    if (!plugin) {
        fprintf(stderr, "[loader] Failed to create plugin\n");
        dlclose(plugin_handle);
        return -1;
    }

    /* Use plugin - all through function pointers */
    char output[256];
    plugin->process("Hello, DynPathResolver!", output, sizeof(output));
    printf("[loader] Plugin output (hex): ");
    for (size_t i = 0; i < strlen(output); i++) {
        printf("%02x ", (unsigned char)output[i]);
    }
    printf("\n");

    /* Cleanup */
    plugin->destroy(plugin);
    dlclose(plugin_handle);

    return 0;
}

/* Conditional branch based on computed value */
static int compute_mode(int argc, char** argv) {
    int mode = 0;

    /* Mode selection based on multiple factors */
    if (argc > 1) {
        /* Command line argument */
        mode = atoi(argv[1]);
    } else if (getenv("LOADER_MODE")) {
        /* Environment variable */
        mode = atoi(getenv("LOADER_MODE"));
    } else {
        /* Compute based on PID (unpredictable) */
        mode = getpid() % 3;
    }

    return mode;
}

int main(int argc, char** argv) {
    printf("=== Complex Dynamic Loader Demo ===\n\n");

    /* Get library directory from environment or use current dir */
    const char* lib_dir = getenv("LIB_DIR");
    if (!lib_dir) {
        lib_dir = ".";
    }

    /* Decrypt the secret library name */
    char* secret_lib = decrypt_libname(encrypted_lib, sizeof(encrypted_lib) - 1);
    if (!secret_lib) {
        fprintf(stderr, "[loader] Failed to decrypt library name\n");
        return 1;
    }

    printf("[loader] Decrypted library: %s\n", secret_lib);

    /* Build full path */
    char* lib_path = build_lib_path(lib_dir, secret_lib);
    free(secret_lib);

    if (!lib_path) {
        fprintf(stderr, "[loader] Failed to build library path\n");
        return 1;
    }

    printf("[loader] Loading library: %s\n", lib_path);

    /* Load the secret library */
    void* handle = dlopen(lib_path, RTLD_NOW);
    free(lib_path);

    if (!handle) {
        fprintf(stderr, "[loader] Failed to load library: %s\n", dlerror());
        return 1;
    }

    /* Determine execution mode */
    int mode = compute_mode(argc, argv);
    printf("[loader] Selected mode: %d\n\n", mode);

    int result = 0;

    switch (mode) {
        case 0:
            result = run_direct_mode(handle);
            break;
        case 1:
            result = run_vtable_mode(handle);
            break;
        case 2:
            result = run_plugin_mode(lib_dir);
            break;
        default:
            printf("[loader] Unknown mode, running all modes\n\n");
            result = run_direct_mode(handle);
            if (result == 0) result = run_vtable_mode(handle);
            if (result == 0) result = run_plugin_mode(lib_dir);
            break;
    }

    dlclose(handle);

    printf("\n=== Loader Complete (result: %d) ===\n", result);
    return result;
}
