/**
 * Benchmark 08: Anti-debugging checks
 *
 * Library is only loaded if no debugger is attached.
 * Uses ptrace self-attach technique common in malware.
 * Analyzer must handle or bypass anti-debug checks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <unistd.h>

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif
#ifndef PTRACE_DETACH
#define PTRACE_DETACH 17
#endif

static int detect_debugger(void) {
    // Classic ptrace anti-debug: if we can't trace ourselves, debugger is attached
#ifdef __APPLE__
    // macOS ptrace has different signature: int ptrace(int, pid_t, caddr_t, int)
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
        return 1;  // Debugger detected
    }
    // Detach from ourselves
    ptrace(PTRACE_DETACH, getpid(), NULL, 0);
#else
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;  // Debugger detected
    }
    // Detach from ourselves
    ptrace(PTRACE_DETACH, getpid(), NULL, NULL);
#endif
    return 0;
}

static int check_proc_status(void) {
    // Check /proc/self/status for TracerPid
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0;  // Non-zero TracerPid means debugger
        }
    }
    fclose(f);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("Benchmark 08: Anti-debugging checks\n");

    // Multiple anti-debug checks
    printf("Checking for debugger...\n");

    if (detect_debugger()) {
        printf("Debugger detected via ptrace! Exiting.\n");
        return 1;
    }

    if (check_proc_status()) {
        printf("Debugger detected via /proc/self/status! Exiting.\n");
        return 1;
    }

    printf("No debugger detected, loading payload...\n");

    void* handle = dlopen("./libprotected.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    typedef void (*func_t)(void);
    func_t func = (func_t)dlsym(handle, "protected_function");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    func();
    dlclose(handle);
    return 0;
}
