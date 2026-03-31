/**
 * anti_analysis.h - Anti-debugging and anti-analysis techniques
 *
 * Multiple layers of detection to prevent:
 * - Debugger attachment
 * - Timing-based emulation detection
 * - VM/Sandbox detection
 * - Code tampering detection
 */

#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Detection result codes */
#define CLEAN           0
#define DEBUGGER        1
#define TIMING_ANOMALY  2
#define VM_DETECTED     3
#define SANDBOX         4
#define TAMPERED        5

/* Timing threshold in nanoseconds (adjust based on target) */
#define TIMING_THRESHOLD_NS 100000000  /* 100ms */

/* Expected code checksum - will be patched at build time */
static volatile uint32_t expected_checksum = 0x00000000;

/**
 * Check if process is being traced via ptrace.
 */
static int check_ptrace(void) {
#ifdef __linux__
    /* Try to trace ourselves - fails if already being traced */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return DEBUGGER;
    }
    /* Detach from ourselves */
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
#endif
    return CLEAN;
}

/**
 * Check /proc/self/status for TracerPid.
 */
static int check_tracer_pid(void) {
#ifdef __linux__
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return CLEAN;  /* Can't check, assume clean */

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            if (tracer_pid != 0) {
                return DEBUGGER;
            }
            return CLEAN;
        }
    }
    fclose(f);
#endif
    return CLEAN;
}

/**
 * Timing check - detect emulation/debugging via execution speed.
 */
static int check_timing(void) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Do some predictable computation */
    volatile uint32_t x = 0;
    for (int i = 0; i < 100000; i++) {
        x = x * 1103515245 + 12345;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

    if (elapsed_ns > TIMING_THRESHOLD_NS) {
        return TIMING_ANOMALY;
    }

    return CLEAN;
}

/**
 * Check environment variables for VM/sandbox indicators.
 */
static int check_environment(void) {
    const char* suspicious_vars[] = {
        "QEMU",
        "VMWARE",
        "VBOX",
        "SANDBOX",
        "ANALYSIS",
        "MALWARE",
        NULL
    };

    for (int i = 0; suspicious_vars[i] != NULL; i++) {
        /* Check if any env var contains the suspicious string */
        extern char** environ;
        for (char** env = environ; *env != NULL; env++) {
            if (strstr(*env, suspicious_vars[i]) != NULL) {
                return VM_DETECTED;
            }
        }
    }

    return CLEAN;
}

/**
 * Check /proc/cpuinfo for hypervisor flag.
 */
static int check_cpuinfo(void) {
#ifdef __linux__
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return CLEAN;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "hypervisor") != NULL) {
            fclose(f);
            return VM_DETECTED;
        }
    }
    fclose(f);
#endif
    return CLEAN;
}

/**
 * Check /proc/self/maps for analysis tool signatures.
 */
static int check_loaded_libraries(void) {
#ifdef __linux__
    const char* analysis_tools[] = {
        "frida",
        "pin",
        "dynamorio",
        "valgrind",
        "vgpreload",
        NULL
    };

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return CLEAN;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; analysis_tools[i] != NULL; i++) {
            if (strstr(line, analysis_tools[i]) != NULL) {
                fclose(f);
                return SANDBOX;
            }
        }
    }
    fclose(f);
#endif
    return CLEAN;
}

/**
 * Compute checksum of code section to detect tampering.
 */
static uint32_t compute_code_checksum(void* start, size_t len) {
    uint8_t* ptr = (uint8_t*)start;
    uint32_t checksum = 0;

    for (size_t i = 0; i < len; i++) {
        checksum = ((checksum << 5) | (checksum >> 27)) ^ ptr[i];
    }

    return checksum;
}

/**
 * Verify code hasn't been patched.
 * Note: expected_checksum must be set at build time or runtime init.
 */
static int check_code_integrity(void* code_start, size_t code_len) {
    if (expected_checksum == 0) {
        /* Not initialized, skip check */
        return CLEAN;
    }

    uint32_t actual = compute_code_checksum(code_start, code_len);
    if (actual != expected_checksum) {
        return TAMPERED;
    }

    return CLEAN;
}

/**
 * Run all anti-analysis checks.
 * Returns CLEAN (0) if all pass, or specific detection code.
 */
static int run_all_checks(void) {
    int result;

    /* Check 1: ptrace detection */
    result = check_ptrace();
    if (result != CLEAN) return result;

    /* Check 2: TracerPid */
    result = check_tracer_pid();
    if (result != CLEAN) return result;

    /* Check 3: Timing anomaly */
    result = check_timing();
    if (result != CLEAN) return result;

    /* Check 4: Environment variables */
    result = check_environment();
    if (result != CLEAN) return result;

    /* Check 5: Hypervisor detection */
    result = check_cpuinfo();
    if (result != CLEAN) return result;

    /* Check 6: Analysis tools in memory maps */
    result = check_loaded_libraries();
    if (result != CLEAN) return result;

    return CLEAN;
}

/**
 * Get human-readable description of detection result.
 */
static const char* detection_to_string(int code) {
    switch (code) {
        case CLEAN:          return "Clean";
        case DEBUGGER:       return "Debugger detected";
        case TIMING_ANOMALY: return "Timing anomaly (emulation?)";
        case VM_DETECTED:    return "Virtual machine detected";
        case SANDBOX:        return "Sandbox/analysis tool detected";
        case TAMPERED:       return "Code tampering detected";
        default:             return "Unknown";
    }
}

#endif /* ANTI_ANALYSIS_H */
