/**
 * libpayload.c - Hidden payload library
 *
 * This library is NEVER referenced in the main binary.
 * It is loaded dynamically based on:
 * 1. Encrypted library name from UDP packet
 * 2. Runtime-derived path construction
 *
 * The symbol "execute_payload" is also received via TCP,
 * making it completely invisible to static analysis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* Hidden initialization - called by execute_payload */
static int initialized = 0;
static char session_id[64];

/**
 * Generate a unique session ID for this execution.
 */
static void init_session(void) {
    if (initialized) return;

    snprintf(session_id, sizeof(session_id),
             "SESSION-%d-%ld", getpid(), time(NULL));
    initialized = 1;
}

/**
 * Primary payload function - received via TCP dlsym.
 * This function name is NEVER in the main binary.
 */
__attribute__((visibility("default")))
int execute_payload(void) {
    init_session();

    printf("[PAYLOAD] execute_payload() called!\n");
    printf("[PAYLOAD] Session ID: %s\n", session_id);
    printf("[PAYLOAD] PID: %d\n", getpid());

    /* Simulate some "malicious" activity */
    printf("[PAYLOAD] Gathering system information...\n");

    /* Return success code */
    return 0x1337;
}

/**
 * Alternative entry point - also hidden.
 */
__attribute__((visibility("default")))
int payload_init(int mode) {
    init_session();

    printf("[PAYLOAD] payload_init(mode=%d) called!\n", mode);

    switch (mode) {
        case 0:
            printf("[PAYLOAD] Mode 0: Reconnaissance\n");
            break;
        case 1:
            printf("[PAYLOAD] Mode 1: Data collection\n");
            break;
        case 2:
            printf("[PAYLOAD] Mode 2: Exfiltration\n");
            break;
        default:
            printf("[PAYLOAD] Mode %d: Unknown\n", mode);
            break;
    }

    return mode;
}

/**
 * Data exfiltration function.
 */
__attribute__((visibility("default")))
int exfiltrate_data(const char* data, size_t len) {
    init_session();

    printf("[PAYLOAD] exfiltrate_data() called with %zu bytes\n", len);
    printf("[PAYLOAD] Data preview: %.32s...\n", data);

    /* In real malware, this would send data to C2 */
    return (int)len;
}

/**
 * Cleanup function.
 */
__attribute__((visibility("default")))
void payload_cleanup(void) {
    printf("[PAYLOAD] payload_cleanup() called\n");
    printf("[PAYLOAD] Cleaning up session: %s\n", session_id);

    /* Clear sensitive data */
    memset(session_id, 0, sizeof(session_id));
    initialized = 0;
}

/**
 * Hidden function - requires specific knowledge to call.
 */
__attribute__((visibility("default")))
int hidden_backdoor(const char* key) {
    /* Simple key check */
    if (key && strcmp(key, "s3cr3t_k3y_2024") == 0) {
        printf("[PAYLOAD] BACKDOOR ACTIVATED!\n");
        return 0xDEAD;
    }
    return -1;
}
