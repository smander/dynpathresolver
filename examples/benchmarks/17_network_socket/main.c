/**
 * Benchmark 17: Network Socket Library Loading
 *
 * Library path is received via network socket:
 * 1. Create a TCP socket and connect to 127.0.0.1:4444
 * 2. recv() the library path from the socket
 * 3. dlopen() the received path
 * 4. recv() the symbol name and dlsym() it
 *
 * Static analysis cannot determine the library name since it comes
 * from the network. DynPathResolver uses network_payloads to provide
 * the recv() data during symbolic execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    printf("Benchmark 17: Network Socket Library Loading\n");
    printf("=============================================\n\n");

    // Create TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    printf("[MAIN] Socket created: fd=%d\n", sockfd);

    // Connect to server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }
    printf("[MAIN] Connected to 127.0.0.1:4444\n");

    // Receive library path from server
    char lib_path[256];
    memset(lib_path, 0, sizeof(lib_path));
    ssize_t n = recv(sockfd, lib_path, sizeof(lib_path) - 1, 0);
    if (n <= 0) {
        printf("[MAIN] recv failed\n");
        close(sockfd);
        return 1;
    }
    printf("[MAIN] Received library path: %s\n", lib_path);

    // Load the library
    void* handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        printf("[MAIN] dlopen failed: %s\n", dlerror());
        close(sockfd);
        return 1;
    }
    printf("[MAIN] Library loaded successfully\n");

    // Receive symbol name from server
    char sym_name[256];
    memset(sym_name, 0, sizeof(sym_name));
    n = recv(sockfd, sym_name, sizeof(sym_name) - 1, 0);
    if (n <= 0) {
        printf("[MAIN] recv for symbol failed\n");
        dlclose(handle);
        close(sockfd);
        return 1;
    }
    printf("[MAIN] Received symbol name: %s\n", sym_name);

    // Look up and call the function
    typedef int (*plugin_func)(void);
    plugin_func func = (plugin_func)dlsym(handle, sym_name);
    if (func) {
        int result = func();
        printf("[MAIN] %s() returned: 0x%x\n", sym_name, result);
    } else {
        printf("[MAIN] dlsym failed: %s\n", dlerror());
    }

    dlclose(handle);
    close(sockfd);
    printf("[MAIN] Done.\n");

    return 0;
}
