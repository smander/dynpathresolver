/**
 * Benchmark 09: Fileless loading via memfd_create
 *
 * Library is loaded from memory without touching the filesystem.
 * Uses memfd_create to create anonymous file descriptor.
 * Common technique for fileless malware.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <fcntl.h>

// Platform-specific memfd support
#ifdef __linux__
#include <sys/syscall.h>
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
static int memfd_create_wrapper(const char* name, unsigned int flags) {
#ifdef __NR_memfd_create
    return syscall(__NR_memfd_create, name, flags);
#else
    return syscall(319, name, flags);  // x86_64 syscall number
#endif
}
#else
// macOS fallback - use shm_open with unlink
#define MFD_CLOEXEC 0
static int memfd_create_wrapper(const char* name, unsigned int flags) {
    char shm_name[64];
    snprintf(shm_name, sizeof(shm_name), "/memfd_%d", getpid());
    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        shm_unlink(shm_name);  // Unlink immediately for "anonymous" behavior
    }
    return fd;
}
#endif

// Embedded minimal ELF shared library (libmemfd.so compiled and embedded)
// This would normally be fetched from network or decrypted from data section
// For testing, we read from a real file and pretend it's embedded
static unsigned char* load_embedded_library(size_t* size) {
    FILE* f = fopen("./libmemfd_payload.so", "rb");
    if (!f) {
        fprintf(stderr, "Could not read embedded payload\n");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* data = malloc(*size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    fread(data, 1, *size, f);
    fclose(f);
    return data;
}

int main(int argc, char* argv[]) {
    printf("Benchmark 09: Fileless loading via memfd_create\n");

    // Load "embedded" library data
    size_t lib_size = 0;
    unsigned char* lib_data = load_embedded_library(&lib_size);
    if (!lib_data) {
        fprintf(stderr, "Failed to load embedded library\n");
        return 1;
    }

    printf("Loaded %zu bytes of embedded library\n", lib_size);

    // Create anonymous memory-backed file
    int fd = memfd_create_wrapper("", MFD_CLOEXEC);
    if (fd == -1) {
        perror("memfd_create");
        free(lib_data);
        return 1;
    }

    printf("Created memfd with fd=%d\n", fd);

    // Write library to memfd
    if (write(fd, lib_data, lib_size) != (ssize_t)lib_size) {
        perror("write");
        close(fd);
        free(lib_data);
        return 1;
    }

    free(lib_data);

    // Build path to memfd: /proc/self/fd/N
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);

    printf("Loading from: %s\n", fdpath);

    // dlopen from the memfd path
    void* handle = dlopen(fdpath, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        close(fd);
        return 1;
    }

    typedef void (*func_t)(void);
    func_t func = (func_t)dlsym(handle, "memfd_payload");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        close(fd);
        return 1;
    }

    func();

    dlclose(handle);
    close(fd);
    return 0;
}
