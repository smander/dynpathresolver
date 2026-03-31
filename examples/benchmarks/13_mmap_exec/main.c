/**
 * Benchmark 13: mmap with PROT_EXEC
 *
 * Library is loaded using:
 * 1. open() to get file descriptor
 * 2. mmap() with PROT_READ | PROT_EXEC to map code
 * 3. Direct function call into mapped memory
 *
 * This bypasses dlopen but is detectable via mmap+PROT_EXEC correlation.
 * Simpler than benchmark 12 (manual ELF) but still evades dlopen hooks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifdef __linux__
#include <elf.h>
#else
// Minimal ELF definitions for 64-bit
#define ELFMAG "\177ELF"
#define SELFMAG 4
#define PT_LOAD 1

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr;
    uint64_t p_filesz, p_memsz, p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} Elf64_Sym;

#define SHT_DYNSYM 11
#endif

/**
 * Simple mmap-based library loader.
 * Opens file, maps it with executable permissions, finds symbol.
 */
static void* simple_mmap_load(const char* path, const char* symbol_name) {
    // Step 1: Open the library file
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }

    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    // Step 2: mmap with PROT_READ | PROT_EXEC
    // This is the key detection point - executable mmap of a file
    void* mapped = mmap(NULL, st.st_size,
                        PROT_READ | PROT_EXEC,  // Executable mapping!
                        MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    printf("Mapped library at: %p (size: %ld)\n", mapped, st.st_size);
    close(fd);

    // Step 3: Parse ELF to find the symbol
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)mapped;

    // Verify ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        munmap(mapped, st.st_size);
        return NULL;
    }

    // Find section headers
    Elf64_Shdr* shdrs = (Elf64_Shdr*)((char*)mapped + ehdr->e_shoff);
    char* shstrtab = (char*)mapped + shdrs[ehdr->e_shstrndx].sh_offset;

    // Find .dynsym and .dynstr
    Elf64_Sym* dynsym = NULL;
    char* dynstr = NULL;
    size_t dynsym_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr* shdr = &shdrs[i];
        const char* name = shstrtab + shdr->sh_name;

        if (shdr->sh_type == SHT_DYNSYM) {
            dynsym = (Elf64_Sym*)((char*)mapped + shdr->sh_offset);
            dynsym_size = shdr->sh_size;
            // Get linked string table
            Elf64_Shdr* strtab_shdr = &shdrs[shdr->sh_link];
            dynstr = (char*)mapped + strtab_shdr->sh_offset;
        }
    }

    if (!dynsym || !dynstr) {
        fprintf(stderr, "Could not find symbol table\n");
        munmap(mapped, st.st_size);
        return NULL;
    }

    // Search for the symbol
    size_t num_syms = dynsym_size / sizeof(Elf64_Sym);
    for (size_t i = 0; i < num_syms; i++) {
        Elf64_Sym* sym = &dynsym[i];
        if (sym->st_name == 0) continue;

        const char* sym_name = dynstr + sym->st_name;
        if (strcmp(sym_name, symbol_name) == 0) {
            // Found it! Return address in mapped region
            void* func_addr = (char*)mapped + sym->st_value;
            printf("Found symbol '%s' at: %p\n", symbol_name, func_addr);
            return func_addr;
        }
    }

    fprintf(stderr, "Symbol '%s' not found\n", symbol_name);
    munmap(mapped, st.st_size);
    return NULL;
}

int main(int argc, char* argv[]) {
    printf("Benchmark 13: mmap with PROT_EXEC\n");

    // Load library via mmap - NO dlopen call
    const char* lib_path = "./libmmap_payload.so";
    const char* symbol_name = "mmap_function";

    printf("Loading via mmap: %s\n", lib_path);

    typedef void (*func_t)(void);
    func_t func = (func_t)simple_mmap_load(lib_path, symbol_name);

    if (!func) {
        fprintf(stderr, "Failed to load library\n");
        return 1;
    }

    // Call the function
    printf("Calling function...\n");
    func();

    printf("Done.\n");
    return 0;
}
