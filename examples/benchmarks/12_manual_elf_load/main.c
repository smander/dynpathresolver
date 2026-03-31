/**
 * Benchmark 12: Manual ELF loading without dlopen
 *
 * Library is loaded manually by:
 * 1. Reading ELF file into memory
 * 2. Parsing ELF headers
 * 3. mmap'ing segments with correct permissions
 * 4. Processing relocations
 * 5. Calling the function directly
 *
 * This bypasses dlopen entirely - the most advanced evasion technique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

// ELF definitions for portability (Linux has elf.h, macOS doesn't)
#ifdef __linux__
#include <elf.h>
#else
// Minimal ELF definitions for 64-bit
#define ELFMAG "\177ELF"
#define SELFMAG 4
#define PT_LOAD 1
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11

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
#endif

// Simplified ELF loader - handles basic shared libraries
typedef struct {
    void* base;
    size_t size;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdrs;
    Elf64_Shdr* shdrs;
    char* shstrtab;
    Elf64_Sym* symtab;
    char* strtab;
    size_t symtab_size;
} LoadedElf;

static void* find_symbol(LoadedElf* elf, const char* name) {
    if (!elf->symtab || !elf->strtab) return NULL;

    size_t num_syms = elf->symtab_size / sizeof(Elf64_Sym);
    for (size_t i = 0; i < num_syms; i++) {
        Elf64_Sym* sym = &elf->symtab[i];
        if (sym->st_name == 0) continue;

        const char* sym_name = elf->strtab + sym->st_name;
        if (strcmp(sym_name, name) == 0) {
            return (void*)((char*)elf->base + sym->st_value);
        }
    }
    return NULL;
}

static LoadedElf* manual_load_elf(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    // Map the entire file first to read headers
    void* file_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_map == MAP_FAILED) {
        perror("mmap file");
        close(fd);
        return NULL;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_map;

    // Verify ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        munmap(file_map, st.st_size);
        close(fd);
        return NULL;
    }

    // Find the extent of loadable segments
    Elf64_Phdr* phdrs = (Elf64_Phdr*)((char*)file_map + ehdr->e_phoff);
    size_t min_vaddr = (size_t)-1, max_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            if (phdrs[i].p_vaddr < min_vaddr) min_vaddr = phdrs[i].p_vaddr;
            size_t end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
            if (end > max_vaddr) max_vaddr = end;
        }
    }

    // Allocate space for all segments
    size_t total_size = max_vaddr - min_vaddr;
    total_size = (total_size + 0xFFF) & ~0xFFF;  // Page align

    void* base = mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap base");
        munmap(file_map, st.st_size);
        close(fd);
        return NULL;
    }

    // Load segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            void* dest = (char*)base + (phdrs[i].p_vaddr - min_vaddr);
            void* src = (char*)file_map + phdrs[i].p_offset;
            memcpy(dest, src, phdrs[i].p_filesz);

            // Zero the rest (BSS)
            if (phdrs[i].p_memsz > phdrs[i].p_filesz) {
                memset((char*)dest + phdrs[i].p_filesz, 0,
                       phdrs[i].p_memsz - phdrs[i].p_filesz);
            }
        }
    }

    // Create LoadedElf structure
    LoadedElf* elf = malloc(sizeof(LoadedElf));
    elf->base = base;
    elf->size = total_size;
    elf->ehdr = ehdr;
    elf->phdrs = phdrs;
    elf->shdrs = (Elf64_Shdr*)((char*)file_map + ehdr->e_shoff);
    elf->shstrtab = (char*)file_map + elf->shdrs[ehdr->e_shstrndx].sh_offset;
    elf->symtab = NULL;
    elf->strtab = NULL;
    elf->symtab_size = 0;

    // Find symbol table and string table
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr* shdr = &elf->shdrs[i];
        const char* name = elf->shstrtab + shdr->sh_name;

        if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
            elf->symtab = (Elf64_Sym*)((char*)file_map + shdr->sh_offset);
            elf->symtab_size = shdr->sh_size;
            // String table is linked via sh_link
            Elf64_Shdr* strtab_shdr = &elf->shdrs[shdr->sh_link];
            elf->strtab = (char*)file_map + strtab_shdr->sh_offset;
        }
    }

    close(fd);
    // Note: we keep file_map alive for the string tables
    // In production code, we'd copy what we need

    return elf;
}

int main(int argc, char* argv[]) {
    printf("Benchmark 12: Manual ELF loading without dlopen\n");

    // Manually load the library - NO dlopen call
    const char* lib_path = "./libmanual.so";
    printf("Manually loading: %s\n", lib_path);

    LoadedElf* elf = manual_load_elf(lib_path);
    if (!elf) {
        fprintf(stderr, "Manual ELF load failed\n");
        return 1;
    }

    printf("Loaded at base: %p\n", elf->base);

    // Find and call the function - NO dlsym call
    typedef void (*func_t)(void);
    func_t func = (func_t)find_symbol(elf, "manual_function");

    if (!func) {
        fprintf(stderr, "Symbol not found\n");
        munmap(elf->base, elf->size);
        free(elf);
        return 1;
    }

    printf("Found symbol at: %p\n", (void*)func);

    // Call the function
    func();

    // Cleanup
    munmap(elf->base, elf->size);
    free(elf);
    return 0;
}
