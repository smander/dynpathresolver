/**
 * Benchmark 11: Multi-layer encoding
 *
 * Library name is encoded with multiple layers:
 * 1. Base64 encoded
 * 2. XOR with key
 * 3. Reversed
 *
 * Each layer must be decoded in order to reveal the library name.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// Base64 decoding table
static const unsigned char b64_table[256] = {
    ['A']=0,  ['B']=1,  ['C']=2,  ['D']=3,  ['E']=4,  ['F']=5,  ['G']=6,  ['H']=7,
    ['I']=8,  ['J']=9,  ['K']=10, ['L']=11, ['M']=12, ['N']=13, ['O']=14, ['P']=15,
    ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25, ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39,
    ['o']=40, ['p']=41, ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47,
    ['w']=48, ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53, ['2']=54, ['3']=55,
    ['4']=56, ['5']=57, ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']=62, ['/']=63
};

static size_t base64_decode(const char* in, unsigned char* out) {
    size_t len = strlen(in);
    size_t out_len = 0;

    for (size_t i = 0; i < len; i += 4) {
        unsigned int val = 0;
        int valid_chars = 0;

        for (int j = 0; j < 4 && i + j < len; j++) {
            char c = in[i + j];
            if (c == '=') {
                // Padding - shift in zeros
                val <<= 6;
            } else {
                val = (val << 6) | b64_table[(unsigned char)c];
                valid_chars++;
            }
        }

        // Output bytes based on how many valid chars we had
        out[out_len++] = (val >> 16) & 0xFF;
        if (valid_chars > 2) out[out_len++] = (val >> 8) & 0xFF;
        if (valid_chars > 3) out[out_len++] = val & 0xFF;
    }

    return out_len;
}

static void xor_decode(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

static void reverse_string(char* str, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        char tmp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = tmp;
    }
}

// Encoded "./libmulti.so":
// 1. Original: "./libmulti.so"
// 2. Reversed: "os.itlumbil/."
// 3. XOR 0x42: encoded bytes
// 4. Base64: final string
//
// Let me compute this properly:
// "./libmulti.so" reversed = "os.itlumbil/."
// XOR each byte with 0x42:
//   'o'^0x42 = 0x2d, 's'^0x42 = 0x31, '.'^0x42 = 0x6c, ...
// Then base64 encode the result

// Pre-computed encoded string (reverse -> XOR 0x42 -> base64)
// "./libmulti.so" -> reverse -> XOR 0x42 -> base64
static const char* encoded_lib = "LTFsKzYuNy8gKy5tbA==";
#define XOR_KEY 0x42

int main(int argc, char* argv[]) {
    printf("Benchmark 11: Multi-layer encoding\n");

    // Layer 1: Base64 decode
    unsigned char decoded[64];
    memset(decoded, 0, sizeof(decoded));
    size_t decoded_len = base64_decode(encoded_lib, decoded);

    printf("After base64 decode: %zu bytes\n", decoded_len);

    // Layer 2: XOR decode
    xor_decode(decoded, decoded_len, XOR_KEY);

    printf("After XOR decode: %s\n", decoded);

    // Layer 3: Reverse
    reverse_string((char*)decoded, decoded_len);

    printf("After reverse: %s\n", decoded);

    // Now we have the library name
    void* handle = dlopen((char*)decoded, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    typedef void (*func_t)(void);
    func_t func = (func_t)dlsym(handle, "multi_function");
    if (!func) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    func();
    dlclose(handle);
    return 0;
}
