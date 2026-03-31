#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char b64_table[256] = {
    [A]=0,  [B]=1,  [C]=2,  [D]=3,  [E]=4,  [F]=5,  [G]=6,  [H]=7,
    [I]=8,  [J]=9,  [K]=10, [L]=11, [M]=12, [N]=13, [O]=14, [P]=15,
    [Q]=16, [R]=17, [S]=18, [T]=19, [U]=20, [V]=21, [W]=22, [X]=23,
    [Y]=24, [Z]=25, [a]=26, [b]=27, [c]=28, [d]=29, [e]=30, [f]=31,
    [g]=32, [h]=33, [i]=34, [j]=35, [k]=36, [l]=37, [m]=38, [n]=39,
    [o]=40, [p]=41, [q]=42, [r]=43, [s]=44, [t]=45, [u]=46, [v]=47,
    [w]=48, [x]=49, [y]=50, [z]=51, [0]=52, [1]=53, [2]=54, [3]=55,
    [4]=56, [5]=57, [6]=58, [7]=59, [8]=60, [9]=61, [+]=62, [/]=63
};

static size_t base64_decode(const char* in, unsigned char* out) {
    size_t len = strlen(in);
    size_t out_len = 0;

    for (size_t i = 0; i < len; i += 4) {
        unsigned int val = 0;
        int pad = 0;

        for (int j = 0; j < 4 && i + j < len; j++) {
            char c = in[i + j];
            if (c == =) {
                pad++;
                continue;
            }
            val = (val << 6) | b64_table[(unsigned char)c];
        }

        if (pad < 2) out[out_len++] = (val >> 16) & 0xFF;
        if (pad < 1) out[out_len++] = (val >> 8) & 0xFF;
        out[out_len++] = val & 0xFF;
    }

    return out_len - (len > 0 ? (in[len-1] == = ? (in[len-2] == = ? 2 : 1) : 0) : 0);
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

int main() {
    const char* encoded_lib = "LTFsKzYuNy8gKy5tbA==";
    unsigned char decoded[64];
    memset(decoded, 0, sizeof(decoded));
    
    size_t decoded_len = base64_decode(encoded_lib, decoded);
    printf("After base64 decode: %zu bytes: ", decoded_len);
    for (size_t i = 0; i < decoded_len; i++) printf("%02x ", decoded[i]);
    printf("\n");
    
    xor_decode(decoded, decoded_len, 0x42);
    printf("After XOR decode: \"%s\" (len=%zu)\n", decoded, decoded_len);
    
    reverse_string((char*)decoded, decoded_len);
    printf("After reverse: \"%s\"\n", decoded);
    
    return 0;
}
