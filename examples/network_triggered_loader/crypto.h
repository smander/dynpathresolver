/**
 * crypto.h - Cryptographic primitives for obfuscation
 *
 * All crypto operations use runtime-derived keys.
 * No keys are stored in the binary.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* CRC32 lookup table - computed at runtime to avoid static signatures */
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void init_crc32_table(void) {
    if (crc32_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t compute_crc32(const uint8_t* data, size_t len) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/**
 * Derive encryption key from multiple runtime sources.
 * Key is NEVER stored - always computed fresh.
 */
static uint32_t derive_key(uint32_t seed) {
    uint32_t pid = (uint32_t)getpid();

    /* Use minute-resolution time for time-window validity */
    uint32_t time_component = (uint32_t)(time(NULL) / 60);

    /* Mix all components */
    uint32_t key = seed ^ pid ^ time_component;

    /* Additional mixing rounds */
    key = ((key << 13) | (key >> 19)) ^ 0xCAFEBABE;
    key = ((key << 7) | (key >> 25)) ^ 0xDEADBEEF;
    key = ((key << 17) | (key >> 15)) ^ 0x13371337;

    return key;
}

/**
 * XOR encryption/decryption with key stream.
 * Same function for encrypt and decrypt.
 */
static void xor_crypt(const uint8_t* input, uint8_t* output,
                      size_t len, uint32_t key) {
    uint32_t state = key;

    for (size_t i = 0; i < len; i++) {
        /* Simple PRNG for key stream */
        state = state * 1103515245 + 12345;
        uint8_t key_byte = (state >> 16) & 0xFF;
        output[i] = input[i] ^ key_byte;
    }
}

/**
 * Encrypt data with IV for TCP packets.
 * IV is prepended to ensure different ciphertext each time.
 */
static void xor_crypt_with_iv(const uint8_t* input, uint8_t* output,
                              size_t len, const uint8_t* iv, size_t iv_len) {
    /* Derive key from IV */
    uint32_t key = 0;
    for (size_t i = 0; i < iv_len && i < 4; i++) {
        key |= ((uint32_t)iv[i]) << (i * 8);
    }
    key = derive_key(key);

    xor_crypt(input, output, len, key);
}

/**
 * Simple checksum for packet verification.
 */
static uint32_t compute_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = ((sum << 5) | (sum >> 27)) + data[i];
    }
    return sum;
}

#endif /* CRYPTO_H */
