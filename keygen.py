#!/usr/bin/env python3
"""
IEC104MS License Key Generator for Motorola ACE3600 RTU (PowerPC).

Generates license keys for the ace104ms.plz driver (IEC 60870-5-104 protocol).
Based on reverse-engineered algorithm from decompiled ELF binary (40.c).

The license key is a 128-bit hash (custom TEA-based CBC-MAC) of:
    CPU_ID + LICENSE_TYPE + padding ('*')

Usage:
    python keygen.py <CPU_ID> [<CPU_ID> ...]

    CPU_ID is the 10-character serial number printed on the CPU module
    (e.g. "085SLW00TV"). The key for all 3 license modes will be printed.

License types:
    IEC104MASTER  - Master mode only
    IEC104SLAVE_  - Slave mode only
    IEC104PEER__  - Master & Slave mode

The output can be placed in file "iec104lk.29" on the RTU:
    IEC104License = <32-char-hex-key>

Driver version: 4.2 (Apr 28 2017)
"""

import struct
import sys


DELTA = 0x61C88647
MASK32 = 0xFFFFFFFF

LICENSE_TYPES = {
    "Master":       "IEC104MASTER",
    "Slave":        "IEC104SLAVE_",
    "Master+Slave": "IEC104PEER__",
}

VERSION_MAJOR = 4
VERSION_MINOR = 2


def tea_hash128(data: bytes) -> tuple:
    """Hash_128 — custom TEA-based 128-bit hash (CBC-MAC mode).
    Input must be > 15 bytes and aligned to 8-byte boundary.
    Returns 4 x uint32.
    """
    assert len(data) > 15 and len(data) % 8 == 0

    blocks = []
    for i in range(0, len(data), 4):
        blocks.append(struct.unpack('>I', data[i:i + 4])[0])

    v21 = v22 = v23 = v24 = 0
    num_blocks = len(data) // 8

    for b in range(num_blocks):
        w0 = blocks[b * 2]
        w1 = blocks[b * 2 + 1]

        # Phase 1: TEA-encipher (v23, v24) with key (v21, v22, w0, w1)
        v13, v14 = v23, v24
        s = 0
        for _ in range(32):
            s = (s - DELTA) & MASK32
            v13 = (v13 + ((((v14 * 16) + v21) ^ (v14 + s) ^ ((v14 >> 5) + v22)) & MASK32)) & MASK32
            v14 = (v14 + ((((v13 * 16) + w0) ^ (v13 + s) ^ ((v13 >> 5) + w1)) & MASK32)) & MASK32
        v23 ^= v13
        v24 ^= v14

        # Phase 2: TEA-encipher (v21, v22) with key (w0, w1, v13, v14)
        v19, v20 = v21, v22
        s = 0
        for _ in range(32):
            s = (s - DELTA) & MASK32
            v19 = (v19 + ((((v20 * 16) + w0) ^ (v20 + s) ^ ((v20 >> 5) + w1)) & MASK32)) & MASK32
            v20 = (v20 + ((((v19 * 16) + v13) ^ (v19 + s) ^ ((v19 >> 5) + v14)) & MASK32)) & MASK32
        v21 ^= v19
        v22 ^= v20

    return (v21, v22, v23, v24)


def _build_buffer(cpu_id: str, license_label: str) -> bytes:
    """Build the 40-byte buffer exactly as key_check() does in the C code."""
    cpu_bytes = cpu_id.encode('ascii')
    label_bytes = license_label.encode('ascii')

    buf = bytearray(41)
    buf[:len(cpu_bytes)] = cpu_bytes
    buf[len(cpu_bytes):len(cpu_bytes) + len(label_bytes)] = label_bytes

    out = bytearray(40)
    for i in range(40):
        out[i] = buf[i] if buf[i] != 0 else 0x2A
    return bytes(out)


def generate(cpu_id: str, license_type: str,
             version_major: int = VERSION_MAJOR,
             version_minor: int = VERSION_MINOR) -> str:
    label = f"{license_type}{version_major}.{version_minor}"
    buf = _build_buffer(cpu_id, label)
    h = tea_hash128(buf)
    return ''.join(f'{x:08X}' for x in h)


def generate_all(cpu_id: str) -> dict:
    return {name: generate(cpu_id, lt) for name, lt in LICENSE_TYPES.items()}


def print_license_file(cpu_id: str, keys: dict):
    print(f"; CPU ID: {cpu_id}")
    print(f"; Driver version {VERSION_MAJOR}.{VERSION_MINOR}")
    print()
    for mode, key in keys.items():
        print(f"IEC104License = {key}    ; {mode} mode")
    print()


def main():
    cpu_ids = sys.argv[1:] if len(sys.argv) > 1 else None

    if cpu_ids:
        for cpu in cpu_ids:
            keys = generate_all(cpu)
            print_license_file(cpu, keys)
    else:
        # Verify against known samples
        samples = [
            ("085SLW00TV", "IEC104SLAVE_4.2", "955077A59242195C93669F441CF661DC"),
            ("085SLW008C", "IEC104SLAVE_4.2", "7F271B10C9E8D0783AA79A4386F88410"),
            ("085SLW01R9", "IEC104SLAVE_4.2", "D036D17FCCF7FA9B71EF9672469024CE"),
            ("085SMY016N", "IEC104SLAVE_4.2", "358B9899860C63A71941D14E5FEAC4AA"),
            ("085SLW0078", "IEC104SLAVE_4.2", "99FD9E91F8E07FFEA6CA5E86E7888C4C"),
            ("085SLW008B", "IEC104SLAVE_4.2", "ACA855F3225A0D2553D34D109F63D3CB"),
        ]
        for cpu, label, expected in samples:
            buf = _build_buffer(cpu, label)
            h = tea_hash128(buf)
            key = ''.join(f'{x:08X}' for x in h)
            ok = "OK" if key == expected else "FAIL"
            print(f"[{ok}] CPU={cpu}  {key}")
        print(f"\nUsage: python {sys.argv[0]} <CPU_ID> [<CPU_ID> ...]")


if __name__ == "__main__":
    main()
