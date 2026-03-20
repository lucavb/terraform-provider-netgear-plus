#!/usr/bin/env python3
"""
Netgear GS108Ev3 Login Lockout Remover
Firmware: GS108Ev3_V2.06.24EN (v2.06.24)

Tested only against GS108Ev3 firmware matching the checks below.
No responsibility is accepted for bricked devices, failed flashes, or any
other damage. Use entirely at your own risk.

Patches two JZ (jump-if-zero) instructions to SJMP (unconditional short jump)
in the 8051 login handler, disabling the "maximum attempts reached" and
"account temporarily locked" lockout paths.

Also recalculates the UMHD checksum field in the firmware header so the
switch bootloader accepts the modified image.

Patch details:
  Offset 0x8BE7: 0x60 (JZ) -> 0x80 (SJMP)  — skips "max attempts reached"
  Offset 0x8C94: 0x60 (JZ) -> 0x80 (SJMP)  — skips "account temporarily locked"

Checksum algorithm (reverse-engineered from EN/GR/JP firmware variants):
  The UMHD checksum is the sum of all 16-bit big-endian words across the
  entire firmware image — with the block count field (0x12-0x15) and the
  checksum field (0x1E-0x21) zeroed to binary 0x00 — plus the fixed seed
  0x60AB, taken modulo 65535 (2^16 - 1, i.e. Fletcher-style).

  The result is written as 4 uppercase ASCII hex characters at 0x1E-0x21.

Usage: python3 patch_lockout.py [input.bin] [output.bin]
"""

import hashlib
import sys
from pathlib import Path

FIRMWARE_NAME = "GS108Ev3_V2.06.24EN.bin"
EXPECTED_SIZE = 720896

PATCHES = [
    (0x8BE7, 0x60, 0x80, "lockout path 1: max attempts reached"),
    (0x8C94, 0x60, 0x80, "lockout path 2: account temporarily locked"),
]

# Context bytes around each patch site for validation.
# Surrounding 8051 instructions confirm we're in the correct function,
# not patching a coincidental 0x60 byte elsewhere in the binary.
CONTEXT_CHECKS = [
    # 0x8BDF: 54 01 = ANL A,#0x01 (mask lockout bit 0 before the JZ we patch)
    (0x8BDF, bytes.fromhex("5401")),
    # 0x8BE9: 90 = MOV DPTR (instruction after the JZ branch target)
    (0x8BE9, bytes.fromhex("90")),
    # 0x8C8C: 54 02 = ANL A,#0x02 (mask lockout bit 1 before the second JZ)
    (0x8C8C, bytes.fromhex("5402")),
    # 0x8C96: 90 = MOV DPTR (instruction after the second JZ branch target)
    (0x8C96, bytes.fromhex("90")),
]

HEADER_CHECK = (0x22, b"GS108Ev3")

# UMHD header structure (embedded in 8051 code space between interrupt vectors):
#   0x0E-0x11: "UMHD"          magic
#   0x12-0x15: block count      ASCII hex, e.g. "000B" = 11 blocks
#   0x16-0x1D: reserved         ASCII zeros "00000000"
#   0x1E-0x21: checksum         ASCII hex, 16-bit value
#   0x22-0x29: model            "GS108Ev3"
UMHD_CHECKSUM_OFFSET = 0x1E
UMHD_CHECKSUM_LEN = 4
UMHD_BLOCK_COUNT_OFFSET = 0x12
UMHD_BLOCK_COUNT_LEN = 4

# Fixed seed added to the word sum before taking mod 65535.
# Empirically constant across EN, GR, and JP firmware variants.
CHECKSUM_SEED = 0x60AB


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_umhd_checksum(data: bytes) -> int:
    raw = data[UMHD_CHECKSUM_OFFSET : UMHD_CHECKSUM_OFFSET + UMHD_CHECKSUM_LEN]
    return int(raw.decode("ascii"), 16)


def write_umhd_checksum(data: bytearray, value: int) -> None:
    ascii_hex = f"{value & 0xFFFF:04X}".encode("ascii")
    data[UMHD_CHECKSUM_OFFSET : UMHD_CHECKSUM_OFFSET + UMHD_CHECKSUM_LEN] = ascii_hex


def compute_umhd_checksum(data: bytes) -> int:
    """Sum all 16-bit big-endian words (block count and checksum fields zeroed)
    plus seed 0x60AB, mod 65535."""
    buf = bytearray(data)
    buf[UMHD_BLOCK_COUNT_OFFSET : UMHD_BLOCK_COUNT_OFFSET + UMHD_BLOCK_COUNT_LEN] = (
        b"\x00" * UMHD_BLOCK_COUNT_LEN
    )
    buf[UMHD_CHECKSUM_OFFSET : UMHD_CHECKSUM_OFFSET + UMHD_CHECKSUM_LEN] = (
        b"\x00" * UMHD_CHECKSUM_LEN
    )
    word_sum = 0
    for i in range(0, len(buf) - 1, 2):
        word_sum += (buf[i] << 8) | buf[i + 1]
    return (word_sum + CHECKSUM_SEED) % 65535


def validate_firmware(data: bytes) -> list[str]:
    errors = []

    if len(data) != EXPECTED_SIZE:
        errors.append(
            f"File size is {len(data)} bytes, expected {EXPECTED_SIZE} "
            f"(0x{EXPECTED_SIZE:X})"
        )
        return errors

    offset, expected = HEADER_CHECK
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        errors.append(
            f"Header at 0x{offset:04X}: expected {expected!r}, "
            f"got {actual!r} — this may not be GS108Ev3 firmware"
        )

    for ctx_offset, ctx_bytes in CONTEXT_CHECKS:
        actual = data[ctx_offset : ctx_offset + len(ctx_bytes)]
        if actual != ctx_bytes:
            errors.append(
                f"Context mismatch at 0x{ctx_offset:04X}: "
                f"expected {ctx_bytes.hex()}, got {actual.hex()} — "
                f"firmware structure differs from expected"
            )

    try:
        read_umhd_checksum(data)
    except (ValueError, UnicodeDecodeError):
        errors.append(
            f"UMHD checksum at 0x{UMHD_CHECKSUM_OFFSET:04X} is not valid ASCII hex"
        )

    for offset, expected_byte, _, desc in PATCHES:
        actual_byte = data[offset]
        if actual_byte == expected_byte:
            pass
        elif actual_byte == 0x80:
            errors.append(f"Offset 0x{offset:04X} ({desc}): already patched (0x80)")
        else:
            errors.append(
                f"Offset 0x{offset:04X} ({desc}): unexpected byte "
                f"0x{actual_byte:02X} (expected 0x{expected_byte:02X})"
            )

    return errors


def apply_patches(data: bytearray) -> int:
    changed = 0
    for offset, _, new_byte, desc in PATCHES:
        if data[offset] != new_byte:
            data[offset] = new_byte
            changed += 1
            print(f"  ✓ 0x{offset:04X}: 0x60 → 0x80  ({desc})")
        else:
            print(f"  – 0x{offset:04X}: already 0x80  ({desc})")
    return changed


def update_checksum(data: bytearray, original_data: bytes) -> None:
    old_cksum = read_umhd_checksum(original_data)
    new_cksum = compute_umhd_checksum(bytes(data))
    write_umhd_checksum(data, new_cksum)
    print(f"  ✓ UMHD checksum: 0x{old_cksum:04X} → 0x{new_cksum:04X}")


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(FIRMWARE_NAME)
    output_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else input_path.with_stem(input_path.stem + "_patched")
    )

    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {input_path} ...")
    data = input_path.read_bytes()
    print(f"  Size: {len(data)} bytes (0x{len(data):X})")
    print(f"  SHA-256: {sha256(data)}")

    print("\nValidating firmware ...")
    errors = validate_firmware(data)

    if errors:
        print("\n✗ Validation failed:\n")
        for err in errors:
            print(f"  • {err}")

        if all("already patched" in e for e in errors):
            print("\nFirmware is already patched. Nothing to do.")
            sys.exit(0)

        print("\nAborting. No changes written.", file=sys.stderr)
        sys.exit(1)

    print("  ✓ File size correct")
    print("  ✓ GS108Ev3 header found")
    print("  ✓ Instruction context matches (correct function boundaries)")
    print("  ✓ UMHD checksum field is valid")
    print("  ✓ Patch sites contain expected original bytes")

    print("\nApplying patches ...")
    patched = bytearray(data)
    changed = apply_patches(patched)

    if changed == 0:
        print("\nNo changes needed.")
        sys.exit(0)

    print("\nUpdating checksum ...")
    update_checksum(patched, data)

    output_path.write_bytes(bytes(patched))
    print(f"\nWritten to {output_path}")
    print(f"  Size: {len(patched)} bytes (unchanged)")
    print(f"  SHA-256: {sha256(bytes(patched))}")
    print(f"  Bytes changed: {changed + UMHD_CHECKSUM_LEN}")
    print("\nDone. Login lockout disabled. Flash this file to your GS108Ev3 at your own risk.")


if __name__ == "__main__":
    main()
