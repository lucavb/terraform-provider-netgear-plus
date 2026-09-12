#!/usr/bin/env python3
"""
Netgear GS108Ev3 Login Lockout Remover
Firmware: GS108Ev3_V2.06.24EN (v2.06.24)

Tested only against GS108Ev3 firmware matching the checks below.
No responsibility is accepted for bricked devices, failed flashes, or any
other damage. Use entirely at your own risk.

Lockout mechanism (reverse engineered from the 8051 image, v2.06.24GR):
  The web session keeps a "credit" counter (initialized to 20) in XDATA
  0xAAD6:0xAAD7 (managed by the bank-1 orchestrator, file offsets
  0x1CB40-0x1CD30). When credits reach 0 the switch serves the locked page
  and ignores further requests until a 0x1F000-tick timeout expires.

  Three bank-0 request handlers feed that counter with per-request deficits:
    0x95FA  per-request cost walk (GET accounting)
    0x9826  login-page GET handler
    0x9A48  login SUBMIT handler
  Each walks the 20-slot auth-module table at XDATA 0x99D9 (11-byte entries,
  registered via 0xB0E8), calls HandleLoginRequest (0x8A63) per entry with
  the accumulated cost, and on a NEGATIVE result decrements a 32-bit deficit
  counter (0xA6CB in 95FA, 0xA5D1 in 9826) with an identical 16-byte
  SUBB-chain idiom. The deficit is returned to the orchestrator, which ADDS
  it to the credits - every decrement drains one credit. HLR itself has
  three flags-gated JZ sites, and both 95FA/9826 have early-exit paths that
  return -1 (also a one-credit drain).

  Patch strategy (all sites in bank 0; EN file offset = GR code addr - 0x11):
    sites 1-3   HLR flag gates: JZ -> SJMP so control always follows the
                skip; the auth/lockout failure handling is never executed
                (auth re-check never fails)
    sites 4,6   early-exit -1 returns -> return 0 instead (no credit drain)
    sites 5,7,8 NOP the 16-byte 32-bit deficit SUBB chains: load/store stay,
                the value never decrements (deficit stays 0 forever)
    site 9      NOP the 3-byte submit-failure flag store (0xA699 = 1)

  Everything else (state normalization, page rendering, entry-table walk,
  session handling) is left untouched, so the web UI keeps working.

  The generic HTTP rate-limit helpers (thresholds 25/45) are deliberately
  NOT patched; they are shared timing infrastructure. Keep client-side
  request spacing (see README request_spacing=5).

  Provenance: only the two-gate patch (sites 1-2) has been flashed to and
  run on real hardware. Sites 3-9 are reverse-engineering only; the 9-site
  output has never been flashed. There is no documented recovery mode for
  this hardware - a failed flash likely bricks the switch.

  Security note: this removes the login lockout and the per-request
  CHECK_AUTH re-validation, so failed password attempts are no longer cut
  off by the lockout (a generic request-rate limiter remains, hence the
  request-spacing advice). Keep the management interface on a trusted
  network.

Also recalculates the UMHD checksum field in the firmware header so the
switch bootloader accepts the modified image.

Checksum algorithm (reverse-engineered from EN/GR/JP firmware variants):
  The UMHD checksum is the sum of all 16-bit big-endian words across the
  entire firmware image — with the block count field (0x12-0x15) and the
  checksum field (0x1E-0x21) zeroed to binary 0x00 — plus the fixed seed
  0x60AB, taken modulo 65535 (2^16 - 1, i.e. Fletcher-style).

  The result is written as 4 uppercase ASCII hex characters at 0x1E-0x21.

Patch sites (EN offsets; GR address = offset + 0x11):
  0x8BE7  60 -> 80              HLR gate 1 (flags bit0 lockout branch)
  0x8C94  60 -> 80              HLR gate 2 (CHECK_AUTH re-validation)
  0x8D71  60 -> 80              HLR gate 3 (flags bit0 final gate)
  0x963E  74 FF -> 74 00         95FA early-exit returns 0, not -1
  0x96D8  16-byte SUBB -> NOPs   95FA deficit decrement (negative HLR)
  0x9883  74 FF -> 74 00         9826 early-exit returns 0, not -1
  0x9972  16-byte SUBB -> NOPs   9826 deficit decrement (negative HLR)
  0x9A1A  16-byte SUBB -> NOPs   9826 deficit decrement (auth check)
  0x9BC8  74 01 F0 -> NOPs      9A48 submit-failure flag store

Usage: python3 patch_lockout.py [input.bin] [output.bin]
  Re-running on an output of this script (or of the older 2-site version)
  resumes: sites still in original state are patched, the checksum is
  recomputed, and a fully patched image is reported as complete.
"""

import hashlib
import sys
from pathlib import Path

FIRMWARE_NAME = "GS108Ev3_V2.06.24EN.bin"
EXPECTED_SIZE = 720896

# Identity pins for the one image this script was validated against: the
# pristine (unpatched) GS108Ev3 v2.06.24EN firmware. An input may deviate
# from it ONLY at the 9 patch sites and the checksum field (everything this
# script family writes); any other deviation is refused.
EXPECTED_SHA256 = (
    "bb18df9c001e04229c90d8736775bc20977a028a12369495c4e0e085f071c365"
)
PRISTINE_CHECKSUM_FIELD = b"9C6B"  # checksum field of the unpatched image

# (offset, original bytes, patched bytes, description)
# Offsets are EN file offsets; the GR firmware has the same code at +0x11.
PATCHES = [
    (0x8BE7, bytes.fromhex("60"), bytes.fromhex("80"),
     "HLR gate 1: flags bit0 JZ -> SJMP (lockout branch never taken)"),
    (0x8C94, bytes.fromhex("60"), bytes.fromhex("80"),
     "HLR gate 2: CHECK_AUTH JZ -> SJMP (auth re-check never fails)"),
    (0x8D71, bytes.fromhex("60"), bytes.fromhex("80"),
     "HLR gate 3: flags bit0 JZ -> SJMP (final gate never taken)"),
    (0x963E, bytes.fromhex("74ff"), bytes.fromhex("7400"),
     "95FA early-exit: return 0 instead of -1"),
    (0x96D8, bytes.fromhex("ef9401ffee9400feed9400fdec9400fc"), b"\x00" * 16,
     "95FA: NOP deficit decrement (32-bit SUBB chain on 0xA6CB)"),
    (0x9883, bytes.fromhex("74ff"), bytes.fromhex("7400"),
     "9826 early-exit: return 0 instead of -1"),
    (0x9972, bytes.fromhex("ef9401ffee9400feed9400fdec9400fc"), b"\x00" * 16,
     "9826: NOP deficit decrement (32-bit SUBB chain on 0xA5D1)"),
    (0x9A1A, bytes.fromhex("ef9401ffee9400feed9400fdec9400fc"), b"\x00" * 16,
     "9826: NOP deficit decrement after auth-check (SUBB chain on 0xA5D1)"),
    (0x9BC8, bytes.fromhex("7401f0"), b"\x00" * 3,
     "9A48: NOP submit-failure flag store (0xA699 = 1)"),
]

# Context bytes around each patch site for validation.
# Surrounding 8051 instructions confirm we're in the correct function,
# not patching a coincidental byte sequence elsewhere in the binary.
CONTEXT_CHECKS = [
    # --- HLR (0x8A63) gates: ANL mask before each JZ, MOV DPTR after ---
    (0x8BDF, bytes.fromhex("5401")),    # ANL A,#0x01 (mask flags bit0, gate 1)
    (0x8BE9, bytes.fromhex("90")),     # MOV DPTR (branch target of gate 1)
    (0x8C8C, bytes.fromhex("5402")),    # ANL A,#0x02 (mask flags bit1, gate 2)
    (0x8C96, bytes.fromhex("90")),     # MOV DPTR (branch target of gate 2)
    (0x8D73, bytes.fromhex("9099d6")),  # MOV DPTR,#0x99D6 (after gate 3 JZ)
    # --- 95FA (request-cost walk) ---
    (0x963C, bytes.fromhex("5007")),    # JNC over the early-exit -1 return
    (0x96D3, bytes.fromhex("a3120a9ac3")),  # INC DPTR; LCALL 0x0A9A; CLR CY (deficit load)
    # --- 9826 (login-page GET handler) ---
    (0x9881, bytes.fromhex("5007")),    # JNC over the early-exit -1 return
    (0x996D, bytes.fromhex("a3120a9ac3")),  # INC DPTR; LCALL 0x0A9A; CLR CY (deficit load)
    (0x9A13, bytes.fromhex("90a5d1120a9ac3")),  # MOV DPTR,#0xA5D1; LCALL 0x0A9A; CLR CY
    # --- 9A48 (login SUBMIT handler) ---
    (0x9BC5, bytes.fromhex("90a699")),  # MOV DPTR,#0xA699 (failure flag)
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


def validate_firmware(data: bytes) -> tuple[list[str], dict[str, int]]:
    """Validate the input image.

    Returns (errors, stats):
      errors — structural problems; non-empty means abort, nothing is written.
      stats  — per-site state counts: how many patch sites are "original",
               "patched", or "unexpected". A partially patched input is NOT
               an error; the remaining sites get patched on the run.
    """
    errors: list[str] = []
    stats = {"original": 0, "patched": 0, "unexpected": 0}

    if len(data) != EXPECTED_SIZE:
        errors.append(
            f"File size is {len(data)} bytes, expected {EXPECTED_SIZE} "
            f"(0x{EXPECTED_SIZE:X})"
        )
        return errors, stats

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
        stored = read_umhd_checksum(data)
    except (ValueError, UnicodeDecodeError):
        errors.append(
            f"UMHD checksum at 0x{UMHD_CHECKSUM_OFFSET:04X} is not valid ASCII hex"
        )
    else:
        # Whole-file integrity: the stored checksum must match the content.
        # Catches corrupted downloads and hand edits that the byte-exact
        # site checks (which pin only a small region) cannot see.
        if compute_umhd_checksum(data) != stored:
            errors.append(
                "UMHD checksum mismatch: stored value does not match the "
                "computed checksum — file is corrupted or was modified "
                "after its checksum was written"
            )

    for offset, orig, patched, desc in PATCHES:
        actual = data[offset : offset + len(orig)]
        if actual == orig:
            stats["original"] += 1
        elif actual == patched:
            stats["patched"] += 1
        else:
            stats["unexpected"] += 1
            errors.append(
                f"Offset 0x{offset:04X} ({desc}): unexpected bytes "
                f"{actual.hex()} (expected {orig.hex()})"
            )

    # Identity pin: revert the sanctioned regions (the 9 patch sites and the
    # checksum field) and require the result to be the pristine validated
    # image. This accepts this script family's own outputs (fully or
    # partially patched) while refusing any other deviation — wrong firmware
    # version, corruption elsewhere in the image, or a foreign image.
    restored = bytearray(data)
    for offset, orig, _patched, _desc in PATCHES:
        restored[offset : offset + len(orig)] = orig
    restored[UMHD_CHECKSUM_OFFSET : UMHD_CHECKSUM_OFFSET + UMHD_CHECKSUM_LEN] = (
        PRISTINE_CHECKSUM_FIELD
    )
    if sha256(bytes(restored)) != EXPECTED_SHA256:
        errors.append(
            "Image identity check failed: reverting the patch sites does not "
            f"yield the validated pristine v2.06.24EN image "
            f"(got SHA-256 {sha256(bytes(restored))}) — wrong firmware "
            "version, corruption, or modified image"
        )

    return errors, stats


def apply_patches(data: bytearray) -> None:
    for offset, orig, patched, desc in PATCHES:
        if data[offset : offset + len(patched)] == patched:
            print(f"  – 0x{offset:04X}: already patched  ({desc})")
            continue
        print(
            f"  ✓ 0x{offset:04X}: {orig.hex()} → {patched.hex()}  ({desc})"
        )
        data[offset : offset + len(patched)] = patched


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

    if input_path.resolve() == output_path.resolve():
        print(
            "Error: output path must differ from input (the only copy would "
            "be overwritten). Pass an explicit output path.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not input_path.is_file():
        print(f"Error: {input_path} is not a regular file", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {input_path} ...")
    data = input_path.read_bytes()
    print(f"  Size: {len(data)} bytes (0x{len(data):X})")
    print(f"  SHA-256: {sha256(data)}")

    print("\nValidating firmware ...")
    errors, stats = validate_firmware(data)

    if errors:
        print("\n✗ Validation failed:\n")
        for err in errors:
            print(f"  • {err}")
        print("\nAborting. No changes written.", file=sys.stderr)
        sys.exit(1)

    total = len(PATCHES)
    print("  ✓ File size correct")
    print("  ✓ GS108Ev3 header found")
    print("  ✓ Instruction context matches (correct function boundaries)")
    print("  ✓ UMHD checksum round-trips (field matches content)")
    print("  ✓ Image identity pinned to validated v2.06.24EN")
    print(
        f"  ✓ Patch sites: {stats['original']} original, "
        f"{stats['patched']} already patched"
    )

    if stats["patched"] == total:
        print(
            f"\nFirmware is already fully patched ({total}/{total} sites). "
            "Nothing to do."
        )
        sys.exit(0)

    if stats["patched"]:
        print(
            f"\nResuming partially patched image: {stats['patched']}/{total} "
            "sites already patched."
        )
    print("\nApplying patches ...")
    patched = bytearray(data)
    apply_patches(patched)

    print("\nUpdating checksum ...")
    update_checksum(patched, data)

    output_path.write_bytes(bytes(patched))
    changed = sum(a != b for a, b in zip(data, patched))
    print(f"\nWritten to {output_path}")
    print(f"  Size: {len(patched)} bytes (unchanged)")
    print(f"  SHA-256: {sha256(bytes(patched))}")
    print(f"  Bytes changed: {changed}")
    print(
        "\nDone. Login lockout and credit drain disabled. "
        "Flash this file to your GS108Ev3 at your own risk."
    )


if __name__ == "__main__":
    main()
