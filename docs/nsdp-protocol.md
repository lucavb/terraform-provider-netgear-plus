# NSDP Protocol Reference — NETGEAR Plus switches (GS108Ev3 line)

Complete wire-level reference for the NETGEAR Switch Discovery Protocol (NSDP) as spoken
by the GS108Ev3 (firmware V2.06.24GR) and its official Windows clients. There is no public
NETGEAR specification; everything below was reverse-engineered for this repository.

## 1. Overview and provenance

NSDP is a UDP broadcast protocol used by the ProSAFE Plus Utility / Switch Discovery Tool
family to discover and configure Plus-line smart switches without the HTTP UI. On the
GS108Ev3 it is served by the `plusutility` firmware task: a small 8051 service that
listens on UDP 63322, validates requests, walks TLV entries, and builds replies in place
in the RX buffer. For this provider it provides a fast read path (model, name, MAC,
IP/netmask/gateway, firmware, serial) and, since the login chain was cracked, a
credential-authenticated SET path for configuration. Beyond the GS108Ev3, NSDP is
spoken by at least the GS724T, GS748T, FS116E (which omits the IP/firmware TLVs) and
FS726TP (on the v1 port pair) `[wiki]`; the 2012 ProSafeLinux client targeted the
GS105e/GS108e `[psl]`.

How we know what we know — three primary sources, cross-checked against three
third-party analyses:

| Source | What it gave us | Label |
|---|---|---|
| **Live wire tests** (2026-09-12, real GS108Ev3, fw 2.06.24GR) via `tools/nsdp-probe` | packet header field semantics, GET replies, the full login chain (capability → nonce → token → SET → status 0x00), anti-replay behavior, error replies, failing-tag echo | `[live]` |
| **Firmware RE** (GS108Ev3 V2.06.24GR, bank-1 code, Ghidra) | server-side validation, command/status routing, SET gate and 3-strike lockout (XRAM 0x97EE / 0x980F), magic check, packet-length sanity checks | `[fw]` |
| **Client RE** — the utility's own code: `nsdp.js` (Switch Discovery Tool JS) and `nsdpmanager.exe` (ProSAFE Plus Utility protocol engine, PE32, Ghidra) | request framing, GET/SET tag dictionary, login token formulas, retry counts, reply parser, status-code meanings | `[client-js]` / `[client-exe]` |

Interpretation with residual gaps is marked `[inferred]`. Every formula and byte layout
marked `[live]` was exercised against a real switch; the Go library `internal/nsdp`
implements the same wire formats and token math (cross-checked against this document).

Third-party cross-references (2012-era analyses and public documentation):

| Source | What it contributed | Label |
|---|---|---|
| **ProSafeLinux** (2012 Python client; GS105e/GS108e, fw ≤ v1.0004; `psl_class.py` / `psl_typ.py`) | per-port TLV layouts (§6) from its pack/unpack code; independently confirms the NtgrRock key string; pre-dates the nonce/capability login system (inline NtgrRock-XOR'd `0x000A` password TLV per SET; no GET `0x14`/`0x17`, no tokens); its 2-byte sequence field is a historical v1 variant | `[psl]` |
| **Sven Anders, "Netgears Geheimcode", Linux-Magazin 11/2012** — https://www.linux-magazin.de/ausgaben/2012/11/netgears-geheimcode/ — the ProSafeLinux author's original disclosure writeup | 2012-era captures match our frame layout exactly (plaintext `0x000A` auth TLV first on every SET — independent confirmation of the auth-TLV rule across firmware generations); the era's swap-order password-change exploit explains why modern firmware has the nonce+token system and the old-pw-mixing cipher (§9) | `[hist]` |
| **Wikipedia NSDP article** | header/TLV/port cross-check; `0x0005` = system location; the DHCP-mode enum; the firmware-update arming flow; the wider device family. Its 2-byte sequence reading sees only the low half of the live-proven BE32 (§3) | `[wiki]` |

Scope note: firmware image updates ride TFTP (UDP 69), a separate firmware service
task; the NSDP SET types `0x0010`/`0x0011` first **arm the switch's TFTP server**
`[wiki]` — the transfer itself is out of scope here.

## 2. Transport

| | v2 (GS108Ev3 generation) | v1 (legacy) |
|---|---|---|
| Client binds | UDP 63321 | UDP 63323 |
| Switch listens on | UDP 63322 | UDP 63324 |
| Request destination | 255.255.255.255:63322 | 255.255.255.255:63324 |

- Broadcast to `255.255.255.255`; a request with an all-zero Agent MAC reaches every
  switch on the segment. The switch replies **unicast**, from its own IP, to the
  requester's bound source port. `[client-js]`, `[live]` A 2012-era report adds that
  the switch also accepts **unicast** requests addressed to its own IP (on that
  firmware generation replies were observed broadcast). `[hist]`
- The firmware serves both generations from the same code via two connection tables
  (XRAM `0x8804` / `0x8808`); port 63322 (0xF75A) is written into the v2 conn struct at
  init (`plusutility_service_init`, bank-1 `0xc412`). `[fw]`
- **Discovery burst** (Switch Discovery Tool): request burst, then the "AD" request
  re-sent every ~5 s (2 retransmits total), socket closed after a ~5–10 s listening
  window. `[client-js]`
- **Retry counts** (ProSAFE Plus Utility): GET attr `0x14` → 5 attempts; every other
  GET → 14 attempts. Each attempt consumes a **fresh sequence number**. `[client-exe]`
- **Per-request response window**: 800 ms in this repo's implementations (probe
  `-wait` default; `internal/nsdp` client default), after which the attempt is
  considered unanswered and retried.
- **Sequence numbers**: the utility picks a random base per session
  (`nsdp_command_start`: `rand()%1000`, then +1 per command) `[client-exe]`; this
  repo's tools pick a random base in 1000–9999. Randomization is not cosmetic: reusing
  sequence numbers from a previous session gets requests **silently dropped**
  (live-proven 2026-09-12: seqs 258–260 recycled → silence; fresh base 2562 →
  immediate replies). `[live]`

## 3. Packet header (32 bytes)

All multi-byte integers on the wire are **big-endian**.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | version | `0x01` (firmware's packet-class check accepts 0 or 1; else status 1) `[fw]` |
| 1 | 1 | command | `0x01` GET, `0x03` SET (anything else → status 2, rejected) `[fw]`; **replies echo command + 1**: GET reply = `0x02`, SET reply = `0x04` `[live]` |
| 2 | 1 | status | `0x00` in requests; in replies: `0x00` ok, else error (§8) |
| 3 | 1 | reserved | `0x00` |
| 4–5 | 2 | failing tag (BE16) | `0x0000` in requests and ok replies; in error replies the tag the switch wants/failed on (e.g. `0x001A` for a missing auth TLV) `[live]` |
| 6–7 | 2 | reserved | `0x00` |
| 8–13 | 6 | Manager MAC | the client host's MAC |
| 14–19 | 6 | Agent MAC | target switch MAC; all-zero = broadcast to all switches |
| 20–23 | 4 | sequence (BE32) | per-session counter, +1 per request; anti-replay relevant (§2) |
| 24–27 | 4 | magic | `"NSDP"` (`4e 53 44 50`); firmware compares `"NS"` @24 / `"DP"` @26, mismatch → silent drop `[fw]` |
| 28–31 | 4 | reserved | `0x00000000` |

Every field above is live-proven. (The Wikipedia article reads the sequence as 2 bytes
at `[22:24]` plus 2 unknown bytes — it sees only the **low half** of the counter; live
evidence wins: one BE32 at `[20:24]`, e.g. seq 2562 ↔ `00 00 0a 02`, echoed by the
reply. `[live]` vs `[wiki]`) The firmware also runs packet-length sanity checks
(len−1 / len−2 comparisons against the recorded packet length at XRAM `0x98BD`). `[fw]`

### The wire-offset-32 quirk (first TLV tag-high)

There is **no "filler byte" at offset 32** — early capture analysis suggested one, but
the TLV region simply *starts at wire offset 32*, and the byte at `[32]` is the **HIGH
byte of the first TLV's tag**. NETGEAR's own builders (and ours) emit a 32-byte header
plus one byte at `[32]`; the first TLV's tag then begins at `[32]`, i.e. its high byte
occupies that position.

- Small attr tags are `0x00NN`, so `[32] = 0x00` makes the following bytes parse as a
  well-formed TLV `{tag 0x00NN, len 0}`. This is why single-byte-tag GETs "just worked"
  before the model was corrected. `[live]`
- A builder that instead appends a *full* 4-byte TLV header **after** a 33-byte header
  prefix emits `{00,00}` = tag 0x0000 followed by a garbage length (live failure:
  len `0x0A00`) — the firmware parse layer rejects it with status `0x0d`. `[live]`
- For SETs, the first TLV's tag-high lands at `[32]` (e.g. `0x00` for auth TLV
  `0x001A`); every later TLV carries its full 2-byte tag (§4). `[client-exe]`, `[live]`

## 4. TLV region

From wire offset 32, entries are:

```
{tag: u16 BE}{len: u16 BE}{value: len bytes}
```

terminated by the **terminator TLV `{0xFFFF, 0x0000}`** = bytes `ff ff 00 00`. The reply
parser stops at the terminator. `[live]`, `[client-exe]`

### GET request forms

- **Attribute GET entry** — one 4-byte zero-length TLV per requested tag:
  `{tag BE16, 0x0000}`. The discovery tool frames these as 4-byte groups
  `[tag][00 00 00]`; the byte preceding each group (header `[32]` for the first entry,
  the previous group's trailing `00` afterwards) serves as that TLV's tag-high byte.
  Both views produce identical bytes. `[client-js]`, `[live]`
- **Trailer** — the discovery tool ends GETs with the 7-byte marker
  `00 00 00 ff ff 00 00`. In a strict TLV parse, the last entry's trailing `00` plus
  the marker's first three bytes form a zero TLV `{0x0000, 0}`, leaving `ff ff 00 00`
  as the terminator. In the full 92-byte discovery packet (below) the marker bytes are
  instead fully consumed as the tag-highs/terminator of the block entries. The switch
  accepts both. `[client-js]`, `[live]` Wikipedia's example GET ends with real TLVs +
  marker and **no** null TLV — null TLVs are tolerated padding;   a GET body is simply a
  TLV stream, and both forms work. `[wiki]` The trailer's zero bytes can also surface
  in replies as a **phantom dangling tag** (the `00 00` tails — §8's reply-shape
  model). `[fw]`
- **Block GET** — reads a "block" (multi-value family): TLV `{0x0014, 0}` (capability
  attr `0x14`; **v1 uses `0x000F`** instead) followed by one entry per requested block.
  The firmware's request parser buckets tags < `0x1b` as small attrs and < `0x3f` as
  **block indices**: a block entry carries the block's index byte as its TLV tag, and
  the reply tag is **index×4 << 8** (`0x1D`→`0x7400`, `0x1E`→`0x7800`, `0x03`→`0x0c00`,
  `0x0c`→`0x3000`) `[fw]` — nsdpctl already encodes this way. The JS discovery tool
  instead frames block entries as `{0xNN00, 0}` with NN = block id = the reply tag's
  high byte (e.g. block `0x78` → reply tag `0x7800`, serial number), and the switch
  accepts those bytes too `[client-js]`, `[live]` (the exact parse of that form is
  still being read — §8).
- The v2 discovery request is 92 bytes: header + the extra `[32]` byte, eleven attribute
  entries (tags `01,03,04,06,07,08,0b,0c,0d,0e,0f`), block entries
  `14 00 00 78` and `00 00 00 74`, marker `00 00 00 ff ff 00 00`:

```
01 01 00 00 00 00 00 00  <mac[0..5]>  00 00 00 00 00 00
00 00 01 02  4e 53 44 50  00 00 00 00  00
01 00 00 00  03 00 00 00  04 00 00 00  06 00 00 00
07 00 00 00  08 00 00 00  0b 00 00 00  0c 00 00 00
0d 00 00 00  0e 00 00 00  0f 00 00 00
14 00 00 78  00 00 00 74
00 00 00 ff  ff 00 00
```

  `[client-js]`; byte-for-byte live-proven against a real GS108Ev3. `[live]`

### Golden wire example — 44-byte single-attr GET `[live]`

The probe's GET of auth capability `0x14` in the live login session
(manager `2e:85:e5:be:3b:b8`, agent `8c:3b:ad:25:1b:88`, seq 2562):

```
01 01 00 00 00 00 00 00   [0..7]    ver 1 | cmd 1 GET | status 0 | rsvd | failing 0x0000 | rsvd
2e 85 e5 be 3b b8         [8..13]   manager MAC (client)
8c 3b ad 25 1b 88         [14..19]  agent MAC (target switch)
00 00 0a 02               [20..23]  seq 2562 (BE32)
4e 53 44 50               [24..27]  "NSDP"
00 00 00 00               [28..31]  reserved
00 14 00 00               [32..35]  GET entry = TLV{0x0014, len 0} — [32] is the tag-HIGH byte
00 00 00 00               [36..39]  TLV{0x0000, 0} (entry's trailing 00 + marker head)
ff ff 00 00               [40..43]  terminator TLV
```

Reply: status 0, TLV `{0x0014, 4}` = `00 00 00 10` (capability word, §5).

### SET builder semantics `[live]`, `[client-exe]`

- Command byte = `0x03`; the **first TLV's tag-high overwrites `[32]`**, later TLVs
  carry their full 2-byte tags. (Implemented in `internal/nsdp` `encodeSetTLVs`.)
- End every SET with the terminator TLV `ff ff 00 00` — the utility writes
  `{htons(0xFFFF), 0}` for **all** commands, GETs included. `[client-exe]`
- Never append the 7-byte GET trailer after a value TLV: `00 00 00 ff …` would parse
  as tag 0 / len `0x00FF` (255 promised value bytes) — parse-layer garbage, status
  `0x0d`. It is only safe directly after a 4-byte entry. `[live]`

## 5. Login / authentication

The full chain below is **live-proven end to end** on 2026-09-12 against a GS108Ev3
(2.06.24GR): randomized base seq 2562, capability GET → nonce GET → 48-byte login SET →
36-byte status-0 reply. `[live]`

### Step 1 — capability: GET attr `0x14`

Reply TLV `{0x0014, 4}`, value = **auth capability word V, BE32** (big-endian confirmed
by both the utility's reader `FUN_00494880` and live test). Live GS108Ev3:
`00 00 00 10` → V = 0x10 → V2 branch. Bits:

| Bit | Meaning |
|---|---|
| `V & 0x01` | NtgrRock XOR pre-transform applies to the password (see below) |
| `V & 0x08` | "supportEnhanceEncrypted" — 4-byte V1 hash token |
| `V & 0x10` | "supportEnhanceV2Encrypted" — 8-byte V2 hash token |
| none of 0x08/0x10 | plaintext password |

### Step 2 — nonce: GET attr `0x17`

Reply TLV `{0x0017, 4}`, value = **4 raw bytes, in wire order** — not an integer (the
utility's parser stores a raw pointer; our token math indexes them as `n[0..3]` exactly
as they appear on the wire). The nonce is **dynamic** and — critically — **rolls after
every authenticated SET** (live-proven; see "Nonce lifetime" below), so a client must
refresh it immediately before every SET. Three live captures: `46 76 29 1a`,
`7e 74 22 b7`, `03 9b 6a 1b`.

### Step 3 — token computation

Inputs: `n[0..3]` = nonce bytes (wire order); `m[0..5]` = switch MAC (the agent MAC);
`p[0..19]` = admin password **zero-padded to 20 bytes** (truncated if longer).

**NtgrRock pre-transform** — applied first, *iff* `V & 1` (composes with the branches
below; it is not a separate terminal branch): `p'[i] = p[i] ^ "NtgrSmartSwitchRock"[i % 19]`
(repeating 19-byte key). `[client-exe]`

**V2 token** (V & 0x10 → 8 bytes), verbatim from the nsdpmanager disassembly
(`0x489e40–0x48a024`):

```
T0 = n3^n2^m1^m5^p2^p1^p0         T4 = n3^n2^m1^m5^p12^p14^p13
T1 = n3^n1^m4^m0^p4^p3^p5         T5 = n3^n1^m4^m0^p17^p16^p15
T2 = n0^n2^m3^m2^p8^p6^p7         T6 = n0^n2^m3^m2^p19^p18^p0
T3 = n0^n1^m4^m5^p11^p10^p9       T7 = n0^n1^m4^m5^p3^p5^p1
```

**V1 token** (V & 8 → 4 bytes):

```
T0 = m1^n3^n2^p13^p9^m5^p7^p1
T1 = n3^n1^m4^p14^p10^p6^p2^m0
T2 = m3^m2^n0^n2^p12^p8^p5^p0
T3 = n0^n1^m4^p15^p11^p4^p3^m5
```

### Step 4 — auth TLV tag/length per branch

| Branch | Auth TLV | Value |
|---|---|---|
| `V & 0x10` | tag `0x001A`, len **8** | V2 token |
| `V & 8` | tag `0x0018`, len **4** | V1 token |
| else | tag `0x000A`, len = password length | password (NtgrRock-XORed iff `V & 1`) |

The tag is per-branch, not fixed: the switch **announces the required tag** in the
error reply's `[4:5]` failing-tag field when you send the wrong one (live: status
`0x0d`, failing tag `0x001A` when the password went out under `0x000A`). `[live]`
(GS105Ev2 special case in the utility: model TLV `0xA400` + password TLV `0x0A` —
irrelevant to the GS108Ev3. Note that `0x000A` doubles as the OLD-password SET tag —
§9.)

The login itself is the client command type `0xE400` (TLV_LOGIN_SWITCH): a cmd-3 SET
carrying **only** the auth TLV + terminator — the type is a client-side dispatch key
that adds no further TLVs. `[client-exe]`, `[live]`

### Golden wire example — 48-byte login SET `[live]`

```
01 03 00 00 00 00 00 00   [0..7]    ver 1 | cmd 3 SET | status 0 | rsvd | failing 0x0000 | rsvd
2e 85 e5 be 3b b8         [8..13]   manager MAC
8c 3b ad 25 1b 88         [14..19]  agent MAC (switch — also the m[] token input)
00 00 0a 04               [20..23]  seq 2564 (BE32)
4e 53 44 50               [24..27]  "NSDP"
00 00 00 00               [28..31]  reserved
00 1a 00 08               [32..35]  auth TLV {tag 0x001A, len 8} — [32] = tag-HIGH byte
8b 44 f6 1c a3 17 a9 3b   [36..43]  V2 token (from nonce 03 9b 6a 1b + switch MAC + password)
ff ff 00 00               [44..47]  terminator TLV
```

### THE AUTH-TLV-ON-EVERY-SET RULE

**Every cmd-3 SET carries the auth TLV before the type-specific TLV** — unconditionally.
The utility's `nsdp_command_start` writes the password/auth TLV (same branch/tag/len
rules, token recomputed from the cached nonce + MAC + password) from the command
struct *before* dispatching on the SET type; the switch checks it, and its error replies
announce the required tag in `[4:5]`. `[client-exe]` (firmware-consistent: the login
verify handler at bank-1 ~`0x87c0–0x884e` memcmps the parsed auth TLV value). `[fw]`

A login is therefore just the special case "SET with only an auth TLV"; a config SET
is "auth TLV + type TLV(s)". The token is derived from the login nonce, so only the
client that performed the login can produce it.

### Nonce lifetime — refresh before EVERY SET `[live]`

The auth nonce **rolls after every authenticated SET** — and, live observation shows,
under GET-only traffic as well: two serves rolled it 12 s apart with no SETs in
between (ROUND 12), and a GET-only battery saw **three distinct nonces in ~18 s**
(`4d c5 02 cb` → `3b ba 50 11` → `38 24 1e 60`, ROUND 13b). Whether the fine trigger
is every `0x17` read or a short timer is unpinned (either fits; irrelevant for
correctness). A served nonce stayed valid across a ~2–3 s gap. A client must GET
`0x17` and recompute the token immediately before **every** SET (the login SET itself
follows this pattern: capability GET → nonce GET → token → SET). `[live]`

Live end-to-end proof (2026-09-12): login with nonce `50 8f 06 23` → token accepted;
refreshed nonce `50 86 3e cd` → recomputed V2 token `09 8f f1 52 21 dc ae 75` →
system-name SET → status `0x00` → read-back `lab-test`.

**Stale-token behavior**: a token computed from a pre-roll nonce fails with status
`0x0d`, failing tag `0x001A`, and a 46-byte reply whose payload at offset 32 is
`{BE16 len=8, 8 raw bytes}` = the **switch-EXPECTED token** — a raw value, not a TLV
(no tag). Live run #5: sent token `e5 d0 e7 f7 cd 83 b8 d0`, expected
`8f 9f cf fa a7 cc 90 dd`; the XOR delta `6a 4f 28 0d 6a 4f 28 0d` repeats with
period 4, exactly matching the V2 formula's byte-mix pairs (T0/T4, T1/T5, T2/T6, T3/T7
share their nonce/MAC terms) — proof that the payload is a well-formed V2 token
computed for the rolled nonce (~1 in 2^24 coincidence otherwise). This also resolves
the earlier all-zero `0x0d` payload mystery: it was the expected token under a
zero-nonce context.

Consequences:

- Status `0x0d` covers **both** parse-layer errors and auth-verify mismatches; the
  `0x001A` failing tag + 8-byte expected-token payload identifies the auth case.
- A stale-token `0x0d` **is** a verify-stage failure and burns one of the three
  lockout strikes (run #5 left 2 of 3).
- The Go client surfaces the expected token as `ErrStatus.ExpectedAuth` — diagnostic
  only; a stale-token SET is never auto-retried.
- The fine roll trigger is open (per-`0x17`-read vs short-timer — GET-only rolls are
  live-observed, §10) but does not affect correctness: re-read the nonce before every
  SET.

### SET gate and the 3-strike lockout `[fw]`

- The firmware gate for cmd 3 (bank-1 `0x9e20`) is a **lockout-until** comparison, not
  an equality check: a SET is allowed iff the 32-bit lockout deadline at XRAM
  `0x980F` (MSB first) is ≤ the running timer at IRAM `0x26–0x29`.
- The login verify handler counts failures at XRAM `0x97EE`. On a **parsed** auth TLV
  that fails verification: counter++, and at **3 failures** the deadline is set to
  `timer + 0x1B7740` ticks (~30 minutes at a 1 ms tick) — **all SETs are locked out
  for ~30 minutes**. A successful login clears both the counter and the deadline.
- **Parse-layer `0x0d` errors do NOT count**: the counter increments only after a
  well-formed auth TLV reaches the verify stage. A malformed packet dies in the parse
  layer first. Practical rule: an auth-layer error may have burned one of your three
  strikes — never iterate blindly on login errors; a parse error did not.
- GETs bypass the gate entirely and are answered without credentials (live: an
  unregistered host with a random locally-administered Manager MAC gets replies). `[live]`

## 6. GET dictionary

### Small tags

Request = one 4-byte entry per tag; reply value formats are from the utility's reply
parser (ROUND-7 decode) plus live captures.

| Tag | Meaning | Reply value format | Notes |
|---|---|---|---|
| `0x0001` | model | ASCII string | live: `GS108Ev3` `[live]` |
| `0x0002` | model code | BE16 | live: `0` `[live]`, `[client-exe]` |
| `0x0003` | system name | ASCII string | empty when unset — observed both **omitted entirely** and as a **0-byte TLV** `[live]` |
| `0x0004` | MAC address | 6 raw bytes | `[live]` |
| `0x0005` | system location | string | omitted when empty `[live]`; label `[wiki]` |
| `0x0006` | switch IP address | BE32 | live: `10.0.2.2` `[live]` |
| `0x0007` | netmask | BE32 | live: `255.255.0.0` `[live]` |
| `0x0008` | default gateway | BE32 | live: `10.0.0.1` `[live]` |
| `0x000b` | DHCP mode | u8 enum | `0` = Static, `1` = DHCP, `2` = Refresh DHCP `[wiki]`, `[psl]`; live `00` (static) |
| `0x000c` | (unnamed) | u8 | constant `0x01` in fw 2.06.24 `[live]` |
| `0x000d` | firmware image 1 | ASCII string | live: `2.06.24` (no prefix) `[live]` |
| `0x000e` | firmware image 2 | ASCII string | omitted when slot empty `[live]` |
| `0x000f` | active image | u8 | client reads the **low nibble** = image 1/2 `[client-js]`; live `1` |
| `0x0011` | **login info blob** | nested composite or empty | composite `{0x0014 cap}{0x0017 nonce}` + trailing (live len 18+2), or an empty `{0x0011, 0}` echo — subsection below; V1-era utility sense: GET with password TLV attached `[live]`, `[client-exe]` |
| `0x0012` | **login composite marker** | string class: empty or nested login composite | requesting it flips separate `0x14`/`0x17` replies into one composite (live len 20 — subsection below); V1-era utility sense: GET with password + value; the earlier `u8` label (ProSafeLinux) is wrong `[live]`, `[client-exe]` |
| `0x0014` | auth capability word | BE32 | §5; live `00 00 00 10` `[live]` |
| `0x0017` | login nonce | **raw 4 bytes** (wire order) | §5; dynamic `[live]` |

Tags `09, 0a, 10, 13, 15, 16, 18, 19, 1a` are **client-sent only** (auth/password TLV
tags and friends — `0x000A` is the plaintext auth TLV and the OLD-password SET tag,
§9) — the reply parser never consumes them. (The firmware's GET-reply builder does
carry a dispatcher case for `0x19`, semantics unknown — §8 — so the switch can emit at
least that one.)

Special GET dispatch types in the utility (client command types, not wire tags):
`0x0000` discovery (12 len-0 entries), `0x03ff` Uplus-switch discovery (13 entries),
`0x00ff` bulk device-info GET (13-bit mask selects conditional entries),
`0x2800`/`0x8800` block GETs with a selector (0 = all items, `0xffff` = all groups),
`0xf400` extension GET with a 4-byte BE32 selector; all other `0xNN00` → generic entry.
`[client-exe]`

### Block / family tags (reply value formats)

Block id NN = tag high byte (§4): block GET `0x78` → reply tag `0x7800`. The reply
parser dispatches two-level: `tag & 0xfc00` family first, then `tag & 0x3ff`. `[client-exe]`
Request-side, the firmware encodes blocks by index — index×4 = the reply tag's high
byte (§4, §8). Port numbers are **1-based** in all per-port layouts. `[psl]`

| Tag | Meaning | Reply value format |
|---|---|---|
| `0x0c00` | speed/link status (per port) | 3 bytes: `{port u8, speed u8, link u8}` `[psl]` — resolves the unknown block `0x0c`; live dump: 8 entries, ports 1/2/8 `speed=5, link=0`, ports 3–7 all zero — the speed/link **code values are not pinned** `[live]` |
| `0x1000` | **per-port traffic statistics** | per entry: `{port u8 (1-based) + 6 × u64 BE: received, sent, packets, broadcast, multicast, error}` — 1+48 = 49 bytes `[psl]`, `[wiki]`; the reply parser's old "serial blob" label was wrong (serial = `0x7800`) |
| `0x1400` | (family scalar; SET type = reset port stats, §7) | BE32 (client stores raw) |
| `0x2000` | VLAN engine mode | 1 byte (`0x2400` = port-based, `0x2800` = 802.1Q) `[psl]` |
| `0x2400` | VLAN-ID port bitmap | (len−2)/2 × BE16 `[psl]` |
| `0x3000` | PVID per port | 3 bytes: `{port u8 (1-based), vlan_id u16 BE}` `[psl]` — layout confirmed; live: port 4 = VLAN 1001, port 5 = VLAN 10, remaining ports VLAN 1 `[live]` |
| `0x3800` | per-port QoS | 2 bytes: `{port u8 (1-based), priority u8}` — `1`=High, `2`=Middle, `3`=Normal, `4`=Low `[psl]` — layout confirmed |
| `0x4c00` | ingress bandwidth limit (per port) | 5 bytes: `{port u8, 00 00, limit u16 BE}` `[psl]` — refines the parser's "concat 4+1" |
| `0x5000` | egress bandwidth limit (per port) | 5 bytes: `{port u8, 00 00, limit u16 BE}` `[psl]` |
| `0x5400` | (family scalar) | BE32 |
| `0x5800` | broadcast-storm rate limit (per port) | 5 bytes: `{port u8, 00 00, limit u16 BE}` `[psl]` |
| `0x5c00` | port mirroring | 3 bytes: `{dst_port u8, reserved u8, src_ports u8 bitmap}` `[psl]` |
| `0x6000` | (family scalar) | BE32 |
| `0x6400` | (family scalar) | BE32 |
| `0x6800` | IGMP snooping | 4 bytes: `{enabled u16 BE, vlan_id u16 BE}` `[psl]` |
| `0x6c00` | (family scalar) | BE32 |
| `0x7000` | (unnamed) | — (SET-side: 1-byte family, §7) |
| `0x7400` | fw/config block 0x74 | client parses as string + sets a flag `[client-exe]`; live replies: `00 00 00 18 7f fc ff ff` and a mostly-zero dump containing `18 7f` — still **opaque** (§10) `[live]` |
| `0x7800` | **serial number** (block 0x78) | 21-byte blob: `{01 33, 12-char ASCII serial, 00, trailing garbage}` — the serial is the **12 ASCII chars at offset 2** (live: `UH77B5R033EE`); the earlier `3UH77B5R033EEZvSoIo` reading wrongly folded in the `0x33` prefix byte and an uninitialized-RAM tail `[live]` |
| `0x7c00` | (family scalar) | BE32 |
| `0x8000` | fw image (string) | string |
| `0x8400` | (family scalar) | BE32 |
| `0x8800` | port stats / LA groups | multi-entry |
| `0x8c00` | (family scalar) | BE32 |
| `0x9000` | (unnamed) | len 1 |
| `0x9400` | port admin status | len 3 per entry: `{port u8, BE16}` — layout live-confirmed (8 entries, all `0x0100`); the value's **semantics are unverified** (§10) `[live]` |
| `0x9c00` | VLAN config entry (reply) | len 3 per entry — **layout unverified** `[client-exe]` |
| `0xa000` | (unnamed) | len 1 |
| `0xa800` | (unnamed) | len 1 |
| `0xac00` | (unnamed) | len 1 |
| `0xb000` | string blob | string |
| `0xf000` | (unnamed) | len 1 |
| `0xf400` | extension | len 9 (4+4+1) or len 6 (detailed stats) |
| `0xf800` | (family scalar) | BE32 |

Every live block reply **leads with the capability TLV `{0x0014}`** — the block GET's
`0x14` marker entry lands in the small-attr bucket, so the switch answers capability +
block(s) in one reply. The official web client bundles exactly this: attr `0x14` +
block `0x7800` in ONE GET (nsdp.js lines 88/156). `[live]`, `[client-js]`

### Login-info blob and composite (0x0011 / 0x0012)

ROUND-12 tag-set × reply-shape experiments mapped how the switch answers requests
containing `0x11`/`0x12` — the reply builder has **no dispatcher case** for either tag
(§8), so their reply tags dangle and the following bytes get swallowed as a length:

- `get 11` → a clean empty echo: `{0x0011, len 0}`.
- `get 14 17 11` → separate `TLV{0x14}` + `TLV{0x17}` + empty `{0x0011, 0}` — this
  **refutes** the "capability context window gates `0x11`" hypothesis.
- `get 12 14 17 11` → **one composite** `{0x0012, len 20}`, wire
  `00 12 00 14 | 00 04 00 00 00 10 | 00 17 00 04 4e 5d 1a 8e | 00 11 00 00 | ff ff`
  (the length bytes `00 14` double as the nested capability tag; nested entries are
  tag-elided) — requesting `0x12` flips separate 14/17 replies into a composite.
- the ROUND-11 dump batch → a composite under `{0x0011, len 18}`: nested
  `{0x0014, 4, capability}{0x0017, 4, nonce}` + 2 trailing bytes.

Same nested content, two serializations (`0x0011` vs `0x0012` framing). `[live]`

## 7. SET dictionary

All from the full `nsdp_command_start` (utility `FUN_00492b80`) decode `[client-exe]`,
unless marked otherwise. **Every SET = cmd 3 + auth TLV first (§5) + type TLV(s) +
terminator.** String values are **plaintext** — only the password TLVs (`0x0009` NEW /
`0x000A` OLD, §9) are encrypted: `nsdp_set_tlv_string_enhance` (`FUN_004945d0`)
plaintext-memcpy's every non-password string and routes only `0x0009`/`0x000A`
through the crypto cluster. `[client-exe]`

Scalar/BE32/string SET types:

| Type | Name / meaning | Value form |
|---|---|---|
| `0x0003` | TLV_SYSTEM_NAME | ASCII string, plaintext; live-proven builder in `internal/nsdp` |
| `0x0004` | (unnamed scalar) | scalar via `nsdp_set_tlv_value` |
| `0x0005` | system location | string `[wiki]` |
| `0x0006` | TLV_IP_ADDRESS | BE32 inline |
| `0x0007` | TLV (netmask) | BE32 inline |
| `0x0008` | TLV (gateway) | BE32 inline |
| `0x0009` | TLV_NEW_PASSWORD | **encrypted** (§9) |
| `0x000A` | TLV_OLD_PASSWORD — same tag as the plaintext auth TLV (§5) | **encrypted** (§9) |
| `0x0010` / `0x0011` / `0x0013` | TLV_UPGRADE_FIRMWARE … TLV_REBOOT | scalar + conditional 2nd TLV; the upgrade types (`0x10`/`0x11`) **arm the switch's TFTP server** — the firmware-update flow (§1) `[wiki]` |
| `0x0012` | login composite marker (GET-side classification, §6; SET-side semantics unknown) | — |
| `0x0017` | scalar (1-byte) | 1 byte |
| `0x000b` / `0x000c` / `0x000f` | TLV_DHCP_MODE … TLV_ACTIVE_IMAGE | scalar |

1-byte-value family (client "caseD_17"): `0x0400` TLV_FACTORY_DEFAULTS through
TLV_BROADCAST_STORM_CONTROL, plus `0x1400` (reset port stats `[psl]`), `0x2000`
(VLAN engine mode), `0x5400`, `0x6c00`, `0x7000`,
`0x7c00`, `0x8400`, `0xa800`, `0xf800`.

Per-port loops (the client repeats `set_tlv(type)` once per selected port; port
numbers are **1-based** `[psl]`):

| Type | Name |
|---|---|
| `0x1800` | TLV_CABLE_TEST |
| `0x2400` | TLV_PORT_BASED_VLAN |
| `0x2800` | TLV_8021Q_VLAN (conditional second `0x3000` loop) |
| `0x2c00` | TLV_DELETE_8021Q_VLAN |
| `0x3000` | TLV_PVID |
| `0x3800` | TLV_PORT_BASED_QOS |
| `0x4c00` / `0x5000` / `0x5800` | TLV_INGRESS_RATE … TLV_BROADCAST_STORM_RATE |
| `0x8800` | LA (link aggregation) groups |
| `0x9400` | TLV_PORT_ADMIN_STATUS — **port enable/disable** |
| `0xb000` | (unnamed) |
| `0xf400` | TLV_EXTENSION 1~ |

Single-TLV SETs: `0x5c00` TLV_PORT_MIRRORING, `0x6800`, `0x7800`,
`0x8000` TLV_IGS_STATIC_ROUTER_PORT, `0x9c00` TLV_ONE_TO_ONE_MIRROR, `0xa000`,
`0xac00`.

Special command types:

| Type | Behavior |
|---|---|
| `0xE400` | TLV_LOGIN_SWITCH — auth TLV only (§5) — **live-proven** `[live]` |
| `0xE800` | TLV_SET_DEVICE_INFO — bitmask selects conditional TLVs `0x0006` (IP), `0x0007` (mask), `0x0008` (gateway), `0x000b` (DHCP) — the IP-config bundle |
| `0xEC00` | bitmask selects `0x6800` / `0x6c00` / `0x7000` |

Client-side writer helpers (for building frames exactly like the utility): 
`nsdp_set_tlv_type` `{htons(tag), 0}` (GET entries); `nsdp_set_tlv(tag, len, bytes)`;
`nsdp_set_tlv_value(tag, len ∈ {1,2,4}, BE scalar; anything else is a client-side
length error 0xfb)`; `nsdp_set_tlv_string_enhance` (strings; encrypts types
`0x0009`/`0x000A` only).
Unknown SET types are a client-side error (0xfc) — never sent. `[client-exe]`

### Golden wire example — 58-byte system-name SET

Constructed (not live-captured) from the client builder + login state above; arithmetic:
**header 32 + auth TLV 12 + name TLV 10 (full 2-byte tag) + terminator 4 = 58** with a
6-byte name. `[client-exe]` The frame shape is live-validated: the E2E run of §5 set
the name `lab-test` (8-byte value → 60-byte frame) and read it back after a status-0
reply. `[live]`

```
01 03 00 00 00 00 00 00   [0..7]    ver 1 | cmd 3 SET
2e 85 e5 be 3b b8         [8..13]   manager MAC
8c 3b ad 25 1b 88         [14..19]  agent MAC
00 00 0a 05               [20..23]  seq 2565
4e 53 44 50               [24..27]  "NSDP"
00 00 00 00               [28..31]  reserved
00 1a 00 08               [32..35]  auth TLV {0x001A, len 8} — [32] = tag-high (FIRST TLV)
8b 44 f6 1c a3 17 a9 3b   [36..43]  V2 auth token (from the login nonce)
00 03 00 06               [44..47]  name TLV {0x0003, len 6} — FULL tag (later TLVs carry both tag bytes)
6c 61 62 2d 73 77         [48..53]  "lab-sw" — PLAINTEXT (only password TLVs 0x0009/0x000A are encrypted)
ff ff 00 00               [54..57]  terminator TLV
```

## 8. Replies

The reply echoes the 32-byte header with: command = request command + 1 (GET `1`→`2`,
SET `3`→`4`), status at `[2]`, failing tag BE16 at `[4:6]`, manager MAC echoed, Agent ID
= the switch's own MAC, sequence echoed, magic echoed. `[live]`

Client-side reply validation (the utility's parser, `FUN_0048edc0`) — a robust
implementation should mirror it: version byte must be 0x01, sequence must match a
pending request, `"NSDP"` magic, manager-MAC filter, agent-MAC filter (all-zero
wildcard or known MACs), reply command = sent + 1, length ≥ 32. `[client-exe]`
(The old JS discovery tool validated none of this; don't copy that.) On top of that,
tolerate **truncated TLV tails** — keep every complete TLV before the cut; a reply
ending mid-TLV is still a valid reply (reply-shape model below; live-proven by the
ROUND-13b battery). `[live]`

### Status codes

| Status | Meaning | Provenance |
|---|---|---|
| `0x00` | ok | `[live]` |
| `0x01` | bad version (firmware); client also groups `0x09` as version-family | `[fw]`, `[client-exe]` |
| `0x02` | bad command byte | `[fw]` |
| `0x03` | missing TLV (client meaning) / invalid-unknown attribute, failing tag echoed at `[4:6]` (firmware) | `[client-exe]`, `[fw]` |
| `0x04` | unknown GET body/block tag | `[fw]` |
| `0x05` | SET-related failure | `[fw]` |
| `0x07` | missing expected TLVs — count short at terminator (client) / manager-MAC check failed (firmware) | `[client-exe]`, `[fw]` |
| `0x0d` | parse error / required TLV missing or malformed, **or** auth-verify mismatch (stale token); **failing tag in `[4:6]`**; the auth case carries an 8-byte expected-token payload (§5) | `[live]` |
| `0x0f` | auth failure | `[client-js]` — **never observed live** |
| `0xf2` | busy (client dedup/retry queue) | `[client-exe]` |
| `0x80–0x84` | retry family (client reschedules); `0x84` = tag-0x10 SET error | `[client-exe]` |

Client-*generated* codes `0xf8` (send fail), `0xfb` (length error), `0xfc` (unknown SET
type) are written by the utility itself, not by the switch. `[client-exe]`

### Golden wire example — 36-byte success reply `[live]`

```
01 04 00 00 00 00 00 00   [0..7]    ver | cmd 4 (SET reply = 3+1) | status 0x00 | failing 0x0000
2e 85 e5 be 3b b8         [8..13]   manager MAC echoed
8c 3b ad 25 1b 88         [14..19]  agent MAC (the switch's own MAC)
00 00 0a 04               [20..23]  seq 2564 echoed
4e 53 44 50               [24..27]  "NSDP"
00 00 00 00               [28..31]  reserved
ff ff 00 00               [32..35]  bare terminator — success carries NO TLVs
```

Success = header + bare terminator (36 bytes). Error replies are 46 bytes with a
payload and the failing tag in `[4:6]`.

### Golden wire example — 46-byte error reply `[live]`

Captured twice byte-identically when the login SET carried the wrong auth-TLV tag
(plaintext `0x000A` instead of the required V2 `0x001A`):

```
01 04 0d 00 00 1a 00 00   [0..7]    cmd 4 | status 0x0d | failing tag 0x001A (required auth TLV)
2e 85 e5 be 3b b8         [8..13]   manager MAC echoed
8c 3b ad 25 1b 88         [14..19]  agent MAC
00 00 01 04               [20..23]  seq 260 echoed
4e 53 44 50               [24..27]  "NSDP"
00 00 00 00               [28..31]  reserved
00 08                     [32..33]  expected-token length (BE16) = 8 — the payload is NOT a TLV
00 00 00 00 00 00 00 00   [34..41]  the switch-EXPECTED V2 token — all zeros here (zero-nonce context, §5)
ff ff 00 00               [42..45]  terminator TLV
```

Auth-verify mismatch replies (stale token, §5) carry the same 46-byte shape with the
**actual expected token** in the payload — live run #5: sent `e5 d0 e7 f7 cd 83 b8 d0`,
expected `8f 9f cf fa a7 cc 90 dd`; the period-4 XOR delta proves the payload is a V2
token computed for the rolled nonce. `[live]`

### Reply value formats and block↔tag unification

Reply value formats per tag are tabulated in §6 (small tags and family tags). Block↔tag
unification: the block id *is* the reply tag's high byte (`0x78` ↔ `0x7800`), the block
GET carries marker TLV `0x0014` (v1: `0x000F`) + one entry per block, and the reply
parser dispatches families by `tag & 0xfc00` then `tag & 0x3ff` — parsing the tag as one
BE16 covers both the `0x00NN` and `0xNN00` forms. Request-side, the firmware encodes
block entries as **index bytes** (reply tag = index×4 << 8) — see the builder below.
`[client-exe]`, `[live]`, `[fw]`

### The GET reply builder (firmware decode) `[fw]`

Decoded in Ghidra from the live bank (`GS108Ev3_V2.06.24GR_bank1.bin`, ROUND 13):

- **Orchestrator at `CODE:5000`**: the reply write ptr starts at base + `0x20` (the TLV
  region after the 32-byte header), stored at XRAM `0x9f15`, with the reply-length
  counter at `0x9f16`; XRAM `0x989e` is the "this is a SET" flag (reply cmd byte =
  4 for SET, 2 for GET). Early exits write status (`0x989f` / `0x98a2`=5 /
  `0x98a3`=4) or the failing tag (`0x98a0:0x98a1` → status 3) and send immediately.
  The SET-auth-mismatch reply builder (status `0x0d` + `{0x001A, 8-byte expected
  token}`, §5) is confirmed at `0x50d1–0x5138`.
- **Small-attr loop (`0x5169`)**: per entry the reply tag `00 {attr}` is appended
  **first**, then the entry byte dispatches through an XRL/CJNE chain: cases
  `01–08, 0b–0f, 14, 17, 19` (`0x0a` gated by the SET flag). There are **no cases
  for `0x11`/`0x12`** — their tags dangle in the reply with no length/value, which is
  the composite mechanism below. The `0x14` case appends `00 04` + 3 zero bytes + the
  capability byte; the `0x17` case appends `00 04` + the 4-byte nonce (file read).
- **Block loop (`0x55e7`)**: per entry appends reply tag `{index×4, 0x00}`
  (`0x1D`→`0x7400`, `0x1E`→`0x7800`, `0x25`→`0x9400`, `0x03`→`0x0c00`,
  `0x0c`→`0x3000`; CJNE #1–#5 = the port-stat blocks).
- **Finalize (`0x64ac`)**: appends the terminator `ff ff 00 00`, computes the reply
  length, and sends via `0xc803` — **unconditionally**. The only no-send aborts
  (`0x540c`/`0x54f3` → bare `RET` at `0x64f9`) are file-lookup failures: a GET reply
  is always sent.
- **Request parser**: small tags (< `0x1b`) append the tag low byte to
  `0x981d[0x981c++]` (~`0x8630`, tag read from `0x9b8f`); block entries (< `0x3f`)
  append to `0x985e[0x985d++]` (~`0x7a30`, tag from `0x9b91`); anything larger
  rejects the whole request with status 3 + failing tag. So block GETs send the
  block **index** as the TLV tag — nsdpctl's encoder already does this; the JS
  discovery tool's `{0xNN00}`-framed bytes are accepted as well (that parse path is
  still being read).

### Reply shapes explained (every observed GET reply) `[fw]`, `[live]`

One model covers every observed GET reply — and is **live-proven end-to-end** by the
ROUND-13b battery:

- The `00 00` before the terminator is a **dangling tag**: either a request-side
  `0x11`/`0x12` entry the dispatcher has no case for, or a phantom block entry
  (byte `00` parsed from the client GET trailer, §4). Composites form when a dangling
  `00 11`/`00 12` tag is followed by more reply bytes: the walker reads the next
  `00 14`-style bytes as a **length**, swallowing capability + nonce (+ tail) as one
  TLV value — the `0x0011`/`0x0012` shapes of §6.
  - dump batch: `{0x0011, len 18}` = dangling `11` + `12`-as-length; the value ends
    `00 00`, so the trailing was the phantom, not extra TLV content.
  - `get 12 14 17 11`: `{0x0012, len 20}` swallows through `ff ff`; the leftover
    `00 00` is < 4 bytes and ignored.
  - `get 14 17 11`: `TLV{14}` + `TLV{17}` + `TLV{0x0011, 0}` + terminator — clean.
  - lone `get 11` / `get 12`: dangling tag + `00 00` = zero-length TLV — clean.
- Lone `get 14` / `get 17` replies end `00 00 ff ff 00 00`: the tail parses as
  `{tag 0x0000, len 0xFFFF}` — a TLV **truncated mid-value**. The switch **did**
  reply (the finalize send is unconditional); a strict client that rejects truncated
  tails drops the reply and reports "no reply" — apparent silence.
- **Live proof (ROUND 13b, 13:41)**: with a truncation-tolerant `ParseReply` and no
  other change, lone `get 14` → capability `0x10`, `get 17` → nonce, and
  `get 14 17` ×2 → both — all green. The 13:21 lone-14/17 "silence" was the
  client-side truncated-tail drop, exactly as the firmware model predicted; the
  seq-anti-replay alternate theory is dead.
- The official web client never sends lone `0x14`: it bundles attr `0x14` + block
  `0x7800` in ONE GET (nsdp.js lines 88/156).
- Walker guidance: accept truncated TLV tails; keep everything before the cut.

## 9. Password-change cipher (TLV types 0x0009 / 0x000A)

The only encrypted SET values. Tag assignment (corrected from the earlier 9=old /
10=new reading): **`0x0009` = NEW password, `0x000A` = OLD password** — `0x000A` is
the same tag as the plaintext auth TLV (§5). `[hist]`, `[psl]` From the call-site
disasm of the utility's crypto cluster (`FUN_004879f0`, call sites `0x494690`/`0x494790`
in `nsdp_set_tlv_string_enhance`) `[client-exe]`:

```
out[i] = OLD[i % oldlen] ^ NEW[i] ^ M[i % 6] ^ N[(i+2)%4] ^ N[i % 4],   i = 0..newlen-1
```

- `OLD` = current/old password bytes, cycled by old length; `NEW` = the string being
  SET, linear; `M` = 6-byte key at `0x6cd8ec` — very likely the cached **switch MAC**;
  `N` = 4-byte key at `0x6ccce0` — very likely the cached **nonce**. (Runtime-initialized
  globals; MAC/nonce roles are `[inferred]`, confirm on first live password change.)
- 32-byte zeroed out buffer; the TLV value is the first `newlen` bytes (V1) or
  `newlen+1` bytes (V2 — the extra byte is a `0x00` from the padding).
- **Design**: for the OLD-password TLV (`0x000A`) the string being SET equals the old
  password, so the output reduces to the pure pad `M[i%6] ^ N[(i+2)%4] ^ N[i%4]` — the
  old-password TLV doubles as a pad carrier. The NEW-password TLV (`0x0009`) output
  is `pad ^ old ^ new`. Given the `0x000A` TLV the switch can verify it against its
  own MAC/nonce (proving old-password knowledge) and use it to decrypt `0x0009`; the
  nonce makes the pair replay-protected.
- **Why this crypto exists** `[hist]`: 2012-era firmware accepted a password change
  when the TLVs arrived in swapped order (`0x0009` new before `0x000A` old) — a
  password change without knowing the old password (the ProSafeLinux swap-order
  exploit). The modern nonce-challenge + token system (§5) and this old-pw-mixing
  cipher are NETGEAR's fix: explicit proof-of-old-password. (The article also notes
  the serial number doubles as the factory/recovery password.)

Password change is LOW priority for this provider (the HTTP path already implements
it); the formula is recorded for completeness.

## 10. Known-unknowns

Explicitly unverified items — do not build against these without live confirmation.
(ROUNDs 8–13b resolved several former entries — the PVID/QoS/bandwidth/IGMP/mirror/
VLAN-engine/speed-link layouts, block `0x0c` and block `0x30` semantics, the `0x0d`
error-reply payload, the SET-type `0x0010` grouping, the block-`0x78` serial layout,
the `0x9400` entry layout, the GET reply builder + reply-shape model, and the
lone-14/17 "silence" — see §6, §5, §7, §8.)

- **3-byte entry layout `0x9c00` (VLAN config)** — reply-side length known from the
  client parser; field layout still inferred only. (`0x9400`'s layout is now
  live-confirmed as `{port u8, BE16}` — §6 — but all 8 live entries read `0x0100`,
  whose meaning is unknown.)
- **Status `0x0f` auth-fail** — a client-side meaning, still never observed on the
  wire; the observed auth-failure signaling is status `0x0d` + failing tag +
  expected-token payload (§5), or silence under lockout.
- **Block `0x74` semantics** — still opaque: live replies `00 00 00 18 7f fc ff ff`
  and a mostly-zero dump containing `18 7f`, uninterpreted beyond the client's
  string + flag handling. (Block `0x30` is resolved — `0x3000` PVID per port,
  live-dumped, §6; block `0x0c` is resolved — speed/link status, §6.)
- **Request cmd `0x02`** — firmware accepts only 1/3 (else status 2); Wikipedia
  lists op codes 1–4, consistent with the cmd+1 echo model, but whether a distinct
  cmd-2 request exists in some client generation is unknown.
- **Fine nonce-roll trigger** — the nonce rolls after every authenticated SET and also
  under GET-only traffic (two serves 12 s apart with no SETs; three distinct nonces
  in ~18 s) `[live]`; whether each `0x17` read rolls it or a short timer does is
  unpinned — either fits, and it is irrelevant for correctness (re-read before every
  SET, §5).
- **Anti-replay exact drop rule** — recycled sequences get silently dropped `[live]`,
  but the precise window contradicts simple stored±2 models; needs a firmware decode
  of the seq check or more live data.
- **Password-cipher key identity** — M = switch MAC / N = nonce is inferred from
  runtime-initialized globals, not proven.
- **The 13:07-vs-13:21 tail-shape anomaly (academic)** — at 13:07 the strict client
  accepted lone `0x03`/`0x14`/`0x17` gets byte-identical to the ones it dropped at
  13:21; had the `00 00` phantom tail been unconditional, the 13:07 replies would have
  truncated too. The tail's presence is state/time-dependent (fresh-boot state is a
  candidate). Academic now — the client tolerates both tail shapes and the
  truncation-drop model is live-confirmed (§8); not worth further RE.

## 11. Client implementations in this repo

`tools/nsdp-probe` is the live wire instrument used to produce and validate everything
marked `[live]` in this document: discovery and attribute/block sweeps, the login
chain (with the 3-strike lockout warning), and the system-name SET experiment —
run it with `go run ./tools/nsdp-probe` (flags documented in its source). The
production client is the Go library `internal/nsdp`: header/TLV encoding and reply
parsing (`wire.go`), token derivation (`token.go` — implements the §5 formulas
verbatim), and a `Client` with the client-faithful retry/window policy of §2; its
package documentation (`doc.go`) summarizes the evidence trail. ROUND 13's client
updates are part of that trail: `ParseReply` accepts truncated TLV tails
(`Reply.Truncated` flag + a verbose acceptance log — live-proven by the ROUND-13b
battery, §8), and the `0x0012` decode was reclassified from `u8` (a wrong
ProSafeLinux-derived label) to the string-class login composite marker, rendered via
the `0x0011` blob renderer (display names: `0x0011` "login info blob", `0x0012`
"login composite marker"). The `nsdpctl` CLI is documented separately and
deliberately not described here.
