# GS108Tv2 live text-config captures (phase 0a pinning evidence)

Provenance: captured 2026-09-16 from the bench switch (GS108Tv2,
FASTPATH 5.4.2.36, @10.0.2.8) over the emweb HTTP channel
(internal/fastpath WebSession.SaveConfig) in four states:

| file | content |
|---|---|
| factory-live.txt | the switch's factory-state startup-config as fetched |
| vlan42-upload.txt | hand-mutated config UPLOADED via multipart restore: a COMPACT `vlan 42` declaration inserted directly after `vlan database` (no blank line between them, see lines 21–24) |
| vlan42-reserved.txt | the switch's RE-SERVED config after ingesting that upload — the declaration survived, re-serialized DOUBLE-SPACED (`vlan database\n\nvlan 42\n\nexit`) |
| factory-reverted.txt | the switch's config after reverting to the factory state |

## Live-pinned facts (phase 0a, partial)

1. **`vlan <id>` declaration template is live-pinned**: the bench
   switch accepted an uploaded `vlan 42` declaration over this channel
   and re-served it structurally intact — same line text, no
   membership lines required. See vlan42-upload.txt →
   vlan42-reserved.txt.
2. **Double-spacing normalization**: the switch IGNORES the upload's
   whitespace shape and re-serializes in its own double-spaced style
   (every content line followed by exactly one blank line). A compact
   upload therefore CANNOT verify by byte comparison — canonical
   (up-time-excluded) byte divergence after an apply is expected
   whitespace-normalization noise, which is exactly why the stage-only
   semantics verify structurally (model.Equal) and treat CanonicalBytes
   divergence as a WARNING only. This is the recorded evidence for that
   decision.
3. **Annotation drift beyond `!System Up Time`**: factory-live.txt
   carries a configure-level `snmp-server sysname " "` line and an
   `ip dhcp filtering` line that the repo-root fixture
   (startup-config-gs108t) lacks. Both sit in the configure section of
   the config, they are foreign (unmanaged) to the VLAN codec and must
   decode to the default state regardless — pinned by
   TestDecodeLiveFactoryDefaultState.

Reference: compare with ../../..(repo root)/startup-config-gs108t —
the offline factory fixture from the previous capture session; the
differences are only the annotations/lines noted above plus the live
up-time stamp.
