// Package gs108tv2 implements the GS108Tv2 (FASTPATH 5.4.2.36
// generation) VLAN read/apply flow over the emweb text-config channel
// served by internal/fastpath.
//
// The flow is save → mutate → restore → read-back:
//
//   - Every read/apply starts with its own fresh SaveConfig. The driver
//     NEVER caches the parsed config or file bytes between operations:
//     two resource types share one startup-config file, and a cached
//     copy would silently revert the other resource's staging.
//   - Applies are STAGE-ONLY by default: ConfigRestore writes the
//     startup-config and does NOT reboot the switch. Verification is
//     structural: the re-fetched (uptime-canonical) startup-config must
//     parse to the desired state. Byte comparison is never the truth —
//     the re-fetched CanonicalBytes divergence from the uploaded bytes
//     is a WARNING signal only (ApplyOutcome.CanonicalDiverged).
//   - After a successful restore the switch has a ~2-minute transient
//     ingest window: logins are refused outright and fetches can come
//     back mangled (observed "!x4e47…" first-line corruption →
//     ValidateTextConfigHeader failure). Reads in that window are
//     RETRYABLE, never drift. See waitTransientAndVerify.
//   - Only `vlan database` and `interface 0/1`..`interface 0/8` are
//     managed. `interface 3/x` sections (CPU/LACP) and the whole
//     `configure` preamble are immutable; foreign (non-vlan) body
//     lines inside managed sections are preserved on edit.
package gs108tv2
