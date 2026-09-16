// Package fastpath provides config-file transfer and text-configuration
// tooling for the NETGEAR ProSAFE "Smart Managed" switch family — the
// FASTPATH/LVL7 firmware generation (GS108Tv2/GS110TPv2 et al., e.g.
// v5.4.2.36) whose management plane is distinct from the "Plus"-line
// switches the rest of this provider targets.
//
// # Wire channels
//
// The primary channel is the switch's emweb HTTP UI (reverse-engineered
// from switchdrvr.bin's ewsFileSetupFilesystemDoc dispatcher and the
// rollover.js page scripts):
//
//	save:   POST /base/main_login.html (pwd=<password>&login.x=5&login.y=5)
//	        → SID cookie session
//	        → GET /base/system/http_file_upload.html (arming page)
//	        → GET /filesystem/startup-config
//	        The dispatcher copies nvram:startup-config to backup-config
//	        and serves the copy as text/plain.
//	restore: POST /base/system/http_file_download.html
//	        multipart/form-data with the browser field set
//	        (file_type=txtcfg, .filename_handle=<file>, submt="16",
//	        download_status, cncel, err_flag, err_msg); the re-served
//	        page carries the outcome in its hidden err_flag / err_msg /
//	        download_status fields (see RestoreResult).
//
// The dispatcher also serves /filesystem/image1 and /filesystem/image2
// as application/octet-stream, guards against ".." path traversal, and
// answers 404 — not 401 — for failed session validation.
//
// Live-measured behaviour (GS108Tv2, fw 5.4.2.36, 2026-09-16):
//
//   - SID sessions are bound to the TCP connection that created them;
//     a valid SID re-presented over a fresh connection answers bare
//     404. Keep every request of an operation on one keep-alive
//     connection (WebSession does; SaveConfig retries once on a
//     session-class status).
//   - Right after a restore POST the switch serves a ~2-minute
//     transient window: reads can race the ingest (mangled first
//     header byte) and new logins may be refused. Back off, re-login.
//   - Served config bytes are verbatim except the "!System Up Time"
//     annotation, which tracks the switch's wall clock — exclude that
//     line from byte-for-byte comparisons.
//
// The secondary channel is RFC1350 TFTP (tftp.go client,
// tftpserver.go server for switch-push flows), matching the CLI `copy`
// family (nvram:startup-config tftp://<host>/<file>). On the reference
// GS108Tv2 the TFTP port is filtered and the switch's own TFTP client
// targets the privileged port 69, so the HTTP channel is preferred.
//
// # Content validation
//
// Both channels carry the "NSDP Text Configuration" file whose header
// lines the firmware validates on restore (cliTxtCfg* strings:
// "Invalid text config header!", "Incompatible text config Firmware
// revision!"). ParseTextConfig and ValidateTextConfigHeader implement
// exactly that contract.
package fastpath
