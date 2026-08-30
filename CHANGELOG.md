# Changelog

## 3.3.0

- Added Authorized Remote Linux discovery over SSH/SFTP from Windows or Linux scanner hosts.
- Added explicit Linux host/root allowlists, password and SSH private-key authentication.
- Added fail-closed SHA-256 SSH host-key verification plus explicit TOFU known-hosts support.
- Added remote Linux metadata-only classification, JVM project fast-path, Must-Copy estimation and Linux service backup sets.
- Remote SFTP does not execute shell commands and does not upload/download file content.
- Added mixed local/SMB/SFTP history, diff, readiness and Backup Gap path semantics.
- Hardened known-hosts file against reparse/symlink redirection.
- Updated Windows GUI with Linux host/root/credential/host-key controls.

## 3.2.0

- Added cross-platform `net10.0` Linux CLI target while retaining `net10.0-windows` GUI/SMB target.
- Added Linux default roots: `/home`, `/srv`, `/opt`, `/var/www`, `/var/lib`, `/etc` when present.
- Added Linux filesystem policy: virtual/system trees and container runtime/overlay trees skipped by default.
- Added child mount-boundary protection with explicit `--cross-filesystems` override.
- Added `--include-system-mounts` for explicit virtual/runtime traversal.
- Made filesystem path identity/comparison case-sensitive on Linux.
- Fixed JVM source-layout inference to use platform-native path semantics instead of Windows-only separators.
- Added Linux important service/host configuration metadata rules.
- Added `LinuxServiceData` logical sets for common PostgreSQL, MySQL/MariaDB, Redis, libvirt/KVM and container-volume locations with application-aware backup guidance.
- Added Linux host CPU sampling from `/proc/stat` for adaptive resource control.
- Added Linux platform/mount skip counters to manifest, console and management reports.
- Added cross-platform build scripts and Linux self-test coverage.
- Remote Linux SSH/SFTP crawling remains intentionally absent; run the CLI locally on authorized Linux hosts or scan explicitly mounted paths.

## 3.1.0

- Added Java/JVM source-tree fast path independent of Maven/Gradle markers.
- Added standard JVM layout detection and bounded loose-source-root fallback.
- Source-code extensions no longer trigger signature probing outside detected projects.
- Added Must-Copy estimate and candidate/project volume reporting.
- Added performance counters for fast-path files, avoided signature probes and JVM project detection.

## 3.0.0

- Added Windows Forms customer dashboard.
- Added scan history/diff, Backup Readiness Score and Backup Gap Analysis.
- Added HTML/PDF management reporting and privacy mode.
- Removed implicit `C$`; remote shares must be explicit.
