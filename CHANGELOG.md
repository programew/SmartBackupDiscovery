# Changelog

## 3.4.0

- Added controlled `network-discover` / `network-inventory` private-IPv4 host inventory.
- Added automatic connected-scope detection plus bounded directly connected route discovery.
- Added ICMP, reverse-DNS, local ARP/neighbor-cache and configurable TCP service signals; defaults are ports 22 and 445.
- Added RFC1918-only explicit CIDRs with required authorization acknowledgement, CIDR exclusions, overlap deduplication and a hard 65,536-address ceiling.
- Added probe timeout, concurrency, host-start rate, CPU and network resource limits.
- Added passive suggestions for routed/broad private routes and out-of-scope private neighbors without probing the suggested range or changing host networking.
- Added JSON/CSV inventory, deterministic platform/transport hints, generated review target lists, inventory history and change diff.
- Added a Windows GUI Network inventory tab with a review handoff to existing SMB/SFTP discovery.
- Preserved separation between host inventory and credentialed/file discovery: no authentication, share enumeration or file access occurs during network inventory.
- Fixed Linux path validation compilation and management report top-candidate rendering found by the expanded self-test suite.

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
