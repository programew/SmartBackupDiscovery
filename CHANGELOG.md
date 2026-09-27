# Changelog

## 3.6.0

Released 2026-09-27.

- Added **Start file discovery automatically after network discovery** to the Windows GUI. The opt-in setting is saved in the portable shared configuration; existing configurations keep it off.
- Added `network-discover --auto-discover` and `--no-auto-discover`; the CLI also honors `network.autoStartFileDiscovery` in `--config`. Connection, credential, resource and report options are reused for the follow-up scan.
- Automatic file discovery uses only this run's in-scope, non-excluded IP addresses with an open configured service port. Hosts are deduplicated; unknown/cached-only hosts and unconfigured transports are skipped. Both SMB and SFTP can run for a mixed-service host.
- Preserved target separation: saved local roots, previous host lists and hosts files do not enter automatic scans. Empty results never trigger a local-drive scan. Manual discovery remains available.
- Added a shared GUI busy state and Stop buttons. Concurrent network/file runs are blocked; stopping or failing inventory prevents the next stage. Closing the GUI stops its active child process.
- Do not load old outputs after a failed network run. File results/reports are shown only when produced by the current run, including fresh partial file results with errors.
- Validate connection settings and reject overlapping network/file output paths before starting an automatic workflow. The configured SSH port is probed in automatic mode when no CLI probe-port override is supplied.
- The manual **Use reviewed targets** action now clears obsolete host entries and hosts-file selections.
- Build scripts now stop on PowerShell native-command failures; Linux publish restores its runtime-specific assets.
- Added six deterministic regression tests for persisted flags, target isolation, exclusions/deduplication/custom SSH ports, failure/empty/cancel gates, single handoff and returned exit codes, and invalid configuration/output collisions.

## 3.5.0

- Moved the file-discovery start button into a persistent toolbar and opened the Discover files tab by default.
- Added an editable Windows-host list to the GUI alongside the existing hosts-file option; reviewed network candidates populate that list.
- Added shared JSON settings for GUI and `discover --config` / `network-discover --config`, including target lists, outputs, resource limits, and network scope settings.
- GUI saves settings before starting either discovery workflow and can explicitly save/reload a chosen settings file.
- Optional password persistence uses passphrase-derived authenticated encryption portable between operating systems; the passphrase is not stored in JSON. Added direct `--password`, `--linux-password`, `--config-passphrase` arguments and corresponding stdin alternatives. Direct credentials take priority over saved passwords; command-line secrets can be exposed in process lists/history.
- Linux CLI skips Windows SMB targets and Windows-only paths from a copied GUI settings file; when no compatible configured targets remain, it reports an error instead of scanning implicit local defaults.

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
