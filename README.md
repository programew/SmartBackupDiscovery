# SmartBackupDiscovery 3.3 — .NET 10 Customer Edition

SmartBackupDiscovery is a **discover-only backup-readiness and important-data inventory scanner** for Windows and Linux.

It is designed to answer questions such as:

- What data on this machine or server is likely to be important for backup?
- Which source-code projects, database sets, VM images and protected documents exist?
- How much data should be considered *must-copy* backup material?
- Which important paths are not represented in the current backup inventory?
- What changed since the previous scan?
- Can the scan run without saturating CPU, disk or network resources?

SmartBackupDiscovery **does not perform the backup itself**. It discovers, classifies, measures and reports.

---

## Highlights

- Local Windows discovery
- Local Linux discovery
- Authorized remote Windows discovery over SMB
- Authorized remote Linux discovery over SSH/SFTP
- Explicit host allowlists only — no CIDR sweep or automatic network discovery
- CPU-aware adaptive throttling
- Global network bandwidth limiting
- Per-host network limiting
- Adjustable I/O buffer size and adaptive delay
- Java/JVM source fast-path for large Maven/Gradle/source trees
- Source-project detection for multiple development ecosystems
- Database and Linux service backup-set detection
- Protected/encrypted Microsoft Office candidate detection for local/SMB scans
- Must-Copy file count and estimated size
- Backup Readiness Score
- Backup Gap Analysis
- Scan history and diff
- HTML management report and PDF-style summary
- Privacy-mode reporting
- Windows GUI/dashboard
- Cross-platform .NET 10 CLI

---

# Safety model

SmartBackupDiscovery is intentionally **Discover-only**.

It does not:

- copy candidate files;
- modify discovered files;
- upload files;
- automatically discover hosts by scanning IP ranges;
- enumerate arbitrary network ranges;
- search files for passwords, tokens or connection strings;
- execute arbitrary shell commands on remote Linux systems;
- store supplied SMB/SSH passwords in the manifest, history or reports.

Remote scans must target systems and paths that the operator is explicitly authorized to inspect.

See [SECURITY.md](SECURITY.md) for deployment guidance.

---

# Requirements

## Windows

For development/build:

- Windows 10/11 or Windows Server
- .NET 10 SDK

For a published self-contained build, a separately installed .NET runtime may not be required depending on the publish profile used.

## Linux

For development/build:

- .NET 10 SDK
- a supported Linux distribution

The CLI is cross-platform. The WinForms GUI is Windows-only.

---

# Build

## Windows

From PowerShell:

```powershell
.\build.ps1
```

The Windows target includes the GUI.

## Linux

```bash
chmod +x build-linux.sh
./build-linux.sh
```

The Linux build produces the CLI target without requiring the Windows Desktop targeting pack.

---

# Quick start — Windows

## Start the GUI

Run the Windows executable without arguments:

```powershell
SmartBackupDiscovery.exe
```

or explicitly:

```powershell
SmartBackupDiscovery.exe gui
```

The GUI can be used to configure local discovery, Windows SMB targets, Linux SFTP targets, resource limits and reporting.

## Scan a local drive

```powershell
SmartBackupDiscovery.exe discover --root D:\
```

Scan several roots:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\Projects `
  --root E:\Documents `
  --root F:\VMs
```

Specify the manifest path:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\ `
  --manifest .\reports\server01-manifest.json
```

---

# Resource control and throttling

Large discovery jobs should not monopolize a production server. SmartBackupDiscovery includes adaptive resource controls.

## CPU limit

```text
--max-cpu N
```

Default:

```text
75
```

Example — try to keep scanner activity below approximately 50% CPU pressure:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\ `
  --max-cpu 50
```

The resource governor adapts scan delay according to observed host CPU load. `--max-cpu` is therefore a **governor target**, not a hard OS scheduler quota.

## Global network limit

```text
--network-mbps N
```

Default:

```text
80 Mbps
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --hosts-file .\machines.txt `
  --username "DOMAIN\backupscan" `
  --network-mbps 30
```

## Per-host network limit

```text
--per-host-mbps N
```

Default:

```text
40 Mbps
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --hosts-file .\machines.txt `
  --username "DOMAIN\backupscan" `
  --network-mbps 80 `
  --per-host-mbps 15
```

This is useful when several remote machines are being inspected and no single host should consume the available scan bandwidth.

## I/O buffer size

```text
--io-buffer-kib N
```

Default:

```text
256 KiB
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\ `
  --io-buffer-kib 128
```

## Maximum adaptive delay

```text
--max-adaptive-delay-ms N
```

Default:

```text
80 ms
```

Example for a busy server:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\ `
  --max-cpu 45 `
  --max-adaptive-delay-ms 250
```

## Conservative production example

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\Data `
  --max-cpu 45 `
  --network-mbps 25 `
  --per-host-mbps 10 `
  --io-buffer-kib 128 `
  --max-adaptive-delay-ms 200
```

---

# Traversal safety limits

Large environments can be bounded explicitly.

```text
--max-files N
--max-directories N
--max-depth N
```

Defaults:

```text
max-files       5,000,000
max-directories 1,000,000
max-depth       128
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\ `
  --max-files 1000000 `
  --max-directories 200000 `
  --max-depth 64
```

---

# Authorized Windows SMB discovery

Remote Windows discovery is Windows-only and requires explicit hosts/shares.

There is no automatic network discovery.

## Single host

```powershell
SmartBackupDiscovery.exe discover `
  --host FILESERVER01 `
  --remote-share D$ `
  --username "DOMAIN\backupscan"
```

The password is requested interactively and is not written to the manifest.

## Multiple shares

```powershell
SmartBackupDiscovery.exe discover `
  --host FILESERVER01 `
  --remote-share C$ `
  --remote-share D$ `
  --username "DOMAIN\backupscan"
```

## Hosts file

Example `machines.txt`:

```text
PC01|C$
PC02|C$;D$
FILESERVER01|Data;Projects
```

Run:

```powershell
SmartBackupDiscovery.exe discover `
  --hosts-file .\machines.txt `
  --username "DOMAIN\backupscan"
```

## Password through stdin

For controlled automation:

```powershell
Get-Content .\password.txt | SmartBackupDiscovery.exe discover `
  --hosts-file .\machines.txt `
  --username "DOMAIN\backupscan" `
  --password-stdin
```

Avoid persistent plaintext password files in production. Prefer a protected secret source where possible.

## Delay between hosts

```text
--host-delay-ms N
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --hosts-file .\machines.txt `
  --username "DOMAIN\backupscan" `
  --host-delay-ms 1500
```

---

# Authorized remote Linux discovery from Windows

SmartBackupDiscovery can inspect explicitly allowlisted Linux servers from Windows using SSH/SFTP.

Remote Linux mode is **metadata-only**:

- directory listing and metadata are read;
- source files are not downloaded;
- no SCP upload/download is performed;
- no arbitrary SSH command is executed;
- symbolic links are not followed;
- only explicit hosts and absolute roots are traversed.

## Root/password example

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host 192.168.1.40 `
  --linux-root /home `
  --linux-root /srv `
  --linux-root /etc `
  --linux-root /var/lib `
  --linux-username root `
  --ssh-trust-on-first-use
```

The Linux SSH password is requested using a hidden prompt.

A dedicated least-privilege account is recommended for routine operation, although `root` can be used when intentionally authorized by the server owner.

## Host-key verification

For stronger first-contact verification, obtain the host fingerprint through an independent trusted channel:

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host linux01.example.local `
  --linux-root /srv `
  --linux-username backup-discovery `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT'
```

Unknown hosts fail closed unless a fingerprint is supplied or TOFU is explicitly enabled with:

```text
--ssh-trust-on-first-use
```

## SSH private key

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host linux01 `
  --linux-root /srv `
  --linux-username backup-discovery `
  --ssh-key C:\Keys\backup-discovery_ed25519 `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT'
```

For encrypted private keys:

```text
--ssh-key-passphrase-prompt
```

or in controlled automation:

```text
--ssh-key-passphrase-stdin
```

## Multiple Linux servers

Example `linux-machines.txt`:

```text
linux01|/home;/srv;/etc|SHA256_BASE64_FINGERPRINT
192.168.1.41|/opt;/var/www;/var/lib|SHA256_BASE64_FINGERPRINT
```

Run:

```powershell
SmartBackupDiscovery.exe discover `
  --linux-hosts-file .\linux-machines.txt `
  --linux-username backup-discovery
```

The file is an explicit allowlist. CIDR ranges and wildcard host discovery are not accepted.

## SSH options

```text
--ssh-port N
--ssh-timeout-seconds N
--ssh-host-key-sha256 FP
--ssh-known-hosts PATH
--ssh-trust-on-first-use
```

Default SSH port is `22` and default connection timeout is `30` seconds.

---

# Local Linux discovery

The same scanner core runs locally on Linux.

Example:

```bash
dotnet SmartBackupDiscovery.dll discover \
  --root /home \
  --root /srv \
  --root /var/www
```

On Linux, SmartBackupDiscovery uses case-sensitive path handling and avoids virtual/runtime paths such as:

```text
/proc
/sys
/dev
/run
```

by default.

It also avoids blindly crossing filesystem boundaries unless explicitly requested.

## Cross filesystem boundaries

```bash
dotnet SmartBackupDiscovery.dll discover \
  --root /mnt/data \
  --cross-filesystems
```

## Include system mounts

```text
--include-system-mounts
```

Use this only when the additional mounted/runtime filesystems are intentionally in scope.

---

# Java/JVM performance optimization

Large source trees can contain hundreds of thousands of files. Opening every `.java` file merely to determine its type is expensive, especially over SMB/SFTP.

SmartBackupDiscovery therefore includes a JVM project fast-path.

Recognized indicators include:

- `pom.xml`
- `build.gradle`
- `build.gradle.kts`
- `settings.gradle`
- `settings.gradle.kts`
- `gradle.properties`
- `gradlew`
- `mvnw`
- Ant/Ivy metadata
- Android project metadata
- standard JVM source layouts such as `src/main/java`
- Kotlin
- Scala
- Groovy

Typical generated/dependency paths are excluded from project source volume calculations, including:

```text
target/
build/
.gradle/
out/
classes/
generated/
generated-sources/
generated-test-sources/
```

The manifest reports performance counters such as:

- JVM projects detected;
- project fast-path files;
- signature probes avoided;
- generated directories skipped.

---

# Source-project discovery

SmartBackupDiscovery detects source/project trees using project markers and source-layout heuristics rather than treating every source file as an unrelated document.

This reduces I/O and produces project-level backup candidates.

Project source is included in the Must-Copy estimate while common build/generated output is excluded.

---

# Database and service data

SmartBackupDiscovery can identify database-related backup candidates and Linux service data sets.

For live service data, the scanner may report that an **application-aware backup** or consistent snapshot is required rather than recommending blind copying of raw database files.

Examples include service-data patterns associated with:

- PostgreSQL
- MySQL/MariaDB
- Redis
- virtualization/libvirt data
- persistent container volumes

The scanner remains an inventory/readiness tool; it does not stop services or create database dumps.

---

# Protected Office documents

For local and Windows SMB scans, Microsoft Office files can be inspected for protection/encryption indicators.

Disable this behavior with:

```text
--no-office-protection
```

Remote Linux SFTP mode does not download file contents, so Office protection detection is not performed on remote SFTP files.

---

# Inspection profiles

```text
--profile balanced
--profile deep
```

Default:

```text
balanced
```

Example:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\Data `
  --profile deep
```

Use `deep` when additional inspection is more important than scan speed.

---

# Must-Copy estimate

The final output includes an estimate of the data that should be treated as required backup material.

Example summary:

```text
Candidates: 18,472 / 29,431,223,004 bytes
Must-copy estimate: 13,812 files / 21,773,551,104 bytes
Projects: 37; JVM projects: 14
Fast-path files: 182,906; signature probes avoided: 181,774
Backup readiness: 82/100 (B), confidence High
```

The estimate can include:

- project source trees;
- standalone Critical/MustInclude files;
- protected Office candidates;
- other high-value backup candidates.

Generated/build/dependency output is excluded where appropriate and duplicate counting is avoided.

Linux database/service sets that should use application-aware backup are reported separately rather than being blindly classified as raw-copy targets.

---

# Backup inventory and Gap Analysis

An existing backup inventory can be compared with discovered important data.

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\Data `
  --backup-inventory .\backup-inventory.json
```

Supported inventory formats include JSON, CSV and TXT according to the parser rules in the project.

The resulting Gap Analysis can identify:

- important data already covered;
- potentially uncovered data;
- uncovered Critical candidates;
- uncovered High-priority candidates;
- uncovered project/database sets;
- covered vs. uncovered estimated bytes.

See `backup-inventory.example.json` for an example.

---

# Backup Readiness Score

After discovery, SmartBackupDiscovery calculates a Backup Readiness score from `0–100` with a grade.

The score considers factors such as:

- scan coverage;
- remote access success/failure;
- operational scan health;
- discovered Critical data;
- backup inventory coverage when supplied.

The score is intended as an operational summary, not a guarantee that a backup is restorable.

---

# Scan history and change tracking

History is enabled by default.

Each compatible scan can be compared with a previous snapshot.

The resulting diff includes:

- added files;
- changed files;
- removed files;
- added bytes;
- removed bytes;
- selected top changes.

## Custom history directory

```text
--history-dir PATH
```

## Retention

```text
--history-retain N
```

Default:

```text
30
```

## Disable history

```text
--no-history
```

## Compare two manifests manually

```powershell
SmartBackupDiscovery.exe compare `
  .\old-manifest.json `
  .\new-manifest.json
```

---

# Reports

Generate reports during discovery:

```powershell
SmartBackupDiscovery.exe discover `
  --root D:\Data `
  --report-dir .\report
```

Or generate a report from an existing manifest:

```powershell
SmartBackupDiscovery.exe report `
  .\discovery-manifest.json `
  --output-dir .\report
```

Reports include management-oriented summaries such as:

- Backup Readiness;
- Critical/High counts;
- candidate volume;
- Must-Copy volume;
- projects;
- Linux service backup sets;
- scan health;
- backup gaps;
- history/diff information.

## Privacy mode

```text
--privacy-mode
```

Example:

```powershell
SmartBackupDiscovery.exe report `
  .\discovery-manifest.json `
  --output-dir .\report `
  --privacy-mode
```

Privacy mode reduces exposure of sensitive path/user information in management reports.

---

# Output manifest

Default manifest filename:

```text
discovery-manifest.json
```

Override it with:

```text
--manifest PATH
```

The manifest contains discovery metadata, classifications, project/service sets, performance statistics, volume estimates and assessment information.

Credentials are not intentionally written to the manifest.

---

# Windows production examples

## Local workstation with low CPU impact

```powershell
SmartBackupDiscovery.exe discover `
  --root C:\Users `
  --max-cpu 40 `
  --max-adaptive-delay-ms 200 `
  --report-dir .\report
```

## File server over SMB

```powershell
SmartBackupDiscovery.exe discover `
  --host FILESERVER01 `
  --remote-share Data `
  --remote-share Projects `
  --username "DOMAIN\backupscan" `
  --max-cpu 50 `
  --network-mbps 50 `
  --per-host-mbps 25 `
  --report-dir .\report
```

## Mixed Windows and Linux inventory

```powershell
SmartBackupDiscovery.exe discover `
  --host FILESERVER01 `
  --remote-share Data `
  --username "DOMAIN\backupscan" `
  --linux-host linux01 `
  --linux-root /srv `
  --linux-root /var/www `
  --linux-username backup-discovery `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT' `
  --network-mbps 60 `
  --per-host-mbps 20 `
  --report-dir .\report
```

---

# Linux production example

```bash
dotnet SmartBackupDiscovery.dll discover \
  --root /home \
  --root /srv \
  --root /etc \
  --max-cpu 50 \
  --max-files 2000000 \
  --max-directories 300000 \
  --report-dir ./report
```

---

# Command reference

## Commands

```text
discover [options]
report <manifest> [--output-dir DIR] [--privacy-mode]
compare <previous-manifest> <current-manifest>
selftest
gui
help
```

## Local/resource options

```text
--root PATH                  Repeatable local root
--manifest FILE              Manifest destination
--profile balanced|deep      Inspection profile
--max-cpu N                  CPU governor target; default 75
--network-mbps N             Global scan network limit; default 80
--per-host-mbps N            Per-host network limit; default 40
--io-buffer-kib N            I/O buffer; default 256 KiB
--max-adaptive-delay-ms N     Maximum governor delay; default 80 ms
--max-files N                Traversal file budget; default 5,000,000
--max-directories N          Directory budget; default 1,000,000
--max-depth N                Traversal depth; default 128
--cross-filesystems          Allow crossing filesystem boundaries
--include-system-mounts      Include normally excluded system mounts
--no-office-protection       Disable Office protection inspection
```

## Windows SMB options

```text
--host HOST
--hosts-file FILE
--remote-share SHARE
--username USER
--password-stdin
--host-delay-ms N
```

## Linux SFTP options

```text
--linux-host HOST
--linux-hosts-file FILE
--linux-root /ABSOLUTE/PATH
--linux-username USER
--linux-password-stdin
--ssh-key FILE
--ssh-key-passphrase-prompt
--ssh-key-passphrase-stdin
--ssh-port N
--ssh-timeout-seconds N
--ssh-host-key-sha256 FP
--ssh-known-hosts FILE
--ssh-trust-on-first-use
```

## Assessment/reporting options

```text
--backup-inventory FILE
--history-dir DIR
--history-retain N
--no-history
--report-dir DIR
--privacy-mode
```

Run:

```powershell
SmartBackupDiscovery.exe --help
```

for the command-line help included with the executable.

---

# Self-test

```powershell
SmartBackupDiscovery.exe selftest
```

or on Linux:

```bash
dotnet SmartBackupDiscovery.dll selftest
```

---

# Important operational notes

1. Use a least-privilege discovery account whenever possible.
2. Use `root` or administrative shares only where explicitly authorized and necessary.
3. Verify SSH host keys independently for higher-assurance deployments.
4. Protect manifests and history because file paths and infrastructure names can themselves be sensitive information.
5. A discovered database data directory is not proof that copying raw files is a safe backup method.
6. A Backup Readiness score is not a substitute for restore testing.
7. Use resource limits on production systems and large network shares.

---

# Project files

Useful repository files include:

- `SECURITY.md` — security and deployment guidance
- `CHANGELOG.md` — version changes
- `QA_NOTES_v3.3.md` — QA notes and known validation limitations
- `backup-inventory.example.json` — Gap Analysis example
- `machines.example.txt` — Windows host allowlist example
- `linux-machines.example.txt` — Linux host allowlist example
- `build.ps1` — Windows build/test/publish helper
- `build-linux.sh` — Linux build/test/publish helper

---

# License

SmartBackupDiscovery is dual-licensed under your choice of:

- **MIT License**, or
- **Apache License 2.0**

SPDX expression:

```text
MIT OR Apache-2.0
```

See:

- `LICENSE`
- `LICENSE-MIT`
- `LICENSE-APACHE`
- `NOTICE`

Copyright is attributed to **SmartBackupDiscovery contributors**.
