# SmartBackupDiscovery 3.7 — .NET 10 Customer Edition

SmartBackupDiscovery is a **discover-only backup-readiness and important-data inventory scanner** for Windows and Linux.

[Project website and sample report](https://smartbackupdiscovery.ffffffff8.chatgpt.site/) · [Download version 3.7.0 source](https://github.com/programew/SmartBackupDiscovery/releases/tag/v3.7.0)

It is designed to answer questions such as:

- What data on this machine or server is likely to be important for backup?
- Which hosts are visible on the connected private networks and may need review?
- Which source-code projects, database sets, VM images and protected documents exist?
- How much data should be considered *must-copy* backup material?
- Which important paths are not represented in the current backup inventory?
- What changed since the previous scan?
- Can the scan run without saturating CPU, disk or network resources?

SmartBackupDiscovery **does not perform the backup itself**. It discovers, classifies, measures and reports.

---

## New in 3.7: Active local ARP discovery

Network inventory now actively resolves selected addresses on connected Ethernet/Wi-Fi networks. This can find a local device even when it blocks ICMP and has no open TCP service. The Windows GUI checkbox **Use active ARP on connected networks** is enabled by default and saved as `network.useArp`; older settings retain that default. CLI `--no-arp` disables it and `--arp` re-enables it, overriding the saved choice in argument order.

Windows uses the native neighbor resolver with an explicit interface/source address. Linux sends bounded ARP requests through native packet sockets; it needs `CAP_NET_RAW` or root for this signal. No packet-capture driver or external `arping` executable is required. If the backend is unavailable, a warning is recorded and the other enabled signals continue.

ARP is limited to eligible targets in the selected, non-excluded scopes that match a connected local interface. It does not discover or probe additional ranges behind a gateway. Host concurrency, rate and resource limits still apply. Linux sends at most two ARP requests within the per-signal timeout; Windows native requests use OS retries and at most eight outstanding calls. A timed-out Windows call retains its native slot until it finishes; queued addresses are not skipped just because the slots are busy. Stop cancels pending probes; the GUI terminates the active child process.

Fresh ARP results include the MAC and interface in JSON/CSV and appear as `ArpResolved` when no IP/service signal responded. The neighbor cache is read again after probing, but cache-only entries remain `NeighborCacheOnly`. An ARP reply can come from a proxy, so it does not prove a separate device or SMB/SFTP access; repeated ARP-only addresses sharing one MAC are flagged for review. Automatic file discovery still requires an open configured service port and connection settings.

```powershell
# Default discovery includes active ARP on eligible connected networks.
SmartBackupDiscovery.exe network-discover

# ARP only, with passive cache and IP/service probes disabled.
SmartBackupDiscovery.exe network-discover --no-icmp --no-tcp-probes --no-neighbor-cache --no-dns

# Disable active ARP for this run.
SmartBackupDiscovery.exe network-discover --no-arp
```

## New in 3.6: Optional automatic file discovery

In **Discover files**, configure the Windows SMB username/password and explicit shares, and/or the Linux SSH username/password, roots, port and host-key policy. Then open **Network inventory**, select **Start file discovery automatically after network discovery**, and click **Discover network**. The checkbox is off by default and is saved with the other settings.

On success, the GUI moves to file discovery and then the dashboard. It scans only the freshly discovered hosts with an open port 445 (SMB) or the configured SSH port (default 22) and a configured username for that transport. The saved local roots, manual host lists and hosts files are ignored for this automatic run. Hosts with both services can use both configured connections. Duplicates, excluded/out-of-scope hosts, cached-only hosts and hosts without a compatible service are skipped.

The same workflow works from the CLI:

```powershell
# Explicitly enable the follow-up scan using saved connection settings.
SmartBackupDiscovery.exe network-discover --config .\settings.json --auto-discover --config-passphrase 'your-long-passphrase'

# Honor the checkbox stored in settings (supply credentials/passphrase as needed).
SmartBackupDiscovery.exe network-discover --config .\settings.json

# Override a saved enabled checkbox for this run only.
SmartBackupDiscovery.exe network-discover --config .\settings.json --no-auto-discover
```

Without a config, pass connection settings directly, for example:

```bash
dotnet SmartBackupDiscovery.dll network-discover --auto-discover \
  --linux-username backup-reader --linux-root /srv --linux-password-stdin
```

SSH still requires a previously known key, a supplied `--ssh-host-key-sha256`, or explicitly selected `--ssh-trust-on-first-use`. Automatic mode never enables TOFU by itself. On Linux, SMB transport is skipped. With no `--probe-port` override, automatic mode probes port 445 and the configured SSH port. A custom probe list must contain the required service ports for hosts to be selected.

CLI file-discovery settings (shares, Linux roots, credentials, limits, manifest, history and reports) can accompany `--auto-discover`. Explicit `--root`, `--host`, `--linux-host` and hosts-file options are rejected in automatic mode; use `discover` for those manual targets. Saved targets are ignored without modifying the config. Credential stdin lines remain in the documented order below, only for the transports actually selected; use direct password arguments or encrypted settings when a fixed multi-transport stdin sequence is unsuitable.

Failed or cancelled inventory does not start a file scan. If no compatible targets are found, the program reports that and stops; it never falls back to scanning local drives. Exit status reflects the follow-up file scan when it runs. In the GUI, **Stop** terminates the active child process and cancels the remaining stage; an incomplete file scan may leave its existing checkpoint. Settings and start buttons stay disabled while a workflow is active. Manual **Start file discovery** remains available after it ends.

The source package also includes framework-dependent builds under `binaries/windows-x64` and `binaries/linux-x64`. Windows requires the .NET 10 Desktop Runtime; Linux requires the .NET 10 runtime. Extract the entire folder so its dependency DLLs remain beside the executable. The source builds remain in `SmartBackupDiscovery/`.

## New in 3.5: Shared GUI and CLI settings

The Windows GUI opens on **Discover files** and keeps **Start file discovery** visible above the scrollable settings. Enter one authorized Windows host per line or choose a hosts file. Linux hosts and local roots also accept multiple lines; Linux hosts files remain available for per-host roots and SSH fingerprints. The **Use reviewed targets** action fills the editable Windows and Linux host lists.

The GUI saves both discovery and network-inventory settings to `%APPDATA%\SmartBackupDiscovery\settings.json` when either scan starts. **Save settings** and **Load settings** work with the path shown in the Discover files tab. The config can be reused from a command prompt:

```powershell
SmartBackupDiscovery.exe discover --config "$env:APPDATA\SmartBackupDiscovery\settings.json"
SmartBackupDiscovery.exe network-discover --config "$env:APPDATA\SmartBackupDiscovery\settings.json"
```

`--config` is explicit: running the CLI without it does not silently use saved hosts or credentials. Single-value CLI options override saved settings; repeatable hosts, roots, shares, and CIDRs are additive. If you add a CIDR on the command line to saved authorized scopes, explicitly add `--authorized-scope` again. Relative file paths in the JSON resolve against the settings file's directory.

Passwords are omitted by default. To store SMB/SSH passwords in the JSON, select **Save passwords encrypted with a portable passphrase** and enter a configuration passphrase of at least 12 characters. The JSON contains an AES-256-GCM encrypted credential envelope with a PBKDF2-HMAC-SHA256 key derivation salt and 600,000 iterations; the passphrase is never saved. On another computer or Linux CLI, use the same file and supply the passphrase to unlock the saved credentials:

```powershell
SmartBackupDiscovery.exe discover --config .\settings.json --config-passphrase 'your-long-passphrase'
```

You can supply passwords directly instead of saving them in the config: `--password <smb-password>` and `--linux-password <ssh-password>`. Direct passwords take priority over saved credentials. `--config-passphrase-stdin`, `--password-stdin`, and `--linux-password-stdin` are available when you do not want passwords visible in process arguments or shell history; when multiple stdin options are used, supply their lines in that order (only the lines actually requested). The GUI transfers scan passwords to its child CLI over stdin. Direct argument values can be visible to other local processes and in shell history, so handle them accordingly.

When moving a Windows GUI settings file to Linux, Windows SMB targets and Windows-only paths are skipped with a warning. Linux SFTP targets and portable relative paths remain usable; specify Linux local paths or output locations with CLI overrides as needed. An empty compatible target list is an error rather than an implicit local scan. Keep the JSON file and passphrase separately; the JSON still discloses hosts, paths, usernames, and network scopes.

---

## Highlights

- Local Windows discovery
- Local Linux discovery
- Controlled automatic private-IPv4 network inventory
- Connected-scope and bounded directly connected-route detection
- Passive, review-only suggestions for secondary private ranges
- Authorized remote Windows discovery over SMB
- Authorized remote Linux discovery over SSH/SFTP
- Explicit reviewed targets for all credentialed SMB/SFTP and file discovery
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
- inventory public address space;
- probe routed, unusually broad or inferred secondary ranges automatically;
- authenticate, enumerate shares or access files during network inventory;
- search files for passwords, tokens or connection strings;
- execute arbitrary shell commands on remote Linux systems;
- store supplied SMB/SSH passwords in the manifest, history or reports.

Automatic inventory is limited to private IPv4 connected scopes, bounded direct routes and explicitly authorized RFC1918 CIDRs. Credentialed remote scans must still target systems and paths that the operator is explicitly authorized to inspect.

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

# Controlled automatic network inventory

The `network-discover` phase builds a reviewable host inventory before any credentialed or file-level discovery. With no CIDR argument, it detects private IPv4 scopes connected to local interfaces and bounded directly connected routes.

```powershell
# Connected private scopes, using conservative defaults
SmartBackupDiscovery.exe network-discover

# An additional scope that the operator has verified and is authorized to inventory
SmartBackupDiscovery.exe network-discover `
  --cidr 192.168.50.0/24 `
  --authorized-scope `
  --exclude-cidr 192.168.50.1/32
```

The inventory combines limited host-presence signals:

- ICMP response;
- reverse DNS for responsive hosts;
- the scanner host's existing ARP/neighbor cache;
- configurable TCP service hints, using ports 22 and 445 by default.

Network inventory is separate from file discovery. It never supplies credentials, enumerates SMB shares, opens SFTP roots, scans files or copies data. Explicit CIDRs require `--authorized-scope`, must remain entirely within RFC1918 address space and are rejected if the final address set exceeds the configured limit.

The scanner passively inspects existing route and neighbor state for secondary private ranges. Routed or unusually broad routes and out-of-scope neighbors are written to `network-targets/suggested-private-scopes.generated.txt` for operator review and are not automatically probed. The application does not change addresses, subnet masks, routes, gateways, firewall rules or VLAN configuration.

Generated outputs include JSON and CSV inventory, inventory history/diff, and review-only SMB/SFTP candidate lists. The Windows GUI exposes the same inventory-first workflow.

See [NETWORK_DISCOVERY_GUIDE.md](NETWORK_DISCOVERY_GUIDE.md) for scope rules, limitations, load controls and output details.

---

# Authorized Windows SMB discovery

Remote Windows discovery is Windows-only and requires explicit hosts/shares.

Only hosts and shares explicitly selected by the operator are used for credentialed SMB discovery. Network-inventory candidates are not opened automatically.

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
network-discover [options]
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

## Network inventory options

```text
--cidr CIDR                  Repeatable authorized private IPv4 scope
--authorized-scope          Acknowledge authorization for explicit CIDRs
--include-local-scopes      Include detected connected private scopes
--exclude-cidr CIDR         Repeatable scope exclusion
--probe-port N              Repeatable TCP service-hint port
--no-tcp-probes             Disable TCP service hints
--no-icmp                   Disable ICMP probes
--arp                       Enable active connected-network ARP (default)
--no-arp                    Disable active ARP; passive cache is independent
--no-dns                    Disable reverse DNS
--no-neighbor-cache         Ignore existing ARP/neighbor entries
--probe-timeout-ms N        Per-signal timeout; default 600 ms
--network-concurrency N     Concurrent host-probe limit; default 32
--max-hosts N               Maximum final address count; default 4,096
--max-probes-per-second N   Host-start rate limit; default 64
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
8. Review generated network target lists before starting any credentialed discovery.

---

# Project files

Useful repository files include:

- `SECURITY.md` — security and deployment guidance
- `CHANGELOG.md` — version changes
- `NETWORK_DISCOVERY_GUIDE.md` — network-inventory scope, controls and limitations
- `QA_NOTES_v3.4.md` — QA notes and known validation limitations
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
