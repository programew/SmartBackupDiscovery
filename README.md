# SmartBackupDiscovery 3.3 — .NET 10 Customer Edition

Discover-only inventory and backup-readiness scanner for Windows and Linux. It identifies important files, source projects, database/service backup sets and protected Office candidates without performing a backup itself.

## New in 3.3: Authorized Remote Linux SFTP

A Windows scanner can now inspect explicitly allowlisted Linux servers through SSH/SFTP using either username/password or an SSH private key. `root` is accepted when the server owner has intentionally authorized that account, although a dedicated least-privilege read account is recommended for normal deployments.

Remote Linux mode is deliberately metadata-only:

- no network discovery, CIDR sweep or wildcard host expansion;
- no SSH shell commands or remote command execution;
- no file upload/download/copy;
- no remote file-content inspection;
- only explicitly supplied hosts and absolute roots are traversed;
- symbolic links are not followed;
- host-key verification fails closed unless an expected fingerprint is known or TOFU is explicitly selected.

Because remote content is not downloaded, encrypted/protected Office detection is available for local/SMB content inspection but not for remote SFTP files. Remote Linux classification uses path, filename and SFTP metadata.

## Windows GUI

Run the Windows build without arguments or use:

```powershell
SmartBackupDiscovery.exe gui
```

The Discover tab includes local roots, Windows SMB targets and Linux SSH/SFTP hosts. Linux password input is transferred to the child CLI through stdin rather than command-line arguments.

## Remote Linux with root/password from Windows

First connection with explicit trust-on-first-use:

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host 192.168.1.40 `
  --linux-root /home `
  --linux-root /srv `
  --linux-root /etc `
  --linux-username root `
  --ssh-trust-on-first-use
```

The password is requested with a hidden console prompt. The observed host-key fingerprint is stored in SmartBackupDiscovery's known-hosts file. Later connections must match it.

For stricter first-contact verification, obtain the server fingerprint through an independent trusted channel and use:

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host linux01.example.local `
  --linux-root /home `
  --linux-username backup-discovery `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT'
```

Password through stdin for automation:

```powershell
Get-Content .\linux-password.txt | SmartBackupDiscovery.exe discover `
  --linux-host linux01 `
  --linux-root /srv `
  --linux-username root `
  --linux-password-stdin `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT'
```

Avoid persistent plaintext password files in production. Prefer a protected secret provider or SSH key.

## SSH private key

```powershell
SmartBackupDiscovery.exe discover `
  --linux-host linux01 `
  --linux-root /srv `
  --linux-username backup-discovery `
  --ssh-key C:\Keys\backup-discovery_ed25519 `
  --ssh-host-key-sha256 'BASE64_FINGERPRINT'
```

For an encrypted key add `--ssh-key-passphrase-prompt`, or use `--ssh-key-passphrase-stdin` in controlled automation.

## Multiple Linux servers

`linux-machines.example.txt` demonstrates the format:

```text
linux01|/home;/srv;/etc|SHA256_BASE64_FINGERPRINT
192.168.1.41|/opt;/var/www|SHA256_BASE64_FINGERPRINT
```

Run:

```powershell
SmartBackupDiscovery.exe discover `
  --linux-hosts-file .\linux-machines.txt `
  --linux-username backup-discovery
```

The hosts file is an explicit allowlist. It does not accept CIDR ranges or wildcard discovery.

## Linux local mode

The same CLI remains cross-platform:

```bash
dotnet SmartBackupDiscovery.dll discover --root /home --root /srv --root /var/www
```

By default Linux local traversal avoids virtual/runtime filesystems such as `/proc`, `/sys`, `/dev` and `/run`, and does not cross filesystem boundaries unless requested. Remote SFTP cannot reliably identify mount boundaries from portable SFTP metadata, so only its explicit roots plus built-in pseudo/runtime exclusions are enforced.

## Java/JVM performance

Java/JVM source trees are recognized through Maven, Gradle, Ant, Android and standard source layouts including `src/main/java`, Kotlin, Scala and Groovy. Project fast-path avoids signature reads for ordinary source files and excludes generated/dependency directories such as `target`, `build`, `.gradle`, `out`, `classes` and `generated-sources`.

Remote SFTP keeps the same metadata-only project fast path: it lists filesystem metadata but does not download `.java` or other source files.

## Must-Copy estimate

The final manifest/report includes:

- candidate volume;
- must-copy file count and estimated size;
- project source count/size, excluding generated/dependency directories;
- standalone Critical/MustInclude files;
- Linux service backup sets that require application-aware or consistent-snapshot backup rather than blind raw-file copying.

SmartBackupDiscovery never performs the copy itself.

## Reports and customer features

v3.3 retains the v3 product features:

- Windows GUI and dashboard;
- Backup Readiness Score;
- scan history and diff;
- Backup Gap Analysis from JSON/CSV/TXT inventory;
- HTML management report and PDF-style summary;
- privacy-mode report masking;
- CPU/network policy for local/SMB scanning;
- checkpoints and explicit traversal budgets.

## Key CLI options

Run `SmartBackupDiscovery.exe --help` for the full list. Remote Linux options include:

```text
--linux-host <host|IP>
--linux-hosts-file <path>
--linux-root <absolute-path>
--linux-username <user>
--linux-password-stdin
--ssh-key <path>
--ssh-key-passphrase-stdin
--ssh-key-passphrase-prompt
--ssh-port <1-65535>
--ssh-timeout-seconds <n>
--ssh-host-key-sha256 <fingerprint>
--ssh-known-hosts <path>
--ssh-trust-on-first-use
```

## Build

Requires .NET 10 SDK. The project references `SSH.NET` 2026.0.0 for SFTP transport.

Windows:

```powershell
.\build.ps1
```

Linux CLI:

```bash
chmod +x build-linux.sh
./build-linux.sh
```

See `SECURITY.md`, `CHANGELOG.md` and `QA_NOTES_v3.3.md` before production deployment.

## License

SmartBackupDiscovery is available under your choice of the **MIT License** or the **Apache License 2.0** (`MIT OR Apache-2.0`). See `LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE`.

Copyright is attributed to **SmartBackupDiscovery contributors**; no personal author identity is required by this repository.
