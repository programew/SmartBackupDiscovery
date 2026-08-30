# SmartBackupDiscovery 3.3 Security Guidance

## Security boundary

SmartBackupDiscovery is a discovery and assessment tool. It does not back up, modify, upload or delete discovered files.

Remote Windows access is limited to explicitly supplied SMB hosts/shares. Remote Linux access is limited to explicitly supplied SSH/SFTP hosts and absolute roots. The Linux SFTP implementation does not create an SSH shell, execute commands, upload files or download file contents.

## Linux SSH credentials

`root` credentials are technically accepted when intentionally authorized by the system owner. For routine customer deployments, prefer a dedicated read-only account scoped to the required roots. Do not grant sudo solely for SmartBackupDiscovery.

Passwords are read from a hidden prompt or stdin and are not intentionally written to manifests, history, reports or command-line arguments. Managed strings can remain transiently in process memory until garbage collected; use SSH keys or an external protected secret workflow where that threat matters.

Private-key paths may be supplied on the command line; private-key contents are not copied into output artifacts.

## SSH host-key verification

Remote Linux discovery fails closed when the server key is not already known and no expected SHA-256 fingerprint was supplied. `--ssh-trust-on-first-use` must be explicitly selected to accept a previously unknown key. TOFU protects later connections from silent key changes but does not authenticate the first connection against an independent authority.

For higher assurance, verify the server fingerprint through a separate trusted channel and pass it with `--ssh-host-key-sha256` or per host in `--linux-hosts-file`.

The SmartBackupDiscovery known-hosts store rejects reparse/symlink-style redirection on supported host filesystems during read and write. Protect the user profile and the known-hosts file with normal OS access controls.

## Remote traversal

- Hosts must be explicit hostnames/IP addresses; CIDR, wildcard and range expansion are rejected.
- Remote roots must be absolute Unix paths.
- SFTP symbolic links are not followed.
- `/proc`, `/sys`, `/dev`, `/run` and known container overlay/runtime trees are skipped by default.
- SFTP does not provide a portable, reliable mount-device identity equivalent to local `stat`; therefore `--cross-filesystems` cannot guarantee remote mount-boundary enforcement. Use narrowly scoped explicit roots for remote Linux.
- Traversal budgets (`--max-files`, `--max-directories`, `--max-depth`) apply to remote Linux scans.

## Metadata-only limitation

Remote Linux SFTP mode deliberately avoids reading file contents. This means signatures, Office encryption/protection internals and other content-derived signals are not evaluated remotely. Reports label these results `REMOTE_METADATA_ONLY` so they are not confused with local content inspection.

## Live databases and service data

Standard live service directories such as PostgreSQL/MySQL are represented as logical application-aware backup sets. The tool does not claim that blindly copying live database files constitutes a consistent backup.

## Output protection

Manifests, histories and reports may reveal sensitive filenames, server names and directory structure. Store them with access controls appropriate for backup inventory. Use `--privacy-mode` for management reports when paths should be masked.
