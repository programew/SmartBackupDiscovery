# SmartBackupDiscovery 3.6 Security Guidance

## Security boundary

SmartBackupDiscovery is a discovery and assessment tool. It does not back up, modify, upload or delete discovered files.

`network-discover` is a separate, pre-credential inventory phase. It sends only bounded ICMP and selected TCP connection probes, performs reverse-DNS enrichment, and reads local route/neighbor state. That stage does not authenticate, enumerate shares, start SSH/SFTP sessions or inspect file metadata. In 3.6 the operator can explicitly enable a separate follow-up file scan with the GUI checkbox, `network.autoStartFileDiscovery` in settings, or `--auto-discover`. It uses the configured accounts and shares/roots only for live service hosts found inside the current inventory scope. Exclusions apply to both stages; passive hints and cached-only hosts are never automatic file targets. Empty/failed/cancelled inventory never falls back to local roots or previous host lists. `--no-auto-discover` overrides the saved choice for one CLI run.

## Network scope and authorization

- Automatic active scope is limited to connected RFC1918 IPv4 networks and reasonably sized directly connected private routes.
- Explicit CIDRs are rejected unless `--authorized-scope` is present, and public-address CIDRs are always rejected.
- Routed private networks, broad on-link networks and out-of-scope neighbor-cache observations are passive suggestions only. They are not probed unless an authorized operator reviews and explicitly supplies the CIDR.
- `--exclude-cidr`, `--max-hosts`, per-probe timeout, concurrency, probe-start rate and CPU/network policies bound the operation.
- A TCP connect result is only a service hint and does not prove the operating system. Enabling automatic follow-up is the operator choice to use the configured credentials for eligible hosts in the selected scope; enable it only for systems you manage.
- ARP/neighbor records may be stale or misleading. Results marked `NeighborCacheOnly` and suggested scopes require human review.
- No interface address, subnet mask, route, default gateway, firewall policy or VLAN configuration is changed.

Ordinary host-side discovery cannot prove the existence of a completely silent secondary range when the scanner has no matching interface/route, neighbor entry, DNS record or other authorized telemetry. Do not treat absence from the inventory as proof that no other subnet exists.

Remote Windows access is limited to explicitly supplied SMB hosts/shares. Remote Linux access is limited to explicitly supplied SSH/SFTP hosts and absolute roots. The Linux SFTP implementation does not create an SSH shell, execute commands, upload files or download file contents.

## Linux SSH credentials

`root` credentials are technically accepted when intentionally authorized by the system owner. For routine customer deployments, prefer a dedicated read-only account scoped to the required roots. Do not grant sudo solely for SmartBackupDiscovery.

Passwords can be read from a hidden prompt, stdin, direct command-line arguments, or saved encrypted settings. They are not intentionally written to manifests, history, or reports. `--password`, `--linux-password`, and `--config-passphrase` place secrets in process arguments and potentially shell history; use the corresponding `-stdin` options or a hidden prompt where that exposure matters. Managed strings can remain transiently in process memory until garbage collected; use SSH keys or an external protected secret workflow where that threat matters.

The GUI saves a shared settings file only after the user chooses a path or starts a scan. Password storage is opt-in and uses a passphrase-derived AES-256-GCM key (PBKDF2-HMAC-SHA256, 600,000 iterations, random salt and nonce). The JSON contains encrypted credentials, salt, nonce, and authentication tag; the passphrase is never stored. The same file and passphrase can be used across supported operating systems. Possession of both enables decryption, so store them separately. Settings still disclose target hosts, paths, and usernames; keep them out of source repositories and protect their directory. Direct password arguments and password-stdin options override saved credentials. A file in the older Windows-only settings format must be recreated with this portable format.

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

Network inventory JSON/CSV and generated target lists may reveal IP addresses, hostnames, MAC addresses and service hints. Protect these outputs as infrastructure inventory. Generated SMB/SFTP lists are candidates for review, not authorization records.
