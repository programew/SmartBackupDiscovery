# QA Notes — 3.3.0

## Scope

v3.3 adds Authorized Remote Linux SFTP discovery from Windows/Linux scanner hosts while preserving Discover-only behavior.

## Static/security checks performed in the packaging environment

- all C# files checked for balanced delimiters, strings and comments;
- searched changed source for `SshClient`, shell-command APIs, SCP, upload/download and port-forwarding usage: none used by the remote Linux implementation;
- SFTP traversal uses explicit hosts and explicit absolute roots only;
- CIDR/wildcard/range host inputs rejected by parser;
- remote path normalization rejects root escape and invalid components;
- symbolic links are skipped;
- remote file content is not opened/downloaded;
- host-key validation is fail-closed unless a matching stored/provided fingerprint exists or TOFU is explicitly enabled;
- known-hosts reparse/symlink redirection is rejected on read/write;
- passwords are not included in `RemoteLinuxTargetReport` or manifest models;
- existing Windows SMB remote implementation was not replaced by SSH behavior.

## Self-tests added

- explicit Linux hosts-file parsing;
- rejection of CIDR and relative Linux roots;
- remote metadata classification of essential Linux config;
- case-sensitive SFTP backup coverage and host isolation;
- remote path root-escape rejection.

## Build/test limitation

The packaging sandbox does not have the .NET 10 SDK installed and its direct package/network environment did not permit a complete SDK restore/build. Therefore this package received static structural/security QA but not an actual `dotnet build` or live SSH/SFTP integration test in this environment.

Before production use, run `build.ps1` on Windows or `build-linux.sh` on Linux and test against an authorized disposable SSH server with a known host-key fingerprint. Verify password auth, key auth, permission-denied roots, host-key mismatch rejection, TOFU persistence and traversal-budget behavior.
