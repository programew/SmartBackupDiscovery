# QA Notes — 3.2.0

## Changed behavior

- Project now multi-targets `net10.0` and `net10.0-windows`.
- Linux local scanning uses explicit/default roots and does not perform remote SSH/SFTP operations.
- Linux path comparisons are case-sensitive.
- Linux traversal skips virtual/runtime filesystems and child mounts by default.
- JVM source inference is platform-separator independent.
- Linux service configs are metadata-classified; common live service-data roots become logical backup sets.
- Linux CPU throttling reads aggregate host counters from `/proc/stat`.

## Security review focus

- No new network-discovery, credential-search, remote-execution, copy, delete, upload, decryption or backup capability was introduced.
- Windows SMB credential path remains unchanged except for platform gating in `Program.cs`.
- Linux service classification does not inspect configuration contents.
- Database service-data sets explicitly warn that raw live files may not constitute a consistent backup.

## Build note

The sandbox did not have a .NET SDK installed. An attempt to retrieve the official .NET 10.0.302 Linux SDK binary was blocked by the sandbox download/content-type policy, and direct container networking is disabled. Therefore a real `dotnet build` could not be completed here.

Run before production:

```bash
./build-linux.sh
```

and on Windows:

```powershell
.\build.ps1
```
