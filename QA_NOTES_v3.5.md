# QA Notes — 3.5.0

This source revision was reviewed statically. The authoring environment did not include a .NET 10 SDK or a Windows GUI runtime, so a build, the built-in `selftest`, and visual GUI verification have **not** been completed for v3.5. The v3.4 QA notes describe the earlier baseline only.

On a Windows development machine:

1. Run `./build.ps1` from PowerShell and confirm `selftest` succeeds.
2. Open the GUI. Verify that **Start file discovery** stays visible while scrolling the Discover files settings and that the Windows host list accepts multiple explicit hosts.
3. Save settings with password storage unchecked. Confirm the JSON contains no password value, run `discover --config <path>` with a local root, and compare paths, limits, and output with the GUI.
4. Opt in to password storage with a 12+ character passphrase and disposable test credentials. Confirm the JSON does not contain plaintext secrets. Verify `discover --config <path> --config-passphrase <value>` and the stdin passphrase variant; verify incorrect passphrases and modified ciphertext fail. Test `--password` / `--linux-password` and their stdin alternatives override stored values. Use only disposable credentials for this check.
5. Run `network-discover --config <path>` against a small authorized private scope. Confirm any additional command-line CIDR requires a fresh `--authorized-scope`.
6. Copy the configuration to a Linux machine. Verify the same passphrase unlocks saved Linux SFTP credentials, Windows SMB targets and Windows-only paths are skipped with warnings, and missing compatible targets fail rather than triggering a default local scan. Supply suitable local output paths through CLI overrides. Confirm a wrong passphrase is rejected.
7. Confirm arguments containing passwords are visible in process arguments/shell history, and use stdin or a hidden prompt if that exposure is unacceptable.
