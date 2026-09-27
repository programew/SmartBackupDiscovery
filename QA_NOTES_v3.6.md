# QA Notes — 3.6.0

Verified on 2026-09-27 with .NET SDK 10.0.101 in a Linux build environment.

## Completed

- Release builds for `net10.0` and `net10.0-windows`: succeeded, no compiler warnings or errors.
- Framework-dependent publish: Windows x64 and Linux x64 completed successfully. Included under `binaries/`.
- Built-in `selftest`: **38 passed, 0 failed**, including six automatic-workflow regression tests. The suite also checks existing classifiers, portable secret encryption and tamper rejection, CIDR handling, inventory output, history/diff, SFTP target validation and Linux path behavior.
- Five CLI smoke checks against the published Linux build: explicit automatic mode with no compatible hosts; saved automatic mode without reading obsolete saved hosts files/local roots; `--no-auto-discover` override; missing-connection validation; overlapping-output rejection. All passed. These used passive neighbor-cache lookup with TCP, ICMP and DNS disabled, so no active network probes or remote authentication were performed.
- Empty results did not produce a file manifest or invoke a local-drive fallback. Fixture-based handoff tests verify that only fresh service targets are passed once, and the file engine's exit status is returned.
- Release ZIP CRC/integrity and entry checks completed during packaging. No build intermediates, passwords, runtime scan output, test fixture output, or debug symbols are included.

## Not exercised here

Windows GUI rendering/interaction and live authenticated Windows SMB/Linux SFTP sessions require a Windows desktop and controlled remote hosts. The GUI compiled successfully; this is not a claim of visual or live-network testing.

## Windows acceptance checks

1. Open the GUI and verify the start and Stop buttons remain visible at the supported window sizes. Load a v3.5 config: the new checkbox is off unless subsequently saved as enabled.
2. Configure test SMB and/or SSH connections, enable automatic discovery and inventory a small managed scope. Check the transition from network inventory to file discovery and then dashboard. Verify hosts are contacted only with their configured transport; old manual hosts/local roots are not scanned.
3. Stop during network inventory: file discovery must not start. Stop during file discovery: the child process ends; a partial checkpoint may remain. Check remote connection cleanup as part of your Windows environment validation, because Stop terminates the child process.
4. Verify Start, settings and target-transfer controls stay disabled during either stage. Close the GUI while a test run is active and verify its child process exits.
5. Fail a run with an old output still present: that old output must not be presented as the new result. Confirm a fresh file manifest containing partial results and errors is clearly labeled as such.
6. Verify non-default SSH ports, known-key rejection, supplied fingerprints, and explicitly selected TOFU against controlled hosts.

Use `build.ps1` on Windows or `build-linux.sh` on Linux to build and run the suite again. Historical QA notes describe their corresponding releases only.
