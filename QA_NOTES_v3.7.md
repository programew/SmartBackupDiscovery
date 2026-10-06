# SmartBackupDiscovery 3.7.0 validation

Validated with the .NET 10 SDK:

- Release build for `net10.0`, with warnings treated as errors: passed, zero warnings/errors.
- Release build for `net10.0-windows`, with warnings treated as errors: passed, zero warnings/errors.
- Cross-platform selftest: 54 passed, zero failed, including 16 new deterministic ARP checks.
- Whitespace/error checks on the source diff: passed.

The new tests exercise matching and malformed ARP replies, native interop sizes,
connected-interface selection and gateway exclusions, self/broadcast exclusions,
fresh versus cached evidence, scan exclusions and overlap deduplication, portable
settings and argument overrides, complete/static neighbor filtering, cancellation,
concurrency, proxy-like responses, and JSON/CSV plus file-discovery handoff.
Selftests use injected probes and synthetic packets; they do not scan a network.

## Native behavior and limits

- Windows resolves the selected neighbor using `ResolveIpNetEntry2`, which
  refreshes that entry and sends IPv4 ARP. The native resolver cannot be aborted
  mid-call. There are at most eight outstanding native calls; they keep their
  slots until completion even after the caller timeout/cancellation. Waiting for
  a slot remains cancellable. Replies after the caller deadline may appear only
  as passive cache evidence when the cache is refreshed.
- Linux uses an interface-bound nonblocking `AF_PACKET` datagram socket, sends
  at most two requests per target within the signal timeout, validates the
  sender/target protocol addresses and destination MAC, and closes the socket
  on success, timeout, error or cancellation. Raw-packet capability is required;
  missing capability produces a fallback warning instead of failing inventory.
- Only targets within the selected, non-excluded scopes and a matching local
  Ethernet/Wi-Fi subnet are eligible for active ARP. Known more-specific routed
  targets are skipped. The selected source/interface is recorded with each result.
- ARP-only results indicate address resolution, including possible proxy ARP;
  they do not establish a distinct device or a usable SMB/SFTP service.
- The local route snapshot is advisory. Linux policy routing/VRFs and overlapping
  address spaces are not fully modeled; ordinary routing/subnet configuration
  remains under the operating system's control.

## Remaining runtime validation

This environment did not provide a physical Windows/Linux LAN test setup.
Real ARP replies, blocked-ICMP hosts, multiple adapters, proxy ARP, and Windows
GUI interaction require a LAN smoke test. Cross-compilation and synthetic tests
do not establish that those physical-network cases have been validated.
