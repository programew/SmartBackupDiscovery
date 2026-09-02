# Automatic Network Discovery Guide — SmartBackupDiscovery 3.4

## Purpose and operating boundary

The `network-discover` command builds an inventory of hosts on private IPv4 networks only. It does not use credentials, enumerate SMB shares, establish SSH/SFTP sessions, scan files, or copy data.

Its output is a set of reviewable candidates. After review, an administrator can explicitly pass approved hosts to the separate Discover phase and define the shares, roots, accounts, and SSH host-key policy to use.

## Typical use

On Windows, use the **Network inventory** tab or run:

```powershell
SmartBackupDiscovery.exe network-discover
```

Without `--cidr`, the application detects private scopes connected to local interfaces and reasonably sized directly connected routes. It collects a limited set of signals for each address:

- ICMP response;
- reverse DNS, only for responsive hosts;
- an existing entry in the scanner host's ARP/neighbor cache;
- TCP connectivity to ports 22 and 445 by default (configurable).

## Explicit authorized scopes

For a scope that you have reviewed and are authorized to inventory:

```powershell
SmartBackupDiscovery.exe network-discover `
  --cidr 192.168.20.0/24 `
  --authorized-scope
```

Multiple scopes and exclusions are supported:

```powershell
SmartBackupDiscovery.exe network-discover `
  --cidr 192.168.20.0/24 `
  --cidr 10.44.8.0/23 `
  --exclude-cidr 192.168.20.1/32 `
  --exclude-cidr 10.44.9.0/25 `
  --authorized-scope
```

Public ranges are rejected. Explicit CIDRs are also rejected unless `--authorized-scope` is present.

## Secondary or "hidden" ranges

If another IP range exists on the same physical network but the scanner host has no address or route for it, one of three cases applies:

1. **A direct route exists on the scanner host:** if the route is private and reasonably sized, it can be included in active inventory.
2. **The route uses a next hop or is unusually broad:** it is recorded as a suggestion and is not probed automatically.
3. **An address from that range already exists in the ARP/neighbor cache:** a conservative `/24` suggestion is recorded with supporting evidence; the suggested range is not probed.

Suggestions are written to:

```text
network-targets/suggested-private-scopes.generated.txt
```

Before enabling a suggestion, verify its routing, ownership, and authorization, then pass the precise CIDR with `--authorized-scope`. SmartBackupDiscovery does not change interface addresses, subnet masks, routes, gateways, firewall rules, or VLAN configuration.

A completely silent secondary range with no interface, route, neighbor, DNS, or other authorized telemetry visible to the scanner cannot be discovered reliably from an ordinary host. Absence from the inventory does not prove that no such range exists.

## Load controls

Defaults are conservative. Important options include:

```text
--max-hosts 4096
--network-concurrency 32
--max-probes-per-second 64
--probe-timeout-ms 600
--max-cpu-percent 75
--network-limit-mbps 80
```

The hard ceiling for `--max-hosts` is 65,536. If the resulting address set exceeds the configured limit after exclusions, the operation stops before sending any probe.

Signals can be disabled individually:

```text
--no-icmp
--no-dns
--no-neighbor-cache
--no-tcp-probes
```

Repeat `--probe-port` to add custom ports. An open port is only a service hint and does not establish the host operating system.

## Outputs

- `network-inventory.json`: complete inventory including scopes, policy, warnings, suggestions, and change diff;
- `network-inventory.csv`: tabular host inventory;
- `windows-smb-hosts.generated.txt`: SMB candidates for operator review;
- `linux-sftp-hosts.generated.txt`: SSH/SFTP candidates for operator review;
- `unclassified-hosts.generated.txt`: hosts without a sufficiently strong platform hint;
- `suggested-private-scopes.generated.txt`: suggested private scopes that were not actively probed.

A `NeighborCacheOnly` record may be stale. Review all generated target files before use. Windows shares, Linux roots, accounts, and SSH host-key policy must still be configured explicitly.
