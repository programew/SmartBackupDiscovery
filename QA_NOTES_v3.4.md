# QA Notes — 3.4.0

## Scope

Version 3.4 adds a separate, controlled private-IPv4 network inventory phase. Credentialed SMB/SFTP and file discovery remain explicit downstream actions.

## Automated verification

- Cross-platform non-GUI source compiled against .NET 10 reference assemblies.
- Windows Forms source compiled against .NET 10 Windows Desktop reference assemblies.
- 31 deterministic self-tests passed, 0 failed.
- CIDR canonicalization, address bounds, overlap deduplication and exclusions are covered.
- Explicit CIDR without `--authorized-scope`, public CIDR and a scope above `--max-hosts` fail closed before active probing.
- Linux route-table parsing covers direct and next-hop private routes.
- Probe/neighbor evidence merge, platform hinting and out-of-scope neighbor suggestions are covered with deterministic fakes.
- The out-of-scope neighbor test confirms the suggested secondary `/24` is not actively expanded or probed.
- JSON/CSV, target-list and suggested-scope artifacts are covered.
- Inventory history diff covers added, removed and service-changed hosts.
- Existing classifier, Linux/SFTP path, backup-gap, readiness, history, management report, Must-Copy and JVM regression tests pass.

## Security assertions

- Active automatic inventory is limited to private IPv4 connected scopes and bounded direct routes.
- Explicit active CIDRs require an authorization acknowledgement and remain RFC1918-only.
- Routed/broad route hints and out-of-scope neighbor hints are suggestions only.
- Network inventory does not authenticate, enumerate shares, access SFTP roots or invoke file discovery.
- The implementation does not modify addresses, masks, routes, gateways, firewall rules or VLAN state.
- Generated targets are clearly marked for operator review.

## Known limits

- Host firewalls, ICMP policy, closed/non-default ports and transient packet loss can produce false negatives.
- TCP port hints do not prove an operating system.
- Neighbor-cache entries can be stale or spoofed.
- A silent secondary subnet with no local interface/route, neighbor/DNS evidence or authorized external telemetry is not discoverable reliably from an ordinary endpoint.
- IPv6 inventory, SNMP, LLDP/CDP, packet capture, directory-service import and infrastructure-controller integrations are outside this release.
