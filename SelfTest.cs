using System.IO.Compression;
using System.Text;

namespace SmartBackupDiscovery;

public static class SelfTest
{
    public static int Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "SmartBackupDiscovery-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        int passed = 0, failed = 0;

        try
        {
            Test("SQLite signature is classified as database", () =>
            {
                string path = Path.Combine(root, "mystery.dat");
                byte[] data = new byte[128];
                Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(data, 0);
                File.WriteAllBytes(path, data);
                var result = FileClassifier.Analyze(path, "local:test", false, ContentInspectionProfile.Balanced);
                return result.Category == FileCategory.Database && result.MustInclude && result.Score >= 180;
            });

            Test("generic updater executable is ignored", () =>
            {
                string path = Path.Combine(root, "Update.exe");
                File.WriteAllBytes(path, new byte[4096]);
                var result = FileClassifier.Analyze(path, "local:test", false, ContentInspectionProfile.Balanced);
                return result.Score == 0 && result.Priority == BackupPriority.Ignore;
            });

            Test("encrypted OOXML wrapper is flagged", () =>
            {
                string path = Path.Combine(root, "protected.docx");
                byte[] ole = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0, 0, 0 };
                File.WriteAllBytes(path, ole);
                var result = FileClassifier.Analyze(path, "local:test", true, ContentInspectionProfile.Balanced);
                return result.ProtectionDetected && result.ReasonCode == "OFFICE_ENCRYPTED_PACKAGE";
            });

            Test("Word documentProtection is flagged", () =>
            {
                string path = Path.Combine(root, "locked.docx");
                using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry("word/settings.xml");
                    using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                    writer.Write("<w:settings xmlns:w=\"urn:test\"><w:documentProtection w:enforcement=\"1\"/></w:settings>");
                }
                var result = FileClassifier.Analyze(path, "local:test", true, ContentInspectionProfile.Balanced);
                return result.ProtectionDetected && result.ProtectionType == "WordDocumentProtection";
            });

            Test("remote allowlist parser keeps explicit hosts and shares", () =>
            {
                string hosts = Path.Combine(root, "machines.txt");
                File.WriteAllText(hosts, "# test\nPC01\nPC02|C$;D$\n");
                var targets = AuthorizedRemoteAccess.LoadTargets(Array.Empty<string>(), hosts, new[] { "Data" });
                var pc1 = targets.Single(x => x.Host.Equals("PC01", StringComparison.OrdinalIgnoreCase));
                var pc2 = targets.Single(x => x.Host.Equals("PC02", StringComparison.OrdinalIgnoreCase));
                return targets.Count == 2 &&
                       pc1.Shares.SequenceEqual(new[] { "Data" }, StringComparer.OrdinalIgnoreCase) &&
                       pc2.Shares.SequenceEqual(new[] { "C$", "D$" }, StringComparer.OrdinalIgnoreCase);
            });

            Test("remote allowlist parser rejects CIDR", () =>
            {
                try
                {
                    AuthorizedRemoteAccess.LoadTargets(new[] { "192.168.1.0/24" }, null, Array.Empty<string>());
                    return false;
                }
                catch (ArgumentException)
                {
                    return true;
                }
            });

            Test("remote allowlist requires explicit share", () =>
            {
                try
                {
                    AuthorizedRemoteAccess.LoadTargets(new[] { "PC01" }, null, Array.Empty<string>());
                    return false;
                }
                catch (ArgumentException)
                {
                    return true;
                }
            });

            Test("IPv4 CIDR parser canonicalizes scope and host count", () =>
            {
                Ipv4Cidr cidr = Ipv4Cidr.Parse("192.168.25.77/24");
                string[] hosts = Ipv4Cidr.Parse("10.20.30.0/30").EnumerateUsableAddresses().Select(x => x.ToString()).ToArray();
                return cidr.Canonical == "192.168.25.0/24" && cidr.UsableAddressCount == 254 && cidr.IsPrivateScope() &&
                       hosts.SequenceEqual(new[] { "10.20.30.1", "10.20.30.2" }) &&
                       !Ipv4Cidr.Parse("8.8.8.0/24").IsPrivateScope();
            });

            Test("network target expansion deduplicates overlaps and applies exclusions", () =>
            {
                var scopes = new[]
                {
                    new NetworkDiscoveryScope("192.168.50.0/30", "ExplicitCidr", null, null, 2, true),
                    new NetworkDiscoveryScope("192.168.50.1/32", "ExplicitCidr", null, null, 1, true)
                };
                Dictionary<uint, HashSet<string>> targets = NetworkDiscoveryService.ExpandTargets(
                    scopes,
                    new[] { Ipv4Cidr.Parse("192.168.50.2/32") },
                    10);
                return targets.Count == 1 && targets.ContainsKey(Ipv4Cidr.ToUInt32(System.Net.IPAddress.Parse("192.168.50.1"))) &&
                       targets.Values.Single().Count == 2;
            });

            Test("Linux route parser finds direct and routed private scopes", () =>
            {
                string[] routes =
                {
                    "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT",
                    "eth0 0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0",
                    "eth0 000010AC 0100A8C0 0003 0 0 100 0000F0FF 0 0 0",
                    "eth0 00000000 0100A8C0 0003 0 0 100 00000000 0 0 0"
                };
                IReadOnlyList<NetworkRouteHint> parsed = NetworkRouteTableReader.ParseLinuxRouteLines(routes);
                return parsed.Any(x => x.Cidr == "192.168.0.0/24" && x.IsDirect) &&
                       parsed.Any(x => x.Cidr == "172.16.0.0/12" && !x.IsDirect && x.NextHop == "192.168.0.1") &&
                       parsed.All(x => x.Cidr != "0.0.0.0/0");
            });

            Test("network inventory merges bounded probes and neighbor evidence", () =>
            {
                var observations = new Dictionary<string, NetworkProbeObservation>(StringComparer.OrdinalIgnoreCase)
                {
                    ["192.168.60.1"] = new(true, 2, new[] { 445 }, "fileserver.test"),
                    ["192.168.60.2"] = new(false, null, Array.Empty<int>(), null)
                };
                var neighbors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["192.168.60.2"] = "00:11:22:33:44:55",
                    ["192.168.61.7"] = "00:11:22:33:44:66"
                };
                var policy = new NetworkDiscoveryPolicy(true, true, true, new[] { 22, 445 }, 200, 2, 10, 1000,
                    new ResourcePolicy(100, 0, 0, 64, 0));
                var scopes = new[] { new NetworkDiscoveryScope("192.168.60.0/30", "ExplicitCidr", null, null, 2, true) };
                NetworkInventoryManifest inventory = new NetworkDiscoveryService(
                        new FakeNetworkHostProbe(observations),
                        () => neighbors)
                    .DiscoverAsync(scopes, Array.Empty<Ipv4Cidr>(), policy)
                    .GetAwaiter().GetResult();

                NetworkDiscoveredHost windows = inventory.Hosts.Single(x => x.IpAddress == "192.168.60.1");
                NetworkDiscoveredHost cached = inventory.Hosts.Single(x => x.IpAddress == "192.168.60.2");
                return inventory.Summary.AddressesConsidered == 2 && inventory.Summary.HostsFound == 2 &&
                       windows.PlatformHint == "WindowsOrSmb" && windows.RecommendedTransport.Contains("SMB", StringComparison.Ordinal) &&
                       cached.Reachability == "NeighborCacheOnly" && cached.MacAddress == "00:11:22:33:44:55" &&
                       inventory.SuggestedScopes.Any(x => x.Cidr == "192.168.61.0/24" && !x.ActivelyProbed) &&
                       inventory.Hosts.All(x => x.IpAddress != "192.168.61.7");
            });

            Test("network inventory diff reports host additions removals and service changes", () =>
            {
                NetworkDiscoveredHost Host(string ip, string name, params int[] ports) => new(
                    ip, name, null, "Reachable", true, 1, ports,
                    NetworkDiscoveryService.Classify(ports).PlatformHint,
                    NetworkDiscoveryService.Classify(ports).RecommendedTransport,
                    new[] { "192.168.70.0/24" }, new[] { "fixture" }, DateTime.UnixEpoch);
                var previous = new NetworkInventoryManifest { Hosts = new[] { Host("192.168.70.10", "alpha", 445), Host("192.168.70.20", "gone", 22) } };
                var current = new NetworkInventoryManifest { Hosts = new[] { Host("192.168.70.10", "alpha", 22, 445), Host("192.168.70.30", "new", 22) } };
                NetworkInventoryDiffSummary diff = NetworkInventoryDiff.Compare(previous, current, "previous.json");
                return diff.AddedCount == 1 && diff.RemovedCount == 1 && diff.ChangedCount == 1 && diff.Changes.Count == 3;
            });

            Test("network inventory writer creates JSON CSV and review target lists", () =>
            {
                string outputRoot = Path.Combine(root, "network-output");
                var host = new NetworkDiscoveredHost(
                    "192.168.80.10", "backup-host", "00:AA:BB:CC:DD:EE", "Reachable", true, 1,
                    new[] { 22 }, "LinuxOrSsh", "SSH/SFTP (host-key verification required)",
                    new[] { "192.168.80.0/24" }, new[] { "ICMP echo response" }, DateTime.UnixEpoch);
                var manifest = new NetworkInventoryManifest
                {
                    Hosts = new[] { host },
                    SuggestedScopes = new[]
                    {
                        new NetworkScopeSuggestion(
                            "192.168.81.0/24",
                            "OutOfScopeNeighborCache",
                            "fixture suggestion",
                            new[] { "out-of-scope neighbor=192.168.81.7" },
                            false)
                    },
                    Summary = new NetworkInventorySummary(254, 1, 0, 1, 0, 0, 0)
                };
                NetworkInventoryArtifacts artifacts = NetworkInventoryStore.Write(
                    Path.Combine(outputRoot, "inventory.json"),
                    Path.Combine(outputRoot, "inventory.csv"),
                    Path.Combine(outputRoot, "targets"),
                    manifest,
                    true);
                NetworkInventoryManifest roundTrip = NetworkInventoryStore.Read(artifacts.JsonPath);
                return roundTrip.Hosts.Count == 1 && File.Exists(artifacts.CsvPath) &&
                       File.ReadAllText(artifacts.LinuxHostsPath!).Contains("192.168.80.10", StringComparison.Ordinal) &&
                       File.ReadAllText(artifacts.WindowsHostsPath!).Contains("No share is assumed", StringComparison.Ordinal) &&
                       File.ReadAllText(artifacts.SuggestedScopesPath!).Contains("192.168.81.0/24", StringComparison.Ordinal);
            });

            Test("backup gap analyzer matches explicit coverage roots", () =>
            {
                var manifest = FixtureManifest(
                    new FileCandidate(@"D:\Data\finance.xlsx", 1000, DateTime.UnixEpoch, 200, BackupPriority.Critical, FileCategory.Spreadsheet, true, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0),
                    new FileCandidate(@"D:\Projects\app.csproj", 500, DateTime.UnixEpoch, 140, BackupPriority.High, FileCategory.Project, false, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                var inventory = new BackupInventory("fixture", new[] { @"D:\Data" });
                BackupGapSummary gap = BackupGapAnalyzer.Analyze(manifest, inventory);
                return gap.CoveredCandidateCount == 1 && gap.UncoveredCandidateCount == 1 &&
                       gap.CriticalUncoveredCount == 0 && gap.HighUncoveredCount == 1 &&
                       gap.CoveredCandidateBytes == 1000 && gap.UncoveredCandidateBytes == 500;
            });

            Test("manifest diff reports add remove and change", () =>
            {
                DateTime t = DateTime.UnixEpoch;
                var previous = FixtureManifest(
                    new FileCandidate(@"D:\A.db", 100, t, 180, BackupPriority.Critical, FileCategory.Database, true, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0),
                    new FileCandidate(@"D:\B.docx", 200, t, 100, BackupPriority.High, FileCategory.Document, false, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                var current = FixtureManifest(
                    new FileCandidate(@"D:\A.db", 150, t.AddMinutes(1), 180, BackupPriority.Critical, FileCategory.Database, true, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0),
                    new FileCandidate(@"D:\C.xlsx", 300, t, 100, BackupPriority.High, FileCategory.Spreadsheet, false, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                ScanDiffSummary diff = ManifestDiffService.Compare(previous, current);
                return diff.AddedCount == 1 && diff.RemovedCount == 1 && diff.ChangedCount == 1 &&
                       diff.AddedBytes == 300 && diff.RemovedBytes == 200;
            });

            Test("readiness score reacts to uncovered critical candidate", () =>
            {
                var manifest = FixtureManifest(
                    new FileCandidate(@"D:\Critical.db", 1000, DateTime.UnixEpoch, 220, BackupPriority.Critical, FileCategory.Database, true, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                manifest.BackupGap = BackupGapAnalyzer.Analyze(manifest, new BackupInventory("fixture", new[] { @"D:\Other" }));
                manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
                return manifest.Readiness.Score < 90 && manifest.Readiness.AttentionItems.Any(x => x.Contains("critical", StringComparison.OrdinalIgnoreCase));
            });

            Test("management report writes encoded HTML and PDF", () =>
            {
                string reportRoot = Path.Combine(root, "reports");
                var manifest = FixtureManifest(
                    new FileCandidate(@"D:\Data\<unsafe>.xlsx", 1024, DateTime.UnixEpoch, 120, BackupPriority.High, FileCategory.Spreadsheet, false, "local:d", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                manifest.Diff = ManifestDiffService.NoPrevious();
                manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, null);
                ManagementReportArtifacts artifacts = ManagementReportWriter.Write(reportRoot, Path.Combine(root, "fixture.json"), manifest, false);
                string html = File.ReadAllText(artifacts.HtmlPath);
                byte[] pdf = File.ReadAllBytes(artifacts.PdfPath);
                return html.Contains("&lt;unsafe&gt;", StringComparison.Ordinal) && !html.Contains("<unsafe>", StringComparison.Ordinal) &&
                       Encoding.ASCII.GetString(pdf.Take(5).ToArray()) == "%PDF-";
            });

            Test("project generated directory is pruned", () =>
            {
                string project = Path.Combine(root, "project");
                Directory.CreateDirectory(project);
                File.WriteAllText(Path.Combine(project, "Fixture.csproj"), "<Project />");
                Directory.CreateDirectory(Path.Combine(project, "bin"));
                File.WriteAllBytes(Path.Combine(project, "bin", "Fixture.exe"), new byte[100]);
                File.WriteAllText(Path.Combine(project, "Program.cs"), "class Program {}");
                var roots = new[] { project };
                var sources = SourceIdentityProvider.BuildSources(roots);
                var scan = new FileScanner().Scan(roots, sources, true, ContentInspectionProfile.Balanced,
                    new ResourceGovernor(ResourcePolicy.Default), new TraversalLimits(10_000, 10_000, 32));
                bool marker = scan.Candidates.Any(x => Path.GetFileName(x.Path).Equals("Fixture.csproj", StringComparison.OrdinalIgnoreCase));
                bool generated = scan.Candidates.Any(x => Path.GetFileName(x.Path).Equals("Fixture.exe", StringComparison.OrdinalIgnoreCase));
                return marker && !generated && scan.Coverage.PolicyDirectoriesSkipped >= 1 && scan.ProjectRoots.Count == 1;
            });

            Test("Java and JVM project markers are recognized", () =>
            {
                string[] markers = { "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
                    "gradle.properties", "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", "build.xml", "ivy.xml",
                    "AndroidManifest.xml", ".project", ".classpath" };
                return markers.All(FileClassifier.IsProjectMarkerName);
            });

            Test("standard Java source tree uses JVM fast path without build metadata", () =>
            {
                string project = Path.Combine(root, "java-layout");
                string package = Path.Combine(project, "src", "main", "java", "com", "example");
                Directory.CreateDirectory(package);
                for (int i = 0; i < 20; i++)
                    File.WriteAllText(Path.Combine(package, $"Class{i}.java"), $"package com.example; class Class{i} {{}}");
                Directory.CreateDirectory(Path.Combine(project, "target", "classes"));
                File.WriteAllBytes(Path.Combine(project, "target", "classes", "Class0.class"), new byte[2048]);

                var roots = new[] { project };
                var scan = new FileScanner().Scan(roots, SourceIdentityProvider.BuildSources(roots), false, ContentInspectionProfile.Balanced,
                    new ResourceGovernor(ResourcePolicy.Default), new TraversalLimits(10_000, 10_000, 64));

                return scan.ProjectRoots.Count == 1 &&
                       scan.Performance.JvmProjectsDetected == 1 &&
                       scan.Performance.ProjectFastPathFiles >= 20 &&
                       scan.Performance.SignatureProbesAvoided >= 20 &&
                       scan.Coverage.PolicyDirectoriesSkipped >= 1 &&
                       scan.ProjectVolumes.Count == 1 && scan.ProjectVolumes[0].Files >= 20 && scan.ProjectVolumes[0].Bytes > 0 &&
                       !scan.Candidates.Any(x => x.Path.EndsWith(".java", StringComparison.OrdinalIgnoreCase));
            });

            Test("loose package-style JVM source root is detected without Maven or Gradle files", () =>
            {
                string project = Path.Combine(root, "legacy-java-source");
                string package = Path.Combine(project, "com", "legacy", "app");
                Directory.CreateDirectory(package);
                for (int i = 0; i < 8; i++)
                    File.WriteAllText(Path.Combine(package, $"Legacy{i}.java"), $"package com.legacy.app; class Legacy{i} {{}}");
                File.WriteAllText(Path.Combine(project, "README.txt"), "legacy source");
                var roots = new[] { project };
                var scan = new FileScanner().Scan(roots, SourceIdentityProvider.BuildSources(roots), false, ContentInspectionProfile.Balanced,
                    new ResourceGovernor(ResourcePolicy.Default), new TraversalLimits(10_000, 10_000, 32));
                return scan.ProjectRoots.Count == 1 && scan.Performance.JvmProjectsDetected == 1 &&
                       scan.Performance.ProjectFastPathFiles >= 8 && scan.Performance.SignatureProbesAvoided >= 8;
            });

            Test("compose files are project markers", () =>
            {
                return FileClassifier.IsProjectMarkerName("docker-compose.yml") &&
                       FileClassifier.IsProjectMarkerName("compose.yaml") &&
                       FileClassifier.IsProjectMarkerName("Makefile") &&
                       FileClassifier.IsProjectMarkerName("CMakeLists.txt");
            });

            Test("remote Linux allowlist parses explicit roots and fingerprint", () =>
            {
                string file = Path.Combine(root, "linux-hosts.txt");
                string fp = "abcdefghijklmnopqrstuvwxyzABCDEFGH";
                File.WriteAllText(file, $"# linux\nlinux01|/home;/srv|SHA256:{fp}\n");
                var targets = RemoteLinuxSftpDiscovery.LoadTargets(Array.Empty<string>(), file, Array.Empty<string>(), 22, null);
                return targets.Count == 1 && targets[0].Host == "linux01" && targets[0].Port == 22 &&
                       targets[0].Roots.SequenceEqual(new[] { "/home", "/srv" }, StringComparer.Ordinal) &&
                       targets[0].HostKeySha256 == fp;
            });

            Test("remote Linux allowlist rejects CIDR and relative roots", () =>
            {
                bool cidr = false, relative = false;
                try { RemoteLinuxSftpDiscovery.LoadTargets(new[] { "10.0.0.0/24" }, null, new[] { "/home" }, 22, null); }
                catch (ArgumentException) { cidr = true; }
                try { RemoteLinuxSftpDiscovery.LoadTargets(new[] { "linux01" }, null, new[] { "home/user" }, 22, null); }
                catch (ArgumentException) { relative = true; }
                return cidr && relative;
            });

            Test("remote Linux metadata classifier marks essential config must-copy", () =>
            {
                var item = FileClassifier.AnalyzeRemoteLinuxMetadata(
                    "sftp://linux01/etc/fstab", "/etc/fstab", "fstab", 123, DateTime.UnixEpoch, "sftp:linux01:22:test");
                return item.MustInclude && item.Category == FileCategory.Configuration && item.Priority >= BackupPriority.High &&
                       item.ReasonCode == "REMOTE_METADATA_ONLY";
            });

            Test("sftp backup coverage is host-aware and Linux path case-sensitive", () =>
            {
                var manifest = FixtureManifest(
                    new FileCandidate("sftp://linux01/home/User/Data.db", 100, DateTime.UnixEpoch, 190, BackupPriority.Critical, FileCategory.Database, true,
                        "sftp:linux01:22:home", Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0));
                var covered = BackupGapAnalyzer.Analyze(manifest, new BackupInventory("fixture", new[] { "sftp://linux01/home/User" }));
                var wrongCase = BackupGapAnalyzer.Analyze(manifest, new BackupInventory("fixture", new[] { "sftp://linux01/home/user" }));
                var wrongHost = BackupGapAnalyzer.Analyze(manifest, new BackupInventory("fixture", new[] { "sftp://linux02/home/User" }));
                return covered.CoveredCandidateCount == 1 && wrongCase.CoveredCandidateCount == 0 && wrongHost.CoveredCandidateCount == 0;
            });

            Test("remote Linux path normalization rejects root escape", () =>
            {
                bool escaped = false;
                try { RemoteLinuxPath.NormalizeAbsolute("/../../etc"); }
                catch (ArgumentException) { escaped = true; }
                return escaped && RemoteLinuxPath.NormalizeAbsolute("/srv/./app/") == "/srv/app" &&
                       RemoteLinuxPath.IsSameOrUnder("/srv/app/src", "/srv/app");
            });

            Test("Linux path/source semantics are platform-correct", () =>
            {
                if (!OperatingSystem.IsLinux()) return true;
                var sources = SourceIdentityProvider.BuildSources(new[] { root });
                return sources.Count == 1 && sources[0].Kind == SourceKind.LinuxLocal &&
                       !PathRules.IsSameOrUnder(Path.Combine(root, "data"), Path.Combine(root, "Data"));
            });

            Test("Linux essential config hint is metadata-only must-copy", () =>
            {
                if (!OperatingSystem.IsLinux()) return true;
                LinuxFileHint? hint = LinuxBackupHints.GetHint("/etc/fstab");
                return hint is not null && hint.MustInclude && hint.Category == FileCategory.Configuration && hint.Score >= 120;
            });

            Test("Linux virtual filesystem roots are excluded by default", () =>
            {
                if (!OperatingSystem.IsLinux()) return true;
                var policy = new PlatformScanPolicy(new[] { "/proc" }, PlatformTraversalOptions.Default);
                return policy.ShouldSkipDirectory("/proc", "/proc", out PlatformSkipReason reason) &&
                       reason == PlatformSkipReason.SystemVirtualFileSystem;
            });

            Test("must-copy volume counts project tree once plus standalone critical files", () =>
            {
                string scope = Path.Combine(root, "volume-scope");
                string project = Path.Combine(scope, "app");
                Directory.CreateDirectory(project);
                File.WriteAllText(Path.Combine(project, "pom.xml"), "<project />");
                File.WriteAllBytes(Path.Combine(project, "Main.java"), new byte[100]);
                File.WriteAllBytes(Path.Combine(project, "inside.db"), new byte[200]);
                File.WriteAllBytes(Path.Combine(scope, "outside.db"), new byte[300]);

                DiscoveryManifest manifest = new DiscoveryEngine().Discover(
                    new[] { scope }, false, ContentInspectionProfile.Balanced, ResourcePolicy.Default,
                    new TraversalLimits(10_000, 10_000, 64));

                return manifest.MustCopyVolume.ProjectSourceFiles >= 3 &&
                       manifest.MustCopyVolume.ProjectSourceBytes >= 300 &&
                       manifest.MustCopyVolume.StandaloneMustCopyFiles == 1 &&
                       manifest.MustCopyVolume.StandaloneMustCopyBytes == 300 &&
                       manifest.MustCopyVolume.EstimatedBytes == manifest.MustCopyVolume.ProjectSourceBytes + 300;
            });
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }

        Console.WriteLine($"Selftest: {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;

        static DiscoveryManifest FixtureManifest(params FileCandidate[] candidates)
        {
            return new DiscoveryManifest
            {
                Sources = new[] { new SourceDescriptor("local:d", SourceKind.Local, @"D:\", Environment.MachineName, null, "D:") },
                ScanCoverage = new ScanCoverage(
                    new[] { new RootCoverage(@"D:\", true, true, 1, candidates.Length, candidates.Length, 0, 0, 0, 0) },
                    1, candidates.Length, candidates.Length, 0, 0, 0),
                Candidates = candidates,
                BackupSets = Array.Empty<BackupSet>(),
                Errors = Array.Empty<string>()
            };
        }

        void Test(string name, Func<bool> action)
        {
            try
            {
                if (action()) { passed++; Console.WriteLine($"PASS  {name}"); }
                else { failed++; Console.WriteLine($"FAIL  {name}"); }
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine($"FAIL  {name}: {ex.Message}");
            }
        }
    }

    private sealed class FakeNetworkHostProbe : INetworkHostProbe
    {
        private readonly IReadOnlyDictionary<string, NetworkProbeObservation> _observations;

        public FakeNetworkHostProbe(IReadOnlyDictionary<string, NetworkProbeObservation> observations) =>
            _observations = observations;

        public Task<NetworkProbeObservation> ProbeAsync(
            System.Net.IPAddress address,
            NetworkDiscoveryPolicy policy,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_observations.TryGetValue(address.ToString(), out NetworkProbeObservation? result)
                ? result
                : new NetworkProbeObservation(false, null, Array.Empty<int>(), null));
        }
    }
}
