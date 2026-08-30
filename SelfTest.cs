namespace SmartBackupDiscovery;

public static class SelfTest
{
    public static int Run()
    {
        int failed = 0;
        Check("CIDR rejected for SMB allowlist", () => { try { AuthorizedRemoteAccess.LoadTargets(new[] { "192.168.1.0/24" }, null, Array.Empty<string>()); return false; } catch (ArgumentException) { return true; } });
        Check("CIDR rejected for Linux allowlist", () => { try { RemoteLinuxSftpDiscovery.LoadTargets(new[] { "10.0.0.0/24" }, null, new[] { "/home" }, 22, null); return false; } catch (ArgumentException) { return true; } });
        Check("JVM markers recognized", () => FileClassifier.IsProjectMarkerName("pom.xml") && FileClassifier.IsProjectMarkerName("build.gradle.kts") && FileClassifier.IsJvmSourceFileName("Main.java"));
        Check("Remote Linux path is case-sensitive", () => RemoteLinuxPath.IsSameOrUnder("/home/User/a", "/home/User") && !RemoteLinuxPath.IsSameOrUnder("/home/User/a", "/home/user"));
        Check("Must-copy estimate exists", () => MustCopyVolumeSummary.Empty.EstimatedBytes == 0);
        Console.WriteLine(failed == 0 ? "Selftest passed." : $"Selftest failed: {failed}");
        return failed == 0 ? 0 : 1;
        void Check(string name, Func<bool> test) { try { bool ok = test(); Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) failed++; } catch (Exception ex) { Console.WriteLine($"FAIL  {name}: {ex.Message}"); failed++; } }
    }
}
