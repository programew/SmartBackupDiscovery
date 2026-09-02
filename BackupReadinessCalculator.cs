namespace SmartBackupDiscovery;

public static class BackupReadinessCalculator
{
    public static BackupReadinessAssessment Calculate(DiscoveryManifest manifest, BackupGapSummary? gap)
    {
        var factors = new List<ReadinessFactor>();
        var attention = new List<string>();

        int coverage = CalculateCoverage(manifest, attention);
        factors.Add(new ReadinessFactor("Scan coverage", coverage, 35,
            coverage >= 30 ? "Good" : coverage >= 20 ? "Attention" : "Poor",
            $"{manifest.ScanCoverage.Roots.Count(x => x.Completed)}/{manifest.ScanCoverage.Roots.Count} roots completed; {manifest.ScanCoverage.Roots.Sum(x => x.Errors)} root errors."));

        int access = CalculateAccess(manifest, attention);
        int remoteTargetCount = manifest.RemoteTargets.Count + manifest.RemoteLinuxTargets.Count;
        int remoteSucceeded = manifest.RemoteTargets.Count(x => x.AuthenticationStatus == RemoteAuthenticationStatus.Succeeded) +
                              manifest.RemoteLinuxTargets.Count(x => x.AuthenticationStatus == RemoteAuthenticationStatus.Succeeded);
        factors.Add(new ReadinessFactor("Remote access", access, 25,
            access >= 22 ? "Good" : access >= 13 ? "Attention" : "Poor",
            remoteTargetCount == 0
                ? "No remote targets were requested."
                : $"{remoteSucceeded}/{remoteTargetCount} Windows SMB/Linux SFTP remote targets fully accessible."));

        int operational = Math.Max(0, 15 - Math.Min(15, manifest.Errors.Count * 2));
        if (manifest.Errors.Count > 0)
            attention.Add($"{manifest.Errors.Count} scan error(s) were recorded; review coverage before relying on the inventory.");
        int linuxServiceSets = manifest.BackupSets.Count(x => x.Type == "LinuxServiceData");
        if (linuxServiceSets > 0)
            attention.Add($"{linuxServiceSets} critical Linux service-data set(s) require an application-aware or consistent-snapshot backup method.");
        factors.Add(new ReadinessFactor("Operational health", operational, 15,
            operational >= 13 ? "Good" : operational >= 8 ? "Attention" : "Poor",
            $"{manifest.Errors.Count} manifest error(s)."));

        int backupCoverage;
        bool inventoryProvided = gap is not null && gap.InventoryProvided;
        if (inventoryProvided)
        {
            // The detailed analyzer already determined candidate coverage. Use byte ratio as a stable, transparent score.
            double ratio = gap!.CandidateBytes <= 0 ?
                (gap.UncoveredCandidateCount == 0 ? 1.0 : 0.0) :
                Math.Clamp((double)gap.CoveredCandidateBytes / gap.CandidateBytes, 0, 1);
            backupCoverage = (int)Math.Round(25 * ratio, MidpointRounding.AwayFromZero);
            if (gap.CriticalUncoveredCount > 0)
            {
                backupCoverage = Math.Min(backupCoverage, 10);
                attention.Add($"{gap.CriticalUncoveredCount} critical candidate(s) appear outside the supplied backup inventory.");
            }
            else if (gap.HighUncoveredCount > 0)
            {
                backupCoverage = Math.Min(backupCoverage, 18);
                attention.Add($"{gap.HighUncoveredCount} high-priority candidate(s) appear outside the supplied backup inventory.");
            }
            if (gap.UncoveredBackupSetCount > 0)
            {
                backupCoverage = Math.Min(backupCoverage, 20);
                attention.Add($"{gap.UncoveredBackupSetCount} logical backup set(s) appear uncovered.");
            }
            factors.Add(new ReadinessFactor("Backup coverage", backupCoverage, 25,
                backupCoverage >= 22 ? "Good" : backupCoverage >= 13 ? "Attention" : "Poor",
                $"Candidate-file coverage by supplied inventory: {gap.CoveredCandidateCount}/{gap.CandidateCount}; {FormatBytes(gap.CoveredCandidateBytes)} of {FormatBytes(gap.CandidateBytes)}."));
        }
        else
        {
            backupCoverage = 12;
            attention.Add("No backup inventory was supplied, so actual backup coverage was not verified.");
            factors.Add(new ReadinessFactor("Backup coverage", backupCoverage, 25, "Not assessed",
                "Neutral partial score used because no backup inventory was supplied."));
        }

        int score = Math.Clamp(coverage + access + operational + backupCoverage, 0, 100);
        string grade = score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };

        string confidence = inventoryProvided && manifest.ScanCoverage.Roots.All(x => x.Completed) && manifest.Errors.Count == 0
            ? "High"
            : inventoryProvided ? "Medium" : "Limited";

        return new BackupReadinessAssessment(
            score,
            grade,
            confidence,
            inventoryProvided,
            manifest.Candidates.Count(x => x.Priority == BackupPriority.Critical),
            manifest.Candidates.Count(x => x.Priority == BackupPriority.High),
            manifest.Candidates.Count(x => x.ProtectionDetected),
            SizeMath.SumCandidateBytes(manifest.Candidates),
            factors,
            attention.Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToArray());
    }

    private static int CalculateCoverage(DiscoveryManifest manifest, List<string> attention)
    {
        if (manifest.ScanCoverage.Roots.Count == 0)
        {
            attention.Add("No scan root completed successfully.");
            return 0;
        }

        double completion = (double)manifest.ScanCoverage.Roots.Count(x => x.Completed) / manifest.ScanCoverage.Roots.Count;
        int baseScore = (int)Math.Round(30 * completion, MidpointRounding.AwayFromZero);
        long rootErrors = manifest.ScanCoverage.Roots.Sum(x => x.Errors);
        int errorPenalty = (int)Math.Min(5, rootErrors);
        foreach (RootCoverage root in manifest.ScanCoverage.Roots.Where(x => !x.Completed || x.Errors > 0).Take(5))
            attention.Add($"Coverage issue: {root.Root} (completed={root.Completed}, errors={root.Errors}).");
        return Math.Clamp(baseScore + 5 - errorPenalty, 0, 35);
    }

    private static int CalculateAccess(DiscoveryManifest manifest, List<string> attention)
    {
        int count = manifest.RemoteTargets.Count + manifest.RemoteLinuxTargets.Count;
        if (count == 0) return 25;
        double points = 0;
        foreach (RemoteTargetReport target in manifest.RemoteTargets)
        {
            points += AccessPoints(target.AuthenticationStatus);
            if (target.AuthenticationStatus is not RemoteAuthenticationStatus.Succeeded)
                attention.Add($"Remote Windows target {target.HostReference}: {target.AuthenticationStatus}.");
        }
        foreach (RemoteLinuxTargetReport target in manifest.RemoteLinuxTargets)
        {
            points += AccessPoints(target.AuthenticationStatus);
            if (target.AuthenticationStatus is not RemoteAuthenticationStatus.Succeeded)
                attention.Add($"Remote Linux target {target.HostReference}:{target.Port}: {target.AuthenticationStatus}.");
        }
        return (int)Math.Round(25 * (points / count), MidpointRounding.AwayFromZero);

        static double AccessPoints(RemoteAuthenticationStatus status) => status switch
        {
            RemoteAuthenticationStatus.Succeeded => 1.0,
            RemoteAuthenticationStatus.Partial => 0.5,
            _ => 0.0
        };
    }


    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double value = Math.Max(0, bytes);
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:0.##} {units[unit]}";
    }
}
