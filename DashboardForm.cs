#if WINDOWS_BUILD
using System.Diagnostics;
using System.Windows.Forms;

namespace SmartBackupDiscovery;

public sealed class DashboardForm : Form
{
    private readonly TextBox _roots = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Text = "C:\\" };
    private readonly TextBox _output = new() { Dock = DockStyle.Fill, ReadOnly = true };

    public DashboardForm()
    {
        Text = "SmartBackupDiscovery 3.3"; Width = 900; Height = 650; StartPosition = FormStartPosition.CenterScreen;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1, Padding = new Padding(12) };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        layout.Controls.Add(new Label { Text = "Local roots (one per line). For SMB/Linux remote options use the CLI --help.", Dock = DockStyle.Fill }, 0, 0);
        layout.Controls.Add(_roots, 0, 1);
        var run = new Button { Text = "Run Discover", Width = 150, Height = 32 }; run.Click += RunClicked; layout.Controls.Add(run, 0, 2);
        layout.Controls.Add(_output, 0, 3); Controls.Add(layout);
    }

    private async void RunClicked(object? sender, EventArgs e)
    {
        string[] roots = _roots.Lines.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToArray();
        if (roots.Length == 0) return;
        _output.Text = "Scanning...";
        try
        {
            DiscoveryManifest manifest = await Task.Run(() => new DiscoveryEngine().Discover(roots, true, ContentInspectionProfile.Balanced, ResourcePolicy.Default, TraversalLimits.Default));
            manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, null);
            string path = Path.Combine(Environment.CurrentDirectory, "discovery-manifest.json"); ManifestWriter.WriteDiscovery(path, manifest);
            _output.Text = $"Readiness {manifest.Readiness.Score}/100\r\nCandidates {manifest.Candidates.Count}\r\nMust-copy {manifest.MustCopyVolume.FileCount} files / {manifest.MustCopyVolume.EstimatedBytes:N0} bytes\r\nManifest: {path}";
        }
        catch (Exception ex) { _output.Text = ex.ToString(); }
    }
}
#endif
