using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

namespace SmartBackupDiscovery;

public sealed class DashboardForm : Form
{
    private readonly TextBox _roots = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 72 };
    private readonly TextBox _hostsFile = new();
    private readonly TextBox _shares = new() { Text = "C$" };
    private readonly TextBox _username = new();
    private readonly TextBox _password = new() { UseSystemPasswordChar = true };
    private readonly TextBox _linuxHosts = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 58, PlaceholderText = "linux01\n192.168.1.40" };
    private readonly TextBox _linuxRoots = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 72, Text = "/home\r\n/srv\r\n/opt\r\n/var/www\r\n/var/lib\r\n/etc" };
    private readonly TextBox _linuxUsername = new() { PlaceholderText = "root or backup-discovery" };
    private readonly TextBox _linuxPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox _sshFingerprint = new() { PlaceholderText = "SHA256 fingerprint (optional if already known)" };
    private readonly NumericUpDown _sshPort = new() { Minimum = 1, Maximum = 65535, Value = 22, Width = 90 };
    private readonly CheckBox _sshTofu = new() { Text = "Trust/store first SSH host key (TOFU)", Checked = false, AutoSize = true };
    private readonly TextBox _inventory = new();
    private readonly TextBox _manifest = new() { Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SmartBackupDiscovery", "discovery-manifest.json") };
    private readonly NumericUpDown _cpu = new() { Minimum = 1, Maximum = 100, Value = 75, Width = 90 };
    private readonly NumericUpDown _network = new() { Minimum = 0, Maximum = 100000, Value = 80, Width = 90 };
    private readonly CheckBox _privacy = new() { Text = "Privacy mode in management reports", Checked = false, AutoSize = true };
    private readonly Button _start = new() { Text = "Start discovery", AutoSize = true };
    private readonly Button _openManifest = new() { Text = "Open manifest...", AutoSize = true };
    private readonly Button _openReport = new() { Text = "Open HTML report", AutoSize = true, Enabled = false };
    private readonly TextBox _log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill };
    private readonly Label _score = MetricLabel("Readiness\n-");
    private readonly Label _critical = MetricLabel("Critical\n-");
    private readonly Label _high = MetricLabel("High\n-");
    private readonly Label _mustCopy = MetricLabel("Must-copy\n-");
    private readonly Label _gap = MetricLabel("Uncovered\n-");
    private readonly Label _changes = MetricLabel("Changes\n-");
    private readonly Label _status = new() { AutoSize = true, Text = "Ready", Padding = new Padding(0, 6, 0, 6) };
    private readonly TextBox _networkCidrs = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 58, PlaceholderText = "Blank = detect connected private IPv4 scopes\r\n192.168.10.0/24" };
    private readonly TextBox _networkExclusions = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 48, PlaceholderText = "192.168.10.1/32" };
    private readonly TextBox _networkOutput = new() { Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SmartBackupDiscovery", "network-inventory.json") };
    private readonly CheckBox _networkAuthorized = new() { Text = "I am authorized to inventory the explicit CIDR scope(s)", AutoSize = true };
    private readonly NumericUpDown _networkMaxHosts = new() { Minimum = 1, Maximum = 65536, Value = 4096, Width = 100, ThousandsSeparator = true };
    private readonly NumericUpDown _networkConcurrency = new() { Minimum = 1, Maximum = 256, Value = 32, Width = 80 };
    private readonly NumericUpDown _networkRate = new() { Minimum = 1, Maximum = 10000, Value = 64, Width = 80 };
    private readonly NumericUpDown _networkTimeout = new() { Minimum = 100, Maximum = 30000, Value = 600, Increment = 100, Width = 90 };
    private readonly Button _networkStart = new() { Text = "Discover network", AutoSize = true };
    private readonly Button _networkOpen = new() { Text = "Open inventory", AutoSize = true, Enabled = false };
    private readonly Button _networkUseTargets = new() { Text = "Use reviewed targets", AutoSize = true, Enabled = false };
    private readonly Label _networkStatus = new() { AutoSize = true, Text = "Ready", Padding = new Padding(0, 6, 0, 6) };
    private readonly TextBox _networkLog = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill };
    private readonly DataGridView _networkGrid = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        AllowUserToAddRows = false,
        AllowUserToDeleteRows = false,
        AutoGenerateColumns = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
    };
    private readonly DataGridView _candidateGrid = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        AllowUserToAddRows = false,
        AllowUserToDeleteRows = false,
        AutoGenerateColumns = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
    };

    private string? _lastHtmlReport;
    private string? _lastNetworkInventory;

    public DashboardForm()
    {
        Text = "SmartBackupDiscovery 3.4";
        Width = 1180;
        Height = 820;
        MinimumSize = new System.Drawing.Size(960, 680);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new System.Drawing.Font("Segoe UI", 9F);

        _candidateGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Priority", DataPropertyName = "Priority", FillWeight = 16 });
        _candidateGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Category", DataPropertyName = "Category", FillWeight = 20 });
        _candidateGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Size", DataPropertyName = "Size", FillWeight = 16 });
        _candidateGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Path", DataPropertyName = "Path", FillWeight = 70 });
        _candidateGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Reason", DataPropertyName = "Reason", FillWeight = 45 });

        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP address", DataPropertyName = "IpAddress", FillWeight = 22 });
        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Host name", DataPropertyName = "HostName", FillWeight = 32 });
        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status", DataPropertyName = "Reachability", FillWeight = 20 });
        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Platform hint", DataPropertyName = "PlatformHint", FillWeight = 25 });
        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Open ports", DataPropertyName = "OpenPorts", FillWeight = 18 });
        _networkGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "MAC", DataPropertyName = "MacAddress", FillWeight = 25 });

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildNetworkTab());
        tabs.TabPages.Add(BuildScanTab());
        tabs.TabPages.Add(BuildDashboardTab());
        Controls.Add(tabs);

        _start.Click += async (_, _) => await StartScanAsync(tabs);
        _openManifest.Click += (_, _) => OpenManifestDialog();
        _openReport.Click += (_, _) => OpenLastReport();
        _networkStart.Click += async (_, _) => await StartNetworkDiscoveryAsync();
        _networkOpen.Click += (_, _) => OpenNetworkInventory();
        _networkUseTargets.Click += (_, _) => UseReviewedNetworkTargets(tabs);
    }

    private TabPage BuildNetworkTab()
    {
        var page = new TabPage("Network inventory") { AutoScroll = true };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(14) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 42));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 58));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var fields = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3 };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        AddRow(fields, "Private CIDRs (optional)", _networkCidrs, new Label { Text = "blank = connected scopes", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Exclude CIDRs", _networkExclusions, new Label { Text = "subnet or /32", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Network inventory", _networkOutput, MakeSaveFileButton(_networkOutput));
        AddRow(fields, "Explicit-scope authorization", _networkAuthorized, new Label());

        var limits = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
        limits.Controls.Add(new Label { Text = "Max hosts", AutoSize = true, Padding = new Padding(0, 7, 3, 0) });
        limits.Controls.Add(_networkMaxHosts);
        limits.Controls.Add(new Label { Text = "Concurrency", AutoSize = true, Padding = new Padding(12, 7, 3, 0) });
        limits.Controls.Add(_networkConcurrency);
        limits.Controls.Add(new Label { Text = "Starts/sec", AutoSize = true, Padding = new Padding(12, 7, 3, 0) });
        limits.Controls.Add(_networkRate);
        limits.Controls.Add(new Label { Text = "Timeout ms", AutoSize = true, Padding = new Padding(12, 7, 3, 0) });
        limits.Controls.Add(_networkTimeout);
        AddRow(fields, "Probe limits", limits, new Label());

        var notice = new Label
        {
            Text = "This step only inventories private IPv4 hosts using bounded ICMP, DNS, neighbor-cache and TCP 22/445 signals. Route/neighbor evidence outside the active scope is reported as a passive suggestion and is not probed. No IP, mask, route or gateway is changed. Review generated targets before using credentials.",
            AutoSize = true,
            MaximumSize = new System.Drawing.Size(1050, 0),
            Padding = new Padding(0, 8, 0, 8)
        };
        var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        header.Controls.Add(fields);
        header.Controls.Add(notice);

        var actions = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        actions.Controls.Add(_networkStart);
        actions.Controls.Add(_networkOpen);
        actions.Controls.Add(_networkUseTargets);
        actions.Controls.Add(_networkStatus);

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(_networkLog, 0, 1);
        root.Controls.Add(_networkGrid, 0, 2);
        root.Controls.Add(actions, 0, 3);
        page.Controls.Add(root);
        return page;
    }

    private TabPage BuildScanTab()
    {
        var page = new TabPage("Discover") { AutoScroll = true };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(14) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var fields = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3 };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        AddRow(fields, "Local roots (one per line)", _roots, MakeBrowseFolderButton(_roots));
        AddRow(fields, "Authorized hosts file", _hostsFile, MakeBrowseFileButton(_hostsFile, "Host lists|*.txt;*.csv|All files|*.*"));
        AddRow(fields, "Explicit remote shares", _shares, new Label { Text = "e.g. C$;D$;Data", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Remote username", _username, new Label { Text = "DOMAIN\\user", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Remote password", _password, new Label { Text = "never placed on command line", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Linux SSH hosts", _linuxHosts, new Label { Text = "explicit hosts only", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Linux roots", _linuxRoots, new Label { Text = "absolute paths", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Linux SSH username", _linuxUsername, new Label { Text = "root is allowed when authorized", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Linux SSH password", _linuxPassword, new Label { Text = "sent via stdin, not argv", AutoSize = true, Padding = new Padding(6) });
        var sshPolicy = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
        sshPolicy.Controls.Add(new Label { Text = "Port", AutoSize = true, Padding = new Padding(0, 7, 3, 0) });
        sshPolicy.Controls.Add(_sshPort);
        sshPolicy.Controls.Add(_sshTofu);
        AddRow(fields, "Linux SSH policy", sshPolicy, new Label());
        AddRow(fields, "SSH host-key SHA256", _sshFingerprint, new Label { Text = "per-host fingerprints can use CLI hosts file", AutoSize = true, Padding = new Padding(6) });
        AddRow(fields, "Backup inventory", _inventory, MakeBrowseFileButton(_inventory, "Inventory|*.json;*.csv;*.txt|All files|*.*"));
        AddRow(fields, "Manifest", _manifest, MakeSaveFileButton(_manifest));

        var resourcePanel = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
        resourcePanel.Controls.Add(new Label { Text = "CPU ceiling %", AutoSize = true, Padding = new Padding(0, 7, 3, 0) });
        resourcePanel.Controls.Add(_cpu);
        resourcePanel.Controls.Add(new Label { Text = "Network Mbps", AutoSize = true, Padding = new Padding(14, 7, 3, 0) });
        resourcePanel.Controls.Add(_network);
        resourcePanel.Controls.Add(_privacy);
        AddRow(fields, "Resource/report policy", resourcePanel, new Label());

        var actionPanel = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        actionPanel.Controls.Add(_start);
        actionPanel.Controls.Add(_openManifest);
        actionPanel.Controls.Add(_openReport);
        actionPanel.Controls.Add(_status);

        root.Controls.Add(fields, 0, 0);
        root.Controls.Add(_log, 0, 1);
        root.Controls.Add(actionPanel, 0, 2);
        page.Controls.Add(root);
        return page;
    }

    private TabPage BuildDashboardTab()
    {
        var page = new TabPage("Dashboard");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(14) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var title = new Label { Text = "Backup Readiness Dashboard", Font = new System.Drawing.Font(Font.FontFamily, 18F, System.Drawing.FontStyle.Bold), AutoSize = true };
        var metrics = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 6 };
        for (int i = 0; i < 6; i++) metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 16.6667F));
        metrics.Controls.Add(_score, 0, 0);
        metrics.Controls.Add(_critical, 1, 0);
        metrics.Controls.Add(_high, 2, 0);
        metrics.Controls.Add(_mustCopy, 3, 0);
        metrics.Controls.Add(_gap, 4, 0);
        metrics.Controls.Add(_changes, 5, 0);

        root.Controls.Add(title, 0, 0);
        root.Controls.Add(metrics, 0, 1);
        root.Controls.Add(_candidateGrid, 0, 2);
        page.Controls.Add(root);
        return page;
    }

    private async Task StartNetworkDiscoveryAsync()
    {
        if (!_networkStart.Enabled) return;
        List<string> cidrs = SplitLines(_networkCidrs.Text);
        if (cidrs.Count > 0 && !_networkAuthorized.Checked)
        {
            MessageBox.Show(this, "Confirm that you are authorized to inventory the explicit CIDR scope(s).", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string output = Path.GetFullPath(Environment.ExpandEnvironmentVariables(_networkOutput.Text.Trim()));
        string parent = Path.GetDirectoryName(output) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        _networkLog.Clear();
        _networkGrid.DataSource = null;
        _networkStart.Enabled = false;
        _networkOpen.Enabled = false;
        _networkUseTargets.Enabled = false;
        _networkStatus.Text = "Running...";

        try
        {
            ProcessStartInfo psi = BuildSelfStartInfo();
            psi.ArgumentList.Add("network-discover");
            foreach (string cidr in cidrs) { psi.ArgumentList.Add("--cidr"); psi.ArgumentList.Add(cidr); }
            foreach (string cidr in SplitLines(_networkExclusions.Text)) { psi.ArgumentList.Add("--exclude-cidr"); psi.ArgumentList.Add(cidr); }
            if (cidrs.Count > 0) psi.ArgumentList.Add("--authorized-scope");
            psi.ArgumentList.Add("--output"); psi.ArgumentList.Add(output);
            psi.ArgumentList.Add("--max-hosts"); psi.ArgumentList.Add(_networkMaxHosts.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--network-concurrency"); psi.ArgumentList.Add(_networkConcurrency.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--max-probes-per-second"); psi.ArgumentList.Add(_networkRate.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--probe-timeout-ms"); psi.ArgumentList.Add(_networkTimeout.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--max-cpu-percent"); psi.ArgumentList.Add(_cpu.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--network-limit-mbps"); psi.ArgumentList.Add(_network.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));

            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            process.OutputDataReceived += (_, e) => AppendNetworkLog(e.Data);
            process.ErrorDataReceived += (_, e) => AppendNetworkLog(e.Data);
            process.Start();
            process.StandardInput.Close();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync();

            _networkStatus.Text = $"Finished (exit {process.ExitCode})";
            if (File.Exists(output))
            {
                LoadNetworkInventory(output);
                _lastNetworkInventory = output;
                _networkOpen.Enabled = true;
                _networkUseTargets.Enabled = true;
            }
        }
        catch (Exception ex)
        {
            _networkStatus.Text = "Failed";
            AppendNetworkLog("GUI error: " + ex.Message);
            MessageBox.Show(this, ex.Message, "Network inventory failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _networkStart.Enabled = true;
        }
    }

    private void LoadNetworkInventory(string path)
    {
        NetworkInventoryManifest inventory = NetworkInventoryStore.Read(path);
        _networkGrid.DataSource = inventory.Hosts
            .Select(x => new NetworkHostRow(
                x.IpAddress,
                x.HostName ?? string.Empty,
                x.Reachability,
                x.PlatformHint,
                string.Join(",", x.OpenTcpPorts),
                x.MacAddress ?? string.Empty))
            .ToList();
        _networkStatus.Text = $"{inventory.Summary.HostsFound:N0} host(s) found from {inventory.Summary.AddressesConsidered:N0} addresses; {inventory.SuggestedScopes.Count:N0} passive scope hint(s)";
    }

    private void OpenNetworkInventory()
    {
        if (_lastNetworkInventory is null || !File.Exists(_lastNetworkInventory)) return;
        Process.Start(new ProcessStartInfo(_lastNetworkInventory) { UseShellExecute = true });
    }

    private void UseReviewedNetworkTargets(TabControl tabs)
    {
        if (_lastNetworkInventory is null || !File.Exists(_lastNetworkInventory)) return;
        NetworkInventoryManifest inventory = NetworkInventoryStore.Read(_lastNetworkInventory);
        string parent = Path.GetDirectoryName(_lastNetworkInventory) ?? Environment.CurrentDirectory;
        string windowsList = Path.Combine(parent, "network-targets", "windows-smb-hosts.generated.txt");
        if (File.Exists(windowsList) && inventory.Hosts.Any(x => x.PlatformHint is "WindowsOrSmb" or "MixedServices"))
            _hostsFile.Text = windowsList;

        string[] linuxHosts = inventory.Hosts
            .Where(x => x.PlatformHint is "LinuxOrSsh" or "MixedServices")
            .Select(x => x.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (linuxHosts.Length > 0) _linuxHosts.Text = string.Join(Environment.NewLine, linuxHosts);

        tabs.SelectedIndex = 1;
        MessageBox.Show(this,
            "Candidate hosts were copied to the Discover tab. Review every target, enter explicit SMB shares/credentials or SSH roots/host-key policy, then start file discovery.",
            "Review targets",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private async Task StartScanAsync(TabControl tabs)
    {
        if (_start.Enabled == false) return;
        List<string> roots = SplitLines(_roots.Text);
        string? hostsFile = NullIfWhiteSpace(_hostsFile.Text);
        List<string> linuxHosts = SplitLines(_linuxHosts.Text);
        bool linuxRemote = linuxHosts.Count > 0;
        if (roots.Count == 0 && hostsFile is null && !linuxRemote)
        {
            MessageBox.Show(this, "Add at least one local root, Windows hosts file, or explicit Linux SSH host.", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (hostsFile is not null && string.IsNullOrWhiteSpace(_username.Text))
        {
            MessageBox.Show(this, "Remote discovery requires a username.", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (hostsFile is not null && SplitShares(_shares.Text).Count == 0)
        {
            MessageBox.Show(this, "Remote shares must be explicit in v3. Enter a share such as C$ or Data, or specify shares per host in the hosts file.", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (linuxRemote && string.IsNullOrWhiteSpace(_linuxUsername.Text))
        {
            MessageBox.Show(this, "Linux SFTP discovery requires an SSH username.", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (linuxRemote && SplitLines(_linuxRoots.Text).Count == 0)
        {
            MessageBox.Show(this, "Add at least one absolute Linux root such as /home or /srv.", "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string manifest = Path.GetFullPath(Environment.ExpandEnvironmentVariables(_manifest.Text.Trim()));
        string manifestParent = Path.GetDirectoryName(manifest) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(manifestParent);
        _log.Clear();
        _lastHtmlReport = null;
        _openReport.Enabled = false;
        _start.Enabled = false;
        _status.Text = "Running...";

        try
        {
            ProcessStartInfo psi = BuildSelfStartInfo();
            psi.ArgumentList.Add("discover");
            foreach (string scanRoot in roots) { psi.ArgumentList.Add("--root"); psi.ArgumentList.Add(scanRoot); }
            psi.ArgumentList.Add("--manifest"); psi.ArgumentList.Add(manifest);
            psi.ArgumentList.Add("--max-cpu-percent"); psi.ArgumentList.Add(_cpu.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("--network-limit-mbps"); psi.ArgumentList.Add(_network.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (_privacy.Checked) psi.ArgumentList.Add("--privacy-mode");

            string? inventory = NullIfWhiteSpace(_inventory.Text);
            if (inventory is not null) { psi.ArgumentList.Add("--backup-inventory"); psi.ArgumentList.Add(inventory); }

            bool remote = hostsFile is not null;
            if (remote)
            {
                psi.ArgumentList.Add("--hosts-file"); psi.ArgumentList.Add(hostsFile!);
                foreach (string share in SplitShares(_shares.Text)) { psi.ArgumentList.Add("--remote-share"); psi.ArgumentList.Add(share); }
                psi.ArgumentList.Add("--username"); psi.ArgumentList.Add(_username.Text.Trim());
                psi.ArgumentList.Add("--password-stdin");
            }

            if (linuxRemote)
            {
                foreach (string host in linuxHosts) { psi.ArgumentList.Add("--linux-host"); psi.ArgumentList.Add(host); }
                foreach (string linuxRoot in SplitLines(_linuxRoots.Text)) { psi.ArgumentList.Add("--linux-root"); psi.ArgumentList.Add(linuxRoot); }
                psi.ArgumentList.Add("--linux-username"); psi.ArgumentList.Add(_linuxUsername.Text.Trim());
                psi.ArgumentList.Add("--linux-password-stdin");
                psi.ArgumentList.Add("--ssh-port"); psi.ArgumentList.Add(_sshPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
                string? fingerprint = NullIfWhiteSpace(_sshFingerprint.Text);
                if (fingerprint is not null) { psi.ArgumentList.Add("--ssh-host-key-sha256"); psi.ArgumentList.Add(fingerprint); }
                if (_sshTofu.Checked) psi.ArgumentList.Add("--ssh-trust-on-first-use");
            }

            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            process.OutputDataReceived += (_, e) => AppendLog(e.Data);
            process.ErrorDataReceived += (_, e) => AppendLog(e.Data);
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (remote)
            {
                string password = _password.Text;
                _password.Clear();
                await process.StandardInput.WriteLineAsync(password);
                password = string.Empty;
            }
            if (linuxRemote)
            {
                string linuxPassword = _linuxPassword.Text;
                _linuxPassword.Clear();
                await process.StandardInput.WriteLineAsync(linuxPassword);
                linuxPassword = string.Empty;
            }
            if (remote || linuxRemote)
            {
                await process.StandardInput.FlushAsync();
                process.StandardInput.Close();
            }

            await process.WaitForExitAsync();
            _status.Text = $"Finished (exit {process.ExitCode})";
            if (File.Exists(manifest))
            {
                LoadManifest(manifest);
                string report = Path.Combine(Path.GetDirectoryName(manifest) ?? Environment.CurrentDirectory, "reports", Path.GetFileNameWithoutExtension(manifest) + "-management-report.html");
                if (File.Exists(report)) { _lastHtmlReport = report; _openReport.Enabled = true; }
                tabs.SelectedIndex = 2;
            }
        }
        catch (Exception ex)
        {
            _status.Text = "Failed";
            AppendLog("GUI error: " + ex.Message);
            MessageBox.Show(this, ex.Message, "SmartBackupDiscovery", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _start.Enabled = true;
        }
    }

    private void LoadManifest(string path)
    {
        DiscoveryManifest manifest = ManifestReader.Read(path);
        BackupReadinessAssessment readiness = manifest.Readiness ?? BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        _score.Text = $"Readiness\n{readiness.Score}/100 ({readiness.Grade})";
        _critical.Text = $"Critical\n{readiness.CriticalCandidateCount:N0}";
        _high.Text = $"High\n{readiness.HighCandidateCount:N0}";
        _mustCopy.Text = $"Must-copy\n{ManagementReportWriter.FormatBytes(manifest.MustCopyVolume.EstimatedBytes)}";
        _gap.Text = $"Uncovered\n{manifest.BackupGap?.UncoveredCandidateCount.ToString("N0") ?? "not assessed"}";
        int changes = manifest.Diff is { PreviousScanAvailable: true } d ? d.AddedCount + d.ChangedCount + d.RemovedCount : 0;
        _changes.Text = $"Changes\n{(manifest.Diff?.PreviousScanAvailable == true ? changes.ToString("N0") : "first scan")}";

        _candidateGrid.DataSource = manifest.Candidates
            .OrderByDescending(x => x.Priority)
            .ThenByDescending(x => x.Score)
            .Take(500)
            .Select(x => new CandidateRow(
                x.Priority.ToString(),
                x.Category.ToString(),
                ManagementReportWriter.FormatBytes(x.Size),
                x.Path,
                x.Evidence.FirstOrDefault()?.Summary ?? x.ReasonCode ?? string.Empty))
            .ToList();
        _status.Text = $"Loaded {Path.GetFileName(path)}";
    }

    private void OpenManifestDialog()
    {
        using var dialog = new OpenFileDialog { Filter = "Discovery manifest|*.json|All files|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            LoadManifest(dialog.FileName);
            string report = Path.Combine(Path.GetDirectoryName(dialog.FileName) ?? Environment.CurrentDirectory, "reports", Path.GetFileNameWithoutExtension(dialog.FileName) + "-management-report.html");
            if (File.Exists(report)) { _lastHtmlReport = report; _openReport.Enabled = true; }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Cannot load manifest", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OpenLastReport()
    {
        if (_lastHtmlReport is null || !File.Exists(_lastHtmlReport)) return;
        Process.Start(new ProcessStartInfo(_lastHtmlReport) { UseShellExecute = true });
    }

    private static ProcessStartInfo BuildSelfStartInfo()
    {
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine executable path.");
        var psi = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true
        };
        string? entry = Assembly.GetEntryAssembly()?.Location;
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(entry))
            psi.ArgumentList.Add(entry);
        return psi;
    }

    private void AppendLog(string? line)
    {
        if (line is null) return;
        if (InvokeRequired) { BeginInvoke(new Action(() => AppendLog(line))); return; }
        if (_log.TextLength > 2_000_000) _log.Clear();
        _log.AppendText(line + Environment.NewLine);
    }

    private void AppendNetworkLog(string? line)
    {
        if (line is null) return;
        if (InvokeRequired) { BeginInvoke(new Action(() => AppendNetworkLog(line))); return; }
        if (_networkLog.TextLength > 2_000_000) _networkLog.Clear();
        _networkLog.AppendText(line + Environment.NewLine);
    }

    private static void AddRow(TableLayoutPanel panel, string label, Control value, Control action)
    {
        int row = panel.RowCount++;
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Padding = new Padding(0, 8, 8, 0) }, 0, row);
        value.Dock = DockStyle.Fill;
        value.Margin = new Padding(3, 4, 3, 4);
        panel.Controls.Add(value, 1, row);
        panel.Controls.Add(action, 2, row);
    }

    private static Button MakeBrowseFolderButton(TextBox target)
    {
        var button = new Button { Text = "Add folder...", AutoSize = true };
        button.Click += (_, _) =>
        {
            using var dialog = new FolderBrowserDialog { ShowNewFolderButton = false };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            if (target.TextLength > 0 && !target.Text.EndsWith(Environment.NewLine, StringComparison.Ordinal)) target.AppendText(Environment.NewLine);
            target.AppendText(dialog.SelectedPath);
        };
        return button;
    }

    private static Button MakeBrowseFileButton(TextBox target, string filter)
    {
        var button = new Button { Text = "Browse...", AutoSize = true };
        button.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog { Filter = filter, CheckFileExists = true };
            if (dialog.ShowDialog() == DialogResult.OK) target.Text = dialog.FileName;
        };
        return button;
    }

    private static Button MakeSaveFileButton(TextBox target)
    {
        var button = new Button { Text = "Browse...", AutoSize = true };
        button.Click += (_, _) =>
        {
            using var dialog = new SaveFileDialog { Filter = "JSON manifest|*.json", FileName = Path.GetFileName(target.Text) };
            if (dialog.ShowDialog() == DialogResult.OK) target.Text = dialog.FileName;
        };
        return button;
    }

    private static Label MetricLabel(string text) => new()
    {
        Text = text,
        TextAlign = System.Drawing.ContentAlignment.MiddleCenter,
        Dock = DockStyle.Fill,
        AutoSize = false,
        Height = 85,
        BorderStyle = BorderStyle.FixedSingle,
        Font = new System.Drawing.Font("Segoe UI", 11F, System.Drawing.FontStyle.Bold),
        Margin = new Padding(5)
    };

    private static List<string> SplitLines(string text) => text
        .Split(["\r\n", "\n", "\r"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static List<string> SplitShares(string text) => text
        .Split([';', ',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static string? NullIfWhiteSpace(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record CandidateRow(string Priority, string Category, string Size, string Path, string Reason);
    private sealed record NetworkHostRow(string IpAddress, string HostName, string Reachability, string PlatformHint, string OpenPorts, string MacAddress);
}

public static class GuiLauncher
{
    public static void Run()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new DashboardForm());
    }
}
