using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace FrontlineSuite
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Shared helpers
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class CommandItem
    {
        public string Title;
        public string FileName;
        public string Arguments;
        public string DisplayCommand;

        public CommandItem(string title, string fileName, string arguments, string displayCommand)
        {
            Title = title;
            FileName = fileName;
            Arguments = arguments;
            DisplayCommand = displayCommand;
        }
    }

    internal sealed class AdapterItem
    {
        public string Name;
        public string Description;
        public IPAddress IpAddress;
        public IPAddress SubnetMask;
        public List<string> DnsAddresses = new List<string>();

        public override string ToString() { return Name + " - " + IpAddress; }

        public void RefreshDns()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!String.Equals(nic.Name, Name, StringComparison.OrdinalIgnoreCase)) continue;
                DnsAddresses = nic.GetIPProperties().DnsAddresses
                    .Cast<IPAddress>()
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.ToString())
                    .ToList();
                return;
            }
            DnsAddresses = new List<string>();
        }
    }

    internal sealed class DeviceRow
    {
        public string Timestamp = "";
        public string Adapter = "";
        public string IpAddress = "";
        public string MacAddress = "";
        public string Hostname = "";
        public string Status = "";
        public string OpenServices = "";
        public string RiskNotes = "";
    }

    internal enum SuiteTabIndex
    {
        Dashboard = 0,
        CheckupReport = 1,
        SecurityScan = 2,
        NetworkShield = 3,
        SystemHealth = 4,
        StartupManager = 5,
        WindowsUpdate = 6,
        EventLog = 7,
        JunkCleaner = 8,
        HostsFile = 9,
        Firewall = 10
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Main window – tab container
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class MainForm : Form
    {
        private const string AppName    = "Frontline Suite";
        private const string AppVersion = "4.4.0";

        private readonly Color _bg     = Color.FromArgb(10, 12, 16);
        private readonly Color _panel  = Color.FromArgb(17, 21, 32);
        private readonly Color _panel2 = Color.FromArgb(24, 29, 42);
        private readonly Color _orange = Color.FromArgb(244, 120, 32);
        private readonly Color _blue   = Color.FromArgb(41, 168, 224);
        private readonly Color _text   = Color.FromArgb(232, 234, 240);
        private readonly Color _muted  = Color.FromArgb(148, 156, 176);

        private readonly string _logsDir;
        private TabControl _tabs;

        public MainForm()
        {
            _logsDir = Path.Combine(Application.StartupPath, "logs");
            Directory.CreateDirectory(_logsDir);
            Directory.CreateDirectory(Path.Combine(Application.StartupPath, "data"));

            Text = AppName + " v" + AppVersion;
            MinimumSize = new Size(1100, 780);
            Size = new Size(1200, 840);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = _bg;
            ForeColor = _text;
            Font = new Font("Segoe UI", 10F, FontStyle.Regular);
            Icon = LoadIconSafe();

            BuildLayout();
        }

        private Icon LoadIconSafe()
        {
            try
            {
                string p = Path.Combine(Application.StartupPath, "assets", "frontline_logo.ico");
                if (File.Exists(p)) return new Icon(p);
            }
            catch { }
            return null;
        }

        private void BuildLayout()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.RowCount = 3;
            root.ColumnCount = 1;
            root.Padding = new Padding(14);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            Controls.Add(root);

            root.Controls.Add(BuildHeader(), 0, 0);

            _tabs = new TabControl();
            _tabs.Dock = DockStyle.Fill;
            _tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            _tabs.ItemSize = new Size(132, 36);
            _tabs.Multiline = true;
            _tabs.SizeMode = TabSizeMode.Fixed;
            _tabs.Appearance = TabAppearance.Normal;
            _tabs.BackColor = _bg;
            _tabs.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            _tabs.DrawItem += DrawTab;
            _tabs.Padding = new Point(8, 6);

            TabPage dashboardPage = new TabPage("  Dashboard");
            dashboardPage.BackColor = _bg;
            dashboardPage.Padding = new Padding(0);
            dashboardPage.Controls.Add(new DashboardPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted, delegate(SuiteTabIndex tab) { _tabs.SelectedIndex = (int)tab; }));

            TabPage checkupPage = new TabPage("  Checkup Report");
            checkupPage.BackColor = _bg;
            checkupPage.Padding = new Padding(0);
            checkupPage.Controls.Add(new CheckupReportPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage scannerPage = new TabPage("  Security Scan");
            scannerPage.BackColor = _bg;
            scannerPage.Padding = new Padding(0);
            scannerPage.Controls.Add(new ScannerPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage shieldPage = new TabPage("  Network Shield");
            shieldPage.BackColor = _bg;
            shieldPage.Padding = new Padding(0);
            shieldPage.Controls.Add(new NetworkPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage healthPage = new TabPage("  System Health");
            healthPage.BackColor = _bg;
            healthPage.Padding = new Padding(0);
            healthPage.Controls.Add(new SystemHealthPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage startupPage = new TabPage("  Startup Manager");
            startupPage.BackColor = _bg;
            startupPage.Padding = new Padding(0);
            startupPage.Controls.Add(new StartupPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage updatePage = new TabPage("  Windows Update");
            updatePage.BackColor = _bg;
            updatePage.Padding = new Padding(0);
            updatePage.Controls.Add(new WindowsUpdatePanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage eventLogPage = new TabPage("  Event Log");
            eventLogPage.BackColor = _bg;
            eventLogPage.Padding = new Padding(0);
            eventLogPage.Controls.Add(new EventLogPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage cleanerPage = new TabPage("  Junk Cleaner");
            cleanerPage.BackColor = _bg;
            cleanerPage.Padding = new Padding(0);
            cleanerPage.Controls.Add(new JunkCleanerPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage hostsPage = new TabPage("  Hosts File");
            hostsPage.BackColor = _bg;
            hostsPage.Padding = new Padding(0);
            hostsPage.Controls.Add(new HostsFilePanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage firewallPage = new TabPage("  Firewall");
            firewallPage.BackColor = _bg;
            firewallPage.Padding = new Padding(0);
            firewallPage.Controls.Add(new FirewallPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            _tabs.TabPages.Add(dashboardPage);
            _tabs.TabPages.Add(checkupPage);
            _tabs.TabPages.Add(scannerPage);
            _tabs.TabPages.Add(shieldPage);
            _tabs.TabPages.Add(healthPage);
            _tabs.TabPages.Add(startupPage);
            _tabs.TabPages.Add(updatePage);
            _tabs.TabPages.Add(eventLogPage);
            _tabs.TabPages.Add(cleanerPage);
            _tabs.TabPages.Add(hostsPage);
            _tabs.TabPages.Add(firewallPage);

            _tabs.ItemSize = new Size(132, 36);

            root.Controls.Add(_tabs, 0, 1);
            root.Controls.Add(BuildFooter(), 0, 2);
        }

        private void DrawTab(object sender, DrawItemEventArgs e)
        {
            TabControl tc = sender as TabControl;
            if (tc == null) return;
            bool selected = (e.Index == tc.SelectedIndex);
            Color bg = selected ? _orange : _panel2;
            Color fg = selected ? Color.White : _muted;
            e.Graphics.FillRectangle(new SolidBrush(bg), e.Bounds);
            TextRenderer.DrawText(e.Graphics, tc.TabPages[e.Index].Text, tc.Font,
                e.Bounds, fg, TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter);
        }

        private Control BuildHeader()
        {
            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            header.BackColor = _panel;
            header.Padding = new Padding(16, 10, 16, 10);
            header.Paint += delegate(object s, PaintEventArgs e)
            {
                using (Pen p = new Pen(_orange, 3))
                    e.Graphics.DrawLine(p, 0, header.Height - 2, header.Width, header.Height - 2);
            };

            PictureBox logo = new PictureBox();
            logo.Size = new Size(64, 64);
            logo.Location = new Point(16, 12);
            logo.SizeMode = PictureBoxSizeMode.Zoom;
            logo.BackColor = Color.Transparent;
            string logoPath = Path.Combine(Application.StartupPath, "assets", "frontline_logo.png");
            if (File.Exists(logoPath)) { try { logo.Image = new Bitmap(logoPath); } catch { } }
            header.Controls.Add(logo);

            Label title = new Label();
            title.AutoSize = true;
            title.Location = new Point(92, 12);
            title.Text = "FRONTLINE SUITE";
            title.ForeColor = _text;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold);
            header.Controls.Add(title);

            Label sub = new Label();
            sub.AutoSize = true;
            sub.Location = new Point(96, 54);
            sub.Text = "Local security, network, and system maintenance toolkit";
            sub.ForeColor = _muted;
            sub.Font = new Font("Segoe UI", 10F, FontStyle.Regular);
            header.Controls.Add(sub);

            Label badge = new Label();
            badge.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            badge.AutoSize = false;
            badge.TextAlign = ContentAlignment.MiddleRight;
            badge.Size = new Size(390, 60);
            badge.Text = "v" + AppVersion + "  •  LOCAL ONLY" + "\r\n" + (IsAdministrator() ? "ADMIN MODE ENABLED" : "STANDARD MODE - RUN AS ADMIN FOR FULL TOOLS");
            badge.ForeColor = IsAdministrator() ? _blue : _orange;
            badge.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold);
            header.Controls.Add(badge);
            header.Resize += delegate { badge.Location = new Point(header.ClientSize.Width - badge.Width - 20, 18); };
            badge.Location = new Point(800, 18);
            return header;
        }

        private Control BuildFooter()
        {
            Label footer = new Label();
            footer.Dock = DockStyle.Fill;
            footer.TextAlign = ContentAlignment.MiddleRight;
            footer.ForeColor = _muted;
            footer.Text = "Frontline Tech Consulting, LLC  •  Local logs only  •  Use only on systems and networks you own or have permission to assess";
            footer.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            return footer;
        }

        private static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Dashboard tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class DashboardPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly string _logsDir;
        private readonly Action<SuiteTabIndex> _openTab;
        private readonly List<Label> _dynamicLabels = new List<Label>();
        private System.Windows.Forms.Timer _refreshTimer;

        public DashboardPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted, Action<SuiteTabIndex> openTab)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            _openTab = openTab;

            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            RefreshCards();

            _refreshTimer = new System.Windows.Forms.Timer();
            _refreshTimer.Interval = 15000;
            _refreshTimer.Tick += delegate { RefreshCards(); };
            _refreshTimer.Start();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _refreshTimer != null) _refreshTimer.Dispose();
            base.Dispose(disposing);
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.Padding = new Padding(0, 8, 0, 0);
            root.ColumnCount = 1;
            root.RowCount = 3;
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 165));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 218));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            root.Controls.Add(BuildHero(), 0, 0);
            root.Controls.Add(BuildCards(), 0, 1);
            root.Controls.Add(BuildWorkflow(), 0, 2);
        }

        private Control BuildHero()
        {
            Panel hero = new Panel();
            hero.Dock = DockStyle.Fill;
            hero.BackColor = _panel;
            hero.Padding = new Padding(18);
            hero.Paint += delegate(object s, PaintEventArgs e)
            {
                using (Pen p = new Pen(_orange, 3))
                    e.Graphics.DrawLine(p, 0, hero.Height - 2, hero.Width, hero.Height - 2);
            };

            Label title = new Label();
            title.AutoSize = true;
            title.Location = new Point(22, 18);
            title.Text = "Dashboard";
            title.ForeColor = _text;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold);
            hero.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.AutoSize = false;
            subtitle.Location = new Point(24, 62);
            subtitle.Size = new Size(720, 44);
            subtitle.Text = "Quick view of this PC, recent logs, and the safest next actions. Start with a checkup report, run a scan, review the network, then export logs for customer documentation.";
            subtitle.ForeColor = _muted;
            subtitle.Font = new Font("Segoe UI", 10.5F, FontStyle.Regular);
            hero.Controls.Add(subtitle);

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Location = new Point(20, 112);
            actions.Size = new Size(1040, 44);
            actions.BackColor = _panel;
            actions.WrapContents = false;
            hero.Controls.Add(actions);

            actions.Controls.Add(ActionButton("Create Report", delegate { _openTab(SuiteTabIndex.CheckupReport); }));
            actions.Controls.Add(ActionButton("Start Security Scan", delegate { _openTab(SuiteTabIndex.SecurityScan); }));
            actions.Controls.Add(ActionButton("Review Network", delegate { _openTab(SuiteTabIndex.NetworkShield); }));
            actions.Controls.Add(ActionButton("System Health", delegate { _openTab(SuiteTabIndex.SystemHealth); }));
            actions.Controls.Add(ActionButton("Open Logs", delegate { OpenLogsFolder(); }));

            Label mode = new Label();
            mode.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            mode.AutoSize = false;
            mode.Size = new Size(300, 72);
            mode.TextAlign = ContentAlignment.MiddleRight;
            mode.Location = new Point(850, 22);
            mode.ForeColor = IsAdministrator() ? _blue : _orange;
            mode.Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold);
            mode.Text = IsAdministrator() ? "ADMIN MODE\r\nAll tools available" : "STANDARD MODE\r\nRun as administrator for full tools";
            hero.Controls.Add(mode);
            hero.Resize += delegate { mode.Location = new Point(hero.ClientSize.Width - mode.Width - 24, 22); };

            return hero;
        }

        private Button ActionButton(string text, EventHandler click)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Size = new Size(165, 36);
            btn.Margin = new Padding(4, 2, 8, 2);
            btn.BackColor = _panel2;
            btn.ForeColor = _text;
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold);
            btn.Cursor = Cursors.Hand;
            btn.Click += click;
            return btn;
        }

        private Control BuildCards()
        {
            TableLayoutPanel grid = new TableLayoutPanel();
            grid.Dock = DockStyle.Fill;
            grid.BackColor = _bg;
            grid.Padding = new Padding(0, 12, 0, 0);
            grid.ColumnCount = 4;
            grid.RowCount = 2;
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            for (int r = 0; r < 2; r++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

            grid.Controls.Add(MetricCard("Security Mode", "Checking...", "Administrator access status", _blue), 0, 0);
            grid.Controls.Add(MetricCard("Local IP", "Checking...", "Primary IPv4 address", _orange), 1, 0);
            grid.Controls.Add(MetricCard("System Drive", "Checking...", "Free space on C:\\", _blue), 2, 0);
            grid.Controls.Add(MetricCard("Recent Logs", "Checking...", "Files saved in logs folder", _orange), 3, 0);
            grid.Controls.Add(MetricCard("Pending Reboot", "Checking...", "Windows servicing state", _orange), 0, 1);
            grid.Controls.Add(MetricCard("Firewall", "Use manager", "Review enabled/disabled rules", _blue), 1, 1);
            grid.Controls.Add(MetricCard("DNS", "Use shield", "Harden or reset DNS settings", _blue), 2, 1);
            grid.Controls.Add(MetricCard("Last Refresh", "Checking...", "Dashboard auto-refreshes", _orange), 3, 1);
            return grid;
        }

        private Panel MetricCard(string titleText, string valueText, string detailText, Color accent)
        {
            Panel card = new Panel();
            card.Dock = DockStyle.Fill;
            card.Margin = new Padding(0, 0, 10, 10);
            card.BackColor = _panel2;
            card.Padding = new Padding(14);
            card.Paint += delegate(object s, PaintEventArgs e)
            {
                using (Pen p = new Pen(accent, 2))
                    e.Graphics.DrawLine(p, 0, 0, card.Width, 0);
            };

            Label title = new Label();
            title.AutoSize = false;
            title.Location = new Point(14, 12);
            title.Size = new Size(240, 22);
            title.Text = titleText;
            title.ForeColor = _muted;
            title.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold);
            card.Controls.Add(title);

            Label value = new Label();
            value.AutoSize = false;
            value.Location = new Point(14, 38);
            value.Size = new Size(250, 34);
            value.Text = valueText;
            value.ForeColor = _text;
            value.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
            card.Controls.Add(value);
            _dynamicLabels.Add(value);

            Label detail = new Label();
            detail.AutoSize = false;
            detail.Location = new Point(15, 76);
            detail.Size = new Size(250, 24);
            detail.Text = detailText;
            detail.ForeColor = _muted;
            detail.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            card.Controls.Add(detail);

            return card;
        }

        private Control BuildWorkflow()
        {
            TableLayoutPanel wrap = new TableLayoutPanel();
            wrap.Dock = DockStyle.Fill;
            wrap.BackColor = _panel;
            wrap.Margin = new Padding(0, 4, 0, 0);
            wrap.Padding = new Padding(18);
            wrap.ColumnCount = 2;
            wrap.RowCount = 1;
            wrap.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            wrap.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));

            Label workflow = new Label();
            workflow.Dock = DockStyle.Fill;
            workflow.ForeColor = _text;
            workflow.Font = new Font("Segoe UI", 10.5F, FontStyle.Regular);
            workflow.Text = "Recommended workflow\r\n\r\n1. Generate a Frontline Checkup Report before making changes.\r\n2. Run Defender status and a Quick Scan.\r\n3. Review DNS settings and scan the local network.\r\n4. Run System Health before changing Windows settings.\r\n5. Export logs after the work is complete.\r\n\r\nThis layout keeps the customer-facing path simple while the advanced tabs remain available for deeper troubleshooting.";
            wrap.Controls.Add(workflow, 0, 0);

            Label notes = new Label();
            notes.Dock = DockStyle.Fill;
            notes.ForeColor = _muted;
            notes.Font = new Font("Segoe UI", 10F, FontStyle.Regular);
            notes.Text = "Professional polish added in v4.4.0\r\n\r\n• Customer-facing Checkup Report tab\r\n• TXT and HTML report exports\r\n• Named tab indexes for dashboard actions\r\n• Dashboard-first workflow retained\r\n• Better customer handoff documentation\r\n• Clear admin-mode indicator";
            wrap.Controls.Add(notes, 1, 0);
            return wrap;
        }

        private void RefreshCards()
        {
            if (_dynamicLabels.Count < 8) return;

            _dynamicLabels[0].Text = IsAdministrator() ? "Admin" : "Standard";
            _dynamicLabels[1].Text = GetPrimaryIPv4();
            _dynamicLabels[2].Text = GetSystemDriveFree();
            _dynamicLabels[3].Text = GetLogSummary();
            _dynamicLabels[4].Text = IsPendingReboot() ? "Yes" : "No";
            _dynamicLabels[5].Text = "Review";
            _dynamicLabels[6].Text = "Harden";
            _dynamicLabels[7].Text = DateTime.Now.ToString("h:mm tt");
        }

        private void OpenLogsFolder()
        {
            try
            {
                Directory.CreateDirectory(_logsDir);
                Process.Start("explorer.exe", _logsDir);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ParentForm, ex.Message, "Open Logs", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static string GetPrimaryIPv4()
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation uni in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == AddressFamily.InterNetwork)
                            return uni.Address.ToString();
                    }
                }
            }
            catch { }
            return "Not found";
        }

        private static string GetSystemDriveFree()
        {
            try
            {
                DriveInfo d = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory));
                double free = d.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0;
                return free.ToString("0.0") + " GB";
            }
            catch { return "Unknown"; }
        }

        private string GetLogSummary()
        {
            try
            {
                if (!Directory.Exists(_logsDir)) return "0 files";
                int count = Directory.GetFiles(_logsDir).Length;
                return count.ToString() + (count == 1 ? " file" : " files");
            }
            catch { return "Unknown"; }
        }

        private static bool IsPendingReboot()
        {
            try
            {
                string[] keys = new string[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                    @"SYSTEM\CurrentControlSet\Control\Session Manager"
                };
                if (Registry.LocalMachine.OpenSubKey(keys[0]) != null) return true;
                if (Registry.LocalMachine.OpenSubKey(keys[1]) != null) return true;
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(keys[2]))
                {
                    if (k != null && k.GetValue("PendingFileRenameOperations") != null) return true;
                }
            }
            catch { }
            return false;
        }

        private static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }
    }


    // ─────────────────────────────────────────────────────────────────────────
    //  Frontline Checkup Report tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class CheckupReportPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly string _logsDir;
        private readonly List<Button> _buttons = new List<Button>();
        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private bool _isRunning;
        private string _lastReportText = "";
        private string _lastReportHtml = "";
        private string _lastTxtPath = "";
        private string _lastHtmlPath = "";

        public CheckupReportPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;

            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Frontline Checkup Report ready.");
            AppendOutput("Run this before making changes to create a customer-facing baseline report.");
            AppendOutput("Reports are saved locally in the logs folder as TXT and HTML.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.RowCount = 3;
            root.ColumnCount = 1;
            root.Padding = new Padding(0, 8, 0, 0);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            root.Controls.Add(BuildTopPanel(), 0, 0);
            root.Controls.Add(BuildStatusPanel(), 0, 1);
            root.Controls.Add(BuildOutputBox(), 0, 2);
        }

        private Control BuildTopPanel()
        {
            Panel top = new Panel();
            top.Dock = DockStyle.Fill;
            top.BackColor = _panel;
            top.Padding = new Padding(18);
            top.Paint += delegate(object s, PaintEventArgs e)
            {
                using (Pen p = new Pen(_orange, 3))
                    e.Graphics.DrawLine(p, 0, top.Height - 2, top.Width, top.Height - 2);
            };

            Label title = new Label();
            title.AutoSize = true;
            title.Location = new Point(22, 18);
            title.Text = "Frontline Checkup Report";
            title.ForeColor = _text;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold);
            top.Controls.Add(title);

            Label desc = new Label();
            desc.AutoSize = false;
            desc.Location = new Point(24, 62);
            desc.Size = new Size(900, 42);
            desc.Text = "Create a branded local report with system, network, security, storage, and recommendation sections. Use it as a before-work baseline or customer handoff note.";
            desc.ForeColor = _muted;
            desc.Font = new Font("Segoe UI", 10.5F, FontStyle.Regular);
            top.Controls.Add(desc);

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Location = new Point(20, 112);
            actions.Size = new Size(1080, 44);
            actions.BackColor = _panel;
            actions.WrapContents = false;
            top.Controls.Add(actions);

            actions.Controls.Add(ActionButton("Run Checkup Report", delegate { RunCheckup(); }, 190));
            actions.Controls.Add(ActionButton("Open HTML Report", delegate { OpenHtmlReport(); }, 175));
            actions.Controls.Add(ActionButton("Copy Summary", delegate { CopyReport(); }, 145));
            actions.Controls.Add(ActionButton("Save As...", delegate { SaveAsReport(); }, 130));
            actions.Controls.Add(ActionButton("Open Reports Folder", delegate { OpenReportsFolder(); }, 180));

            Label mode = new Label();
            mode.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            mode.AutoSize = false;
            mode.Size = new Size(330, 70);
            mode.TextAlign = ContentAlignment.MiddleRight;
            mode.ForeColor = IsAdministrator() ? _blue : _orange;
            mode.Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold);
            mode.Text = IsAdministrator() ? "ADMIN MODE\r\nFull local checks available" : "STANDARD MODE\r\nSome checks may be limited";
            top.Controls.Add(mode);
            top.Resize += delegate { mode.Location = new Point(top.ClientSize.Width - mode.Width - 24, 22); };
            mode.Location = new Point(760, 22);

            return top;
        }

        private Button ActionButton(string text, EventHandler click, int width)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Size = new Size(width, 36);
            btn.Margin = new Padding(4, 2, 8, 2);
            btn.BackColor = _panel2;
            btn.ForeColor = _text;
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold);
            btn.Cursor = Cursors.Hand;
            btn.Click += click;
            _buttons.Add(btn);
            return btn;
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.Dock = DockStyle.Fill;
            p.BackColor = _bg;
            p.ColumnCount = 2;
            p.Padding = new Padding(0, 8, 0, 4);
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));

            _statusLabel = new Label();
            _statusLabel.Text = "Ready";
            _statusLabel.ForeColor = _muted;
            _statusLabel.Dock = DockStyle.Fill;
            _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            p.Controls.Add(_statusLabel, 0, 0);

            _progressBar = new ProgressBar();
            _progressBar.Dock = DockStyle.Fill;
            _progressBar.Style = ProgressBarStyle.Blocks;
            _progressBar.Minimum = 0;
            _progressBar.Maximum = 100;
            _progressBar.Value = 0;
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox();
            _outputBox.Dock = DockStyle.Fill;
            _outputBox.Multiline = true;
            _outputBox.ReadOnly = true;
            _outputBox.ScrollBars = ScrollBars.Both;
            _outputBox.WordWrap = false;
            _outputBox.BackColor = Color.FromArgb(5, 7, 9);
            _outputBox.ForeColor = Color.FromArgb(107, 218, 143);
            _outputBox.Font = new Font("Consolas", 10F, FontStyle.Regular);
            _outputBox.BorderStyle = BorderStyle.FixedSingle;
            return _outputBox;
        }

        private void RunCheckup()
        {
            if (_isRunning)
            {
                MessageBox.Show(ParentForm, "A checkup report is already running.", "Frontline Suite", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            _isRunning = true;
            SetButtonsEnabled(false);
            SetStatus("Generating Frontline Checkup Report...", true);
            ClearOutput();
            AppendOutput("[" + Now() + "] Collecting local system information...");

            Thread worker = new Thread(delegate()
            {
                try
                {
                    string report = BuildReportText();
                    string html = BuildReportHtml(report);
                    Directory.CreateDirectory(_logsDir);
                    string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string txtPath = Path.Combine(_logsDir, "frontline_checkup_report_" + stamp + ".txt");
                    string htmlPath = Path.Combine(_logsDir, "frontline_checkup_report_" + stamp + ".html");
                    File.WriteAllText(txtPath, report, Encoding.UTF8);
                    File.WriteAllText(htmlPath, html, Encoding.UTF8);

                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        _lastReportText = report;
                        _lastReportHtml = html;
                        _lastTxtPath = txtPath;
                        _lastHtmlPath = htmlPath;
                        _outputBox.Text = report;
                        _outputBox.SelectionStart = 0;
                        _outputBox.ScrollToCaret();
                        AppendOutput("");
                        AppendOutput("[" + Now() + "] TXT saved:  " + txtPath);
                        AppendOutput("[" + Now() + "] HTML saved: " + htmlPath);
                    }));
                }
                catch (Exception ex)
                {
                    AppendOutput("ERROR: " + ex.Message);
                }
                finally
                {
                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        _isRunning = false;
                        SetButtonsEnabled(true);
                        SetStatus("Ready", false);
                    }));
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        private string BuildReportText()
        {
            StringBuilder sb = new StringBuilder();
            List<string> recommendations = new List<string>();
            bool admin = IsAdministrator();
            bool pendingReboot = IsPendingReboot();
            double freeGb = -1;

            string windows = GetWindowsVersion();
            string drive = GetSystemDriveInfo(out freeGb);
            string localIp = GetPrimaryIPv4();
            string dns = GetDnsSummary();
            string adapterSummary = GetAdapterSummary();
            string defender = GetDefenderSummary();
            string firewall = GetFirewallSummary();
            string logInventory = GetLogInventory();

            if (!admin) recommendations.Add("Rerun Frontline Suite as Administrator before performing DNS, firewall, Defender, DISM, SFC, startup, or hosts-file changes.");
            if (pendingReboot) recommendations.Add("A reboot appears to be pending. Restart the computer after customer approval before continuing deeper maintenance.");
            if (freeGb >= 0 && freeGb < 20) recommendations.Add("System drive free space is below 20 GB. Review downloads, temp files, old installers, and restore points before major updates.");
            if (defender.IndexOf("RealTimeProtectionEnabled : False", StringComparison.OrdinalIgnoreCase) >= 0 || defender.IndexOf("RealTimeProtectionEnabled: False", StringComparison.OrdinalIgnoreCase) >= 0)
                recommendations.Add("Microsoft Defender real-time protection appears disabled. Verify the active antivirus configuration.");
            if (recommendations.Count == 0) recommendations.Add("No urgent baseline issue was detected by the lightweight checkup. Continue with the normal scan, network review, and customer-approved cleanup workflow.");

            sb.AppendLine("============================================================");
            sb.AppendLine("FRONTLINE CHECKUP REPORT");
            sb.AppendLine("Frontline Tech Consulting, LLC");
            sb.AppendLine("============================================================");
            sb.AppendLine("Generated:       " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Computer:        " + Environment.MachineName);
            sb.AppendLine("User:            " + Environment.UserName);
            sb.AppendLine("Admin Mode:      " + (admin ? "Yes" : "No"));
            sb.AppendLine("Report Location: Local logs folder only");
            sb.AppendLine();

            sb.AppendLine("IMPORTANT NOTE");
            sb.AppendLine("This report is a local maintenance snapshot. It does not prove compliance, guarantee that malware is absent, or replace a full security assessment.");
            sb.AppendLine();

            sb.AppendLine("1. SYSTEM OVERVIEW");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine("Windows:         " + windows);
            sb.AppendLine("Architecture:    " + (Environment.Is64BitOperatingSystem ? "64-bit OS" : "32-bit OS"));
            sb.AppendLine("Uptime:          " + GetUptime());
            sb.AppendLine("Pending Reboot:  " + (pendingReboot ? "Yes" : "No"));
            sb.AppendLine();

            sb.AppendLine("2. STORAGE SNAPSHOT");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine(drive);
            sb.AppendLine();

            sb.AppendLine("3. NETWORK SNAPSHOT");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine("Primary IPv4:    " + localIp);
            sb.AppendLine();
            sb.AppendLine("Active Adapters:");
            sb.AppendLine(adapterSummary);
            sb.AppendLine();
            sb.AppendLine("DNS Servers:");
            sb.AppendLine(dns);
            sb.AppendLine();

            sb.AppendLine("4. SECURITY SNAPSHOT");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine("Microsoft Defender:");
            sb.AppendLine(defender.Trim().Length == 0 ? "No Defender status returned." : defender.Trim());
            sb.AppendLine();
            sb.AppendLine("Windows Firewall:");
            sb.AppendLine(firewall.Trim().Length == 0 ? "No firewall status returned." : firewall.Trim());
            sb.AppendLine();

            sb.AppendLine("5. LOCAL LOG INVENTORY");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine(logInventory);
            sb.AppendLine();

            sb.AppendLine("6. RECOMMENDED NEXT ACTIONS");
            sb.AppendLine("------------------------------------------------------------");
            for (int i = 0; i < recommendations.Count; i++)
                sb.AppendLine((i + 1).ToString() + ". " + recommendations[i]);
            sb.AppendLine();

            sb.AppendLine("7. SUGGESTED FRONTLINE WORKFLOW");
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine("1. Save this report as the before-work baseline.");
            sb.AppendLine("2. Run Defender Status and Quick Scan from the Security Scan tab.");
            sb.AppendLine("3. Review DNS settings and local devices from the Network Shield tab.");
            sb.AppendLine("4. Run System Health before applying Windows repair actions.");
            sb.AppendLine("5. Save final logs and provide the customer with the report and completed-work notes.");
            sb.AppendLine();
            sb.AppendLine("============================================================");
            sb.AppendLine("End of Frontline Checkup Report");
            sb.AppendLine("============================================================");
            return sb.ToString();
        }

        private string BuildReportHtml(string textReport)
        {
            string encoded = WebUtility.HtmlEncode(textReport).Replace("\r\n", "<br>").Replace("\n", "<br>");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!doctype html>");
            sb.AppendLine("<html><head><meta charset=\"utf-8\"><title>Frontline Checkup Report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body{margin:0;background:#0a0c10;color:#e8eaf0;font-family:Segoe UI,Arial,sans-serif;} .wrap{max-width:1100px;margin:0 auto;padding:32px;} .hero{border-top:5px solid #f47820;background:#111520;padding:24px;margin-bottom:18px;} h1{margin:0;color:#fff;font-size:30px;} .sub{color:#94a0b5;margin-top:6px;} pre{white-space:pre-wrap;background:#050709;border:1px solid #263044;border-top:3px solid #29a8e0;padding:22px;line-height:1.45;font-size:14px;} .badge{display:inline-block;margin-top:14px;padding:7px 11px;border:1px solid #f47820;color:#f47820;font-weight:700;} .foot{color:#94a0b5;font-size:12px;margin-top:16px;text-align:right;}");
            sb.AppendLine("</style></head><body><div class=\"wrap\"><div class=\"hero\"><h1>Frontline Checkup Report</h1><div class=\"sub\">Frontline Tech Consulting, LLC • Local maintenance snapshot</div><div class=\"badge\">Generated Locally</div></div>");
            sb.AppendLine("<pre>" + encoded + "</pre>");
            sb.AppendLine("<div class=\"foot\">Use only on systems and networks you own or have permission to assess.</div></div></body></html>");
            return sb.ToString();
        }

        private string GetWindowsVersion()
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (k != null)
                    {
                        string product = Convert.ToString(k.GetValue("ProductName"));
                        string display = Convert.ToString(k.GetValue("DisplayVersion"));
                        string build = Convert.ToString(k.GetValue("CurrentBuild"));
                        string ubr = Convert.ToString(k.GetValue("UBR"));
                        string result = product;
                        if (!String.IsNullOrWhiteSpace(display)) result += " " + display;
                        if (!String.IsNullOrWhiteSpace(build)) result += " (Build " + build + (String.IsNullOrWhiteSpace(ubr) ? "" : "." + ubr) + ")";
                        if (!String.IsNullOrWhiteSpace(result)) return result;
                    }
                }
            }
            catch { }
            return Environment.OSVersion.VersionString;
        }

        private string GetSystemDriveInfo(out double freeGb)
        {
            freeGb = -1;
            try
            {
                DriveInfo d = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory));
                double totalGb = d.TotalSize / 1024.0 / 1024.0 / 1024.0;
                freeGb = d.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0;
                double usedPct = totalGb <= 0 ? 0 : ((totalGb - freeGb) / totalGb) * 100.0;
                return d.Name + "  Free: " + freeGb.ToString("0.0") + " GB of " + totalGb.ToString("0.0") + " GB  Used: " + usedPct.ToString("0") + "%";
            }
            catch (Exception ex) { return "System drive information unavailable: " + ex.Message; }
        }

        private string GetPrimaryIPv4()
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation uni in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == AddressFamily.InterNetwork)
                            return uni.Address.ToString();
                    }
                }
            }
            catch { }
            return "Not found";
        }

        private string GetAdapterSummary()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    List<string> ips = new List<string>();
                    foreach (UnicastIPAddressInformation uni in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == AddressFamily.InterNetwork) ips.Add(uni.Address.ToString());
                    }
                    sb.AppendLine("- " + nic.Name + " | " + nic.NetworkInterfaceType + " | " + (ips.Count == 0 ? "No IPv4" : String.Join(", ", ips.ToArray())));
                }
            }
            catch (Exception ex) { sb.AppendLine("Adapter check failed: " + ex.Message); }
            if (sb.Length == 0) sb.AppendLine("No active non-loopback adapter found.");
            return sb.ToString().TrimEnd();
        }

        private string GetDnsSummary()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    List<string> dns = new List<string>();
                    foreach (IPAddress a in nic.GetIPProperties().DnsAddresses)
                    {
                        if (a.AddressFamily == AddressFamily.InterNetwork) dns.Add(a.ToString());
                    }
                    if (dns.Count > 0) sb.AppendLine("- " + nic.Name + ": " + String.Join(", ", dns.ToArray()));
                }
            }
            catch (Exception ex) { sb.AppendLine("DNS check failed: " + ex.Message); }
            if (sb.Length == 0) sb.AppendLine("No IPv4 DNS servers found on active adapters.");
            return sb.ToString().TrimEnd();
        }

        private string GetDefenderSummary()
        {
            string command = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareSignatureVersion,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | Format-List";
            string result = RunPowerShell(command, 15000);
            if (result.IndexOf("Get-MpComputerStatus", StringComparison.OrdinalIgnoreCase) >= 0 && result.IndexOf("not recognized", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Microsoft Defender PowerShell cmdlets were not available on this system.";
            return result;
        }

        private string GetFirewallSummary()
        {
            string command = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize";
            string result = RunPowerShell(command, 15000);
            if (String.IsNullOrWhiteSpace(result)) result = RunProcessText("netsh.exe", "advfirewall show allprofiles", 15000);
            return result;
        }

        private string GetLogInventory()
        {
            try
            {
                Directory.CreateDirectory(_logsDir);
                string[] files = Directory.GetFiles(_logsDir);
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Logs folder: " + _logsDir);
                sb.AppendLine("Total files: " + files.Length.ToString());
                foreach (string f in files.OrderByDescending(x => File.GetLastWriteTime(x)).Take(5))
                {
                    FileInfo info = new FileInfo(f);
                    sb.AppendLine("- " + info.Name + " | " + info.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + " | " + FormatBytes(info.Length));
                }
                return sb.ToString().TrimEnd();
            }
            catch (Exception ex) { return "Log inventory unavailable: " + ex.Message; }
        }

        private string RunPowerShell(string command, int timeoutMs)
        {
            return RunProcessText("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command " + Q(command), timeoutMs);
        }

        private string RunProcessText(string fileName, string arguments, int timeoutMs)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fileName;
                psi.Arguments = arguments;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = new Process())
                {
                    p.StartInfo = psi;
                    p.Start();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch { }
                        return "Command timed out: " + fileName;
                    }
                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    if (!String.IsNullOrWhiteSpace(error)) output += Environment.NewLine + "ERROR: " + error.Trim();
                    return output.Trim();
                }
            }
            catch (Exception ex) { return "Command failed: " + ex.Message; }
        }

        private bool IsPendingReboot()
        {
            try
            {
                if (Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") != null) return true;
                if (Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") != null) return true;
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    if (k != null && k.GetValue("PendingFileRenameOperations") != null) return true;
                }
            }
            catch { }
            return false;
        }

        private string GetUptime()
        {
            try
            {
                int ticks = Environment.TickCount & Int32.MaxValue;
                TimeSpan up = TimeSpan.FromMilliseconds(ticks);
                return up.Days.ToString() + "d " + up.Hours.ToString() + "h " + up.Minutes.ToString() + "m";
            }
            catch { return "Unknown"; }
        }

        private string FormatBytes(long bytes)
        {
            double v = bytes;
            string[] units = new string[] { "B", "KB", "MB", "GB" };
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return v.ToString("0.0") + " " + units[i];
        }

        private void OpenHtmlReport()
        {
            if (String.IsNullOrWhiteSpace(_lastHtmlPath) || !File.Exists(_lastHtmlPath))
            {
                MessageBox.Show(ParentForm, "Run a checkup report first.", "Frontline Checkup Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try { Process.Start(new ProcessStartInfo { FileName = _lastHtmlPath, UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show(ParentForm, ex.Message, "Open Report", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void CopyReport()
        {
            if (String.IsNullOrWhiteSpace(_lastReportText))
            {
                MessageBox.Show(ParentForm, "Run a checkup report first.", "Frontline Checkup Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Clipboard.SetText(_lastReportText);
                MessageBox.Show(ParentForm, "Report copied to clipboard.", "Frontline Checkup Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show(ParentForm, ex.Message, "Copy Report", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void SaveAsReport()
        {
            if (String.IsNullOrWhiteSpace(_lastReportText))
            {
                MessageBox.Show(ParentForm, "Run a checkup report first.", "Frontline Checkup Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using (SaveFileDialog dlg = new SaveFileDialog())
            {
                dlg.Title = "Save Frontline Checkup Report";
                dlg.Filter = "Text Report (*.txt)|*.txt|HTML Report (*.html)|*.html";
                dlg.FileName = "frontline_checkup_report_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt";
                if (dlg.ShowDialog(ParentForm) != DialogResult.OK) return;
                string content = dlg.FileName.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ? _lastReportHtml : _lastReportText;
                File.WriteAllText(dlg.FileName, content, Encoding.UTF8);
                MessageBox.Show(ParentForm, "Saved:\r\n" + dlg.FileName, "Frontline Checkup Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void OpenReportsFolder()
        {
            try
            {
                Directory.CreateDirectory(_logsDir);
                Process.Start("explorer.exe", _logsDir);
            }
            catch (Exception ex) { MessageBox.Show(ParentForm, ex.Message, "Open Reports Folder", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void ClearOutput()
        {
            if (_outputBox == null) return;
            if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new MethodInvoker(ClearOutput)); return; }
            _outputBox.Clear();
        }

        private void AppendOutput(string text)
        {
            if (_outputBox == null) return;
            if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; }
            _outputBox.AppendText(text + Environment.NewLine);
            _outputBox.SelectionStart = _outputBox.TextLength;
            _outputBox.ScrollToCaret();
        }

        private void SetButtonsEnabled(bool enabled)
        {
            if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; }
            foreach (Button b in _buttons) b.Enabled = enabled;
        }

        private void SetStatus(string text, bool running)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; }
            _statusLabel.Text = text;
            if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; }
            else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; }
        }

        private static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        private static string Q(string v)
        {
            if (v == null) return "\"\"";
            return "\"" + v.Replace("\"", "\\\"") + "\"";
        }

        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Security Scanner tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class ScannerPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly string _logsDir;

        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        public ScannerPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;

            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Frontline Security Scanner ready.");
            AppendOutput(IsAdministrator()
                ? "Running with administrator privileges."
                : "WARNING: Not running as administrator. Some actions may fail.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.RowCount = 4;
            root.ColumnCount = 1;
            root.Padding = new Padding(0, 8, 0, 0);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 184));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
            Controls.Add(root);

            root.Controls.Add(BuildButtonGrid(), 0, 0);
            root.Controls.Add(BuildStatusPanel(), 0, 1);
            root.Controls.Add(BuildOutputBox(), 0, 2);
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel();
            grid.Dock = DockStyle.Fill;
            grid.BackColor = _panel2;
            grid.Padding = new Padding(10);
            grid.ColumnCount = 4;
            grid.RowCount = 3;
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            for (int r = 0; r < 3; r++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33F));

            AddBtn(grid, 0, 0, "Defender Status",    "Check Microsoft Defender status",          () => RunDefenderStatus());
            AddBtn(grid, 1, 0, "Update Definitions", "Update Defender threat signatures",         () => RunUpdateDefinitions());
            AddBtn(grid, 2, 0, "Quick Scan",         "Run a fast Microsoft Defender scan",        () => RunQuickScan());
            AddBtn(grid, 3, 0, "Full Scan",          "Run a full Microsoft Defender scan",        () => RunFullScan());

            AddBtn(grid, 0, 1, "Custom Folder Scan", "Scan a selected folder",                   () => RunCustomFolderScan());
            AddBtn(grid, 1, 1, "DISM RestoreHealth", "Repair the Windows image",                 () => RunDism());
            AddBtn(grid, 2, 1, "SFC /scannow",       "Repair protected Windows files",           () => RunSfc());
            AddBtn(grid, 3, 1, "Recommended Sweep",  "Update, scan, and repair",                 () => RunRecommendedSweep());

            AddBtn(grid, 0, 2, "Protection History", "Open Windows Security history",            () => OpenProtectionHistory());
            AddBtn(grid, 1, 2, "Button Guide",       "Explain each button",                      () => ShowButtonGuide());
            AddBtn(grid, 2, 2, "Command List",       "Open command reference",                   () => OpenCommandList());
            AddBtn(grid, 3, 2, "Logs Folder",        "Open saved logs",                          () => OpenLogsFolder());

            return grid;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Dock = DockStyle.Fill;
            btn.Margin = new Padding(6);
            btn.BackColor = _panel;
            btn.ForeColor = _text;
            btn.FlatStyle = FlatStyle.Flat;
            btn.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            btn.Cursor = Cursors.Hand;
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn);
            grid.Controls.Add(btn, col, row);
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.Dock = DockStyle.Fill;
            p.BackColor = _bg;
            p.ColumnCount = 2;
            p.Padding = new Padding(0, 8, 0, 4);
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));

            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);

            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox();
            _outputBox.Dock = DockStyle.Fill;
            _outputBox.Multiline = true;
            _outputBox.ReadOnly = true;
            _outputBox.ScrollBars = ScrollBars.Both;
            _outputBox.WordWrap = true;
            _outputBox.BackColor = Color.FromArgb(5, 7, 9);
            _outputBox.ForeColor = Color.FromArgb(107, 218, 143);
            _outputBox.Font = new Font("Consolas", 10F, FontStyle.Regular);
            _outputBox.BorderStyle = BorderStyle.FixedSingle;
            return _outputBox;
        }

        // ── commands ─────────────────────────────────────────────────────────

        private void RunDefenderStatus()
        {
            string ps = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareSignatureVersion,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | Format-List";
            RunTask("Defender Status", new List<CommandItem> { PsCmd("Defender Status", ps) });
        }

        private void RunUpdateDefinitions() { RunTask("Update Defender Definitions", MpCmd("Update Defender Definitions", "-SignatureUpdate")); }
        private void RunQuickScan()         { RunTask("Quick Malware Scan",           MpCmd("Quick Malware Scan",           "-Scan -ScanType 1")); }
        private void RunFullScan()          { RunTask("Full Malware Scan",            MpCmd("Full Malware Scan",            "-Scan -ScanType 2")); }

        private void RunCustomFolderScan()
        {
            if (_isRunning) return;
            using (FolderBrowserDialog dlg = new FolderBrowserDialog { Description = "Select a folder to scan with Microsoft Defender", ShowNewFolderButton = false })
            {
                if (dlg.ShowDialog(ParentForm) != DialogResult.OK) return;
                RunTask("Custom Folder Scan", MpCmd("Custom Folder Scan: " + dlg.SelectedPath, "-Scan -ScanType 3 -File " + Q(dlg.SelectedPath)));
            }
        }

        private void RunDism()
        {
            RunTask("DISM RestoreHealth", new List<CommandItem> {
                new CommandItem("DISM RestoreHealth", "dism.exe", "/Online /Cleanup-Image /RestoreHealth", "dism.exe /Online /Cleanup-Image /RestoreHealth") });
        }

        private void RunSfc()
        {
            RunTask("SFC Scannow", new List<CommandItem> {
                new CommandItem("SFC /scannow", "sfc.exe", "/scannow", "sfc.exe /scannow") });
        }

        private void RunRecommendedSweep()
        {
            List<CommandItem> list = new List<CommandItem>();
            list.AddRange(MpCmd("Update Defender Definitions", "-SignatureUpdate"));
            list.AddRange(MpCmd("Quick Malware Scan", "-Scan -ScanType 1"));
            list.Add(new CommandItem("DISM RestoreHealth", "dism.exe", "/Online /Cleanup-Image /RestoreHealth", "dism.exe /Online /Cleanup-Image /RestoreHealth"));
            list.Add(new CommandItem("SFC /scannow", "sfc.exe", "/scannow", "sfc.exe /scannow"));
            RunTask("Recommended Sweep", list);
        }

        private List<CommandItem> MpCmd(string title, string args)
        {
            string mp = GetMpCmdRunPath();
            return new List<CommandItem> { new CommandItem(title, mp, args, Q(mp) + " " + args) };
        }

        private CommandItem PsCmd(string title, string command)
        {
            string args = "-NoProfile -ExecutionPolicy Bypass -Command " + Q(command);
            return new CommandItem(title, "powershell.exe", args, "powershell.exe " + args);
        }

        private void RunTask(string taskName, List<CommandItem> commands)
        {
            if (_isRunning)
            {
                MessageBox.Show(ParentForm, "A task is already running.", "Frontline Suite", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _isRunning = true;
            SetButtonsEnabled(false);
            SetStatus("Running: " + taskName, true);

            Thread worker = new Thread(delegate()
            {
                string logFile = Path.Combine(_logsDir, "scanner_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + SafeName(taskName) + ".log");
                try
                {
                    using (StreamWriter sw = new StreamWriter(logFile, false, Encoding.UTF8))
                    {
                        Log(sw, "============================================================");
                        Log(sw, "Frontline Suite – Security Scanner");
                        Log(sw, "Task: " + taskName);
                        Log(sw, "============================================================");
                        Log(sw, "");
                        foreach (CommandItem cmd in commands)
                        {
                            Log(sw, "---- " + cmd.Title + " ----");
                            Log(sw, "Command: " + cmd.DisplayCommand);
                            int code = RunProcess(cmd, sw);
                            Log(sw, "Exit code: " + code);
                            Log(sw, "");
                        }
                        Log(sw, "Task complete.");
                    }
                    AppendOutput("[" + Now() + "] Finished: " + taskName);
                    AppendOutput("[" + Now() + "] Log: " + logFile);
                }
                catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
                finally
                {
                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        _isRunning = false;
                        SetButtonsEnabled(true);
                        SetStatus("Ready", false);
                    }));
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        private int RunProcess(CommandItem cmd, StreamWriter writer)
        {
            try
            {
                if (cmd.FileName.EndsWith("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase) && !File.Exists(cmd.FileName))
                {
                    Log(writer, "ERROR: MpCmdRun.exe not found. Defender may be disabled.");
                    return 9009;
                }
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = cmd.FileName;
                psi.Arguments = cmd.Arguments;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.UTF8;
                psi.StandardErrorEncoding = Encoding.UTF8;
                using (Process p = new Process())
                {
                    p.StartInfo = psi;
                    p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) Log(writer, e.Data); };
                    p.ErrorDataReceived  += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) Log(writer, "ERROR: " + e.Data); };
                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    p.WaitForExit();
                    return p.ExitCode;
                }
            }
            catch (Exception ex) { Log(writer, "ERROR: " + ex.Message); return -1; }
        }

        private void Log(StreamWriter w, string line)
        {
            string s = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + line;
            w.WriteLine(s); w.Flush();
            AppendOutput(s);
        }

        private void OpenProtectionHistory()
        {
            try { Process.Start(new ProcessStartInfo { FileName = "windowsdefender://ThreatHistory", UseShellExecute = true }); }
            catch { try { Process.Start("windowsdefender:"); } catch { MessageBox.Show(ParentForm, "Could not open Windows Security."); } }
        }

        private void OpenCommandList()
        {
            string p1 = Path.Combine(Application.StartupPath, "docs", "Frontline_Malware_Scan_Commands.txt");
            string p2 = Path.Combine(Application.StartupPath, "Frontline_Malware_Scan_Commands.txt");
            string path = File.Exists(p1) ? p1 : p2;
            if (File.Exists(path)) Process.Start("notepad.exe", Q(path));
            else MessageBox.Show(ParentForm, "Command list file not found.");
        }

        private void OpenLogsFolder() { Process.Start("explorer.exe", Q(_logsDir)); }

        private void ShowButtonGuide()
        {
            Form guide = new Form();
            guide.Text = "Security Scanner – Button Guide";
            guide.StartPosition = FormStartPosition.CenterParent;
            guide.Size = new Size(980, 560);
            guide.BackColor = _bg;
            guide.ForeColor = _text;
            guide.Font = new Font("Segoe UI", 10F, FontStyle.Regular);

            ListView list = new ListView();
            list.Dock = DockStyle.Fill;
            list.View = View.Details;
            list.FullRowSelect = true;
            list.GridLines = true;
            list.BackColor = Color.FromArgb(5, 7, 9);
            list.ForeColor = _text;
            list.Columns.Add("Button", 190);
            list.Columns.Add("What it does", 360);
            list.Columns.Add("Why use it", 370);

            Action<string, string, string> add = (n, d, w) => {
                ListViewItem it = new ListViewItem(n);
                it.SubItems.Add(d); it.SubItems.Add(w);
                list.Items.Add(it);
            };
            add("Defender Status",    "Checks Defender and real-time protection status.",    "Confirms the computer has active built-in protection.");
            add("Update Definitions", "Downloads the latest Defender signatures.",            "New definitions improve detection before scanning.");
            add("Quick Scan",         "Scans common malware locations.",                      "Fast routine check when the system seems suspicious.");
            add("Full Scan",          "Scans the full system.",                               "Best when infection is suspected or after risky downloads.");
            add("Custom Folder Scan", "Scans one selected folder.",                           "Useful for Downloads, USB drives, or customer files.");
            add("DISM RestoreHealth", "Repairs the Windows component store.",                 "Helps fix Windows corruption and update problems.");
            add("SFC /scannow",       "Repairs protected Windows system files.",              "Useful after crashes, malware cleanup, or corruption.");
            add("Recommended Sweep",  "Runs update, quick scan, DISM, and SFC.",             "Guided maintenance workflow for general cleanup.");
            add("Protection History", "Opens Windows Security detection history.",            "Review quarantined threats and recommended actions.");
            add("Logs Folder",        "Opens saved scan and repair logs.",                    "Keeps a record of what was run and results.");
            guide.Controls.Add(list);
            guide.ShowDialog(ParentForm);
        }

        // ── helpers ───────────────────────────────────────────────────────────

        private void AppendOutput(string text)
        {
            if (_outputBox == null) return;
            if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; }
            _outputBox.AppendText(text + Environment.NewLine);
            _outputBox.SelectionStart = _outputBox.TextLength;
            _outputBox.ScrollToCaret();
        }

        private void SetButtonsEnabled(bool enabled)
        {
            if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; }
            foreach (Button b in _buttons) b.Enabled = enabled;
        }

        private void SetStatus(string text, bool running)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; }
            _statusLabel.Text = text;
            if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; }
            else          { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; }
        }

        private static string GetMpCmdRunPath()
        {
            try
            {
                string platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows Defender", "Platform");
                if (Directory.Exists(platform))
                {
                    DirectoryInfo[] dirs = new DirectoryInfo(platform).GetDirectories();
                    Array.Sort(dirs, (a, b) => String.Compare(b.Name, a.Name, StringComparison.OrdinalIgnoreCase));
                    foreach (DirectoryInfo d in dirs)
                    {
                        string c = Path.Combine(d.FullName, "MpCmdRun.exe");
                        if (File.Exists(c)) return c;
                    }
                }
                string standard = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
                if (File.Exists(standard)) return standard;
            }
            catch { }
            return "MpCmdRun.exe";
        }

        private static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
        private static string SafeName(string v)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in v) sb.Append(Char.IsLetterOrDigit(c) ? c : '_');
            return sb.ToString().Trim('_');
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Network Shield tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class NetworkPanel : UserControl
    {
        private const string AppName    = "Frontline Network Shield";
        private const string AppVersion = "1.3.2";

        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _termGreen = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;
        private readonly string _dataDir;
        private readonly string _knownDevicesFile;

        private ComboBox _adapterCombo;
        private ComboBox _cidrCombo;
        private CheckBox _stealthCheck;
        private TextBox _outputBox;
        private Label _statusLabel;
        private Label _dnsLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();

        private List<AdapterItem> _adapters = new List<AdapterItem>();
        private List<DeviceRow> _lastScanRows = new List<DeviceRow>();
        private string _lastScanNote = "";
        private string _lastDnsSummary = "";
        private bool _isRunning;

        private readonly Dictionary<string, string[]> _dnsProfiles = new Dictionary<string, string[]>
        {
            { "AdGuard DNS",            new[] { "94.140.14.14",  "94.140.15.15"   } },
            { "Cloudflare Malware DNS", new[] { "1.1.1.2",       "1.0.0.2"        } },
            { "Quad9 Security DNS",     new[] { "9.9.9.9",       "149.112.112.112"} }
        };

        private readonly Dictionary<int, string> _commonPorts = new Dictionary<int, string>
        {
            { 22, "SSH" }, { 80, "HTTP" }, { 443, "HTTPS" }, { 445, "SMB/File Sharing" }, { 3389, "Remote Desktop" }
        };

        public NetworkPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir  = logsDir;
            _dataDir  = Path.Combine(Application.StartupPath, "data");
            _knownDevicesFile = Path.Combine(_dataDir, "known_devices.txt");

            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;

            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();

            AppendOutput(AppName + " v" + AppVersion + " ready.");
            AppendOutput(IsAdministrator() ? "Running with administrator privileges." : "WARNING: Not running as administrator. DNS changes may fail.");
            AppendOutput("Only scan networks you own or have permission to assess.");
            RefreshAdapters();
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.RowCount = 4;
            root.ColumnCount = 1;
            root.Padding = new Padding(0, 8, 0, 0);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 184));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            root.Controls.Add(BuildAdapterPanel(), 0, 0);
            root.Controls.Add(BuildButtonGrid(), 0, 1);
            root.Controls.Add(BuildStatusPanel(), 0, 2);
            root.Controls.Add(BuildOutputBox(), 0, 3);
        }

        private Control BuildAdapterPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.BackColor = _panel2;
            panel.Padding = new Padding(10, 8, 10, 8);
            panel.ColumnCount = 7;
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 135)); // "Network Adapter" label
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));   // adapter combo
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));  // "Scan Range" label
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110)); // CIDR combo
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 115)); // Stealth checkbox
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));   // DNS label
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150)); // Refresh button

            Label lbl = new Label { Text = "Network Adapter", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold) };
            panel.Controls.Add(lbl, 0, 0);

            _adapterCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text };
            _adapterCombo.SelectedIndexChanged += delegate { UpdateDnsDisplay(); };
            panel.Controls.Add(_adapterCombo, 1, 0);

            Label cidrLbl = new Label { Text = "Scan Range:", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold) };
            panel.Controls.Add(cidrLbl, 2, 0);

            _cidrCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text, Font = new Font("Consolas", 9F) };
            _cidrCombo.Items.AddRange(new object[] {
                "/24  (254 hosts)",
                "/23  (510 hosts)",
                "/22  (1022 hosts)",
                "/26  (62 hosts)",
                "/27  (30 hosts)",
                "/28  (14 hosts)"
            });
            _cidrCombo.SelectedIndex = 0;
            new ToolTip { InitialDelay = 250 }.SetToolTip(_cidrCombo,
                "Select the subnet size to scan.\r\n" +
                "/24 = standard home/small office (192.168.x.0–254)\r\n" +
                "/23 = two /24 blocks combined\r\n" +
                "/22 = four /24 blocks (larger offices)\r\n" +
                "/26–/28 = small segments or VLANs");
            panel.Controls.Add(_cidrCombo, 3, 0);

            _stealthCheck = new CheckBox
            {
                Text = "Stealth Mode",
                ForeColor = _muted,
                BackColor = Color.Transparent,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            new ToolTip { InitialDelay = 250 }.SetToolTip(_stealthCheck,
                "Stealth Mode: reduces scan threads from 64 to 8\r\n" +
                "and adds a short delay between pings.\r\n" +
                "Slower, but much less likely to trigger IDS alerts\r\n" +
                "on managed or corporate networks.");
            panel.Controls.Add(_stealthCheck, 4, 0);

            _dnsLabel = new Label { Text = "Current DNS: Not checked yet", ForeColor = _termGreen, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Consolas", 9F) };
            panel.Controls.Add(_dnsLabel, 5, 0);

            Button refresh = SmallBtn("Refresh Adapters");
            refresh.Click += delegate { RefreshAdapters(); };
            panel.Controls.Add(refresh, 6, 0);

            return panel;
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel();
            grid.Dock = DockStyle.Fill;
            grid.BackColor = _panel2;
            grid.Padding = new Padding(10);
            grid.ColumnCount = 4;
            grid.RowCount = 3;
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            for (int r = 0; r < 3; r++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33F));

            AddBtn(grid, 0, 0, "Show Current DNS",       "Display current IPv4 DNS for the selected adapter",   () => UpdateDnsDisplay());
            AddBtn(grid, 1, 0, "AdGuard DNS",            "Set DNS to AdGuard ad/tracker blocking DNS",          () => ApplyDnsProfile("AdGuard DNS"));
            AddBtn(grid, 2, 0, "Cloudflare Malware DNS", "Set DNS to Cloudflare malware-blocking DNS",          () => ApplyDnsProfile("Cloudflare Malware DNS"));
            AddBtn(grid, 3, 0, "Quad9 Security DNS",     "Set DNS to Quad9 security DNS",                       () => ApplyDnsProfile("Quad9 Security DNS"));

            AddBtn(grid, 0, 1, "Reset DNS DHCP",         "Reset selected adapter DNS back to automatic/DHCP",   () => ResetDnsDhcp());
            AddBtn(grid, 1, 1, "Run Network Scan",       "Scan local /24 network and log connected devices",    () => RunNetworkScan());
            AddBtn(grid, 2, 1, "Export Last Scan",       "Save the most recent scan as TXT and CSV",            () => ExportLastScan());
            AddBtn(grid, 3, 1, "Logs Folder",            "Open saved Network Shield logs",                      () => OpenLogsFolder());

            AddBtn(grid, 0, 2, "Device Guide",           "Explain scan notes and common services",              () => ShowDeviceGuide());
            AddBtn(grid, 1, 2, "DNS Guide",              "Explain included DNS profiles",                       () => ShowDnsGuide());
            AddBtn(grid, 2, 2, "Clear Device History",   "Delete the known_devices.txt inventory file",         () => ClearDeviceHistory());
            AddBtn(grid, 3, 2, "Network Settings",       "Open Windows network settings",                       () => OpenNetworkSettings());

            return grid;
        }

        private Button SmallBtn(string text)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6, 0, 0, 0), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            return btn;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn);
            grid.Controls.Add(btn, col, row);
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _termGreen, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── adapter / DNS ─────────────────────────────────────────────────────

        private void RefreshAdapters()
        {
            if (_isRunning) return;
            _adapters.Clear();
            _adapterCombo.Items.Clear();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (!nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
                IPInterfaceProperties props = nic.GetIPProperties();
                foreach (UnicastIPAddressInformation uni in props.UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (uni.IPv4Mask == null) continue;
                    AdapterItem item = new AdapterItem();
                    item.Name = nic.Name; item.Description = nic.Description;
                    item.IpAddress = uni.Address; item.SubnetMask = uni.IPv4Mask;
                    item.DnsAddresses = props.DnsAddresses.Cast<IPAddress>().Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToList();
                    _adapters.Add(item);
                    _adapterCombo.Items.Add(item);
                    break;
                }
            }

            if (_adapterCombo.Items.Count > 0)
            {
                _adapterCombo.SelectedIndex = 0;
                AppendOutput("[" + Now() + "] Found adapter(s): " + String.Join(", ", _adapters.Select(a => a.Name).ToArray()));
                UpdateDnsDisplay();
            }
            else
            {
                _dnsLabel.Text = "Current DNS: No active IPv4 adapters found";
                AppendOutput("No active IPv4 network adapters were found.");
            }
        }

        private AdapterItem SelectedAdapter()
        {
            AdapterItem item = _adapterCombo.SelectedItem as AdapterItem;
            if (item == null) MessageBox.Show(ParentForm, "Select a network adapter first.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return item;
        }

        private void UpdateDnsDisplay()
        {
            AdapterItem adapter = SelectedAdapter();
            if (adapter == null) return;
            adapter.RefreshDns();
            string dns = adapter.DnsAddresses.Count == 0 ? "Automatic/DHCP or no custom IPv4 DNS" : String.Join(", ", adapter.DnsAddresses.ToArray());
            _lastDnsSummary = adapter.Name + ": " + dns;
            _dnsLabel.Text = "Current DNS: " + _lastDnsSummary;
            AppendOutput("[" + Now() + "] " + _lastDnsSummary);
        }

        private void ApplyDnsProfile(string profileName)
        {
            if (_isRunning) return;
            AdapterItem adapter = SelectedAdapter();
            if (adapter == null) return;
            if (!IsAdministrator())
            {
                MessageBox.Show(ParentForm, "Administrator permission required to change DNS. Run this app as Administrator.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string[] servers = _dnsProfiles[profileName];
            SetStatus("Applying DNS: " + profileName, true);
            AppendOutput("[" + Now() + "] Applying DNS profile: " + profileName);
            bool ok1 = RunCmd("netsh.exe", "interface ipv4 set dnsservers name=\"" + adapter.Name + "\" static " + servers[0] + " primary validate=no");
            bool ok2 = RunCmd("netsh.exe", "interface ipv4 add dnsservers name=\"" + adapter.Name + "\" address=" + servers[1] + " index=2 validate=no");
            if (ok1 && ok2)
            {
                AppendOutput("[" + Now() + "] DNS updated: " + servers[0] + ", " + servers[1]);
                RefreshAdapters(); UpdateDnsDisplay();
                MessageBox.Show(ParentForm, "DNS updated for " + adapter.Name + ".", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else AppendOutput("[" + Now() + "] DNS update did not complete. Check console output.");
            SetStatus("Ready", false);
        }

        private void ResetDnsDhcp()
        {
            if (_isRunning) return;
            AdapterItem adapter = SelectedAdapter();
            if (adapter == null) return;
            if (!IsAdministrator())
            {
                MessageBox.Show(ParentForm, "Administrator permission required to reset DNS.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            SetStatus("Resetting DNS to DHCP", true);
            AppendOutput("[" + Now() + "] Resetting DNS to automatic/DHCP for " + adapter.Name + "...");
            bool ok = RunCmd("netsh.exe", "interface ipv4 set dnsservers name=\"" + adapter.Name + "\" source=dhcp");
            if (ok)
            {
                AppendOutput("[" + Now() + "] DNS reset to automatic/DHCP.");
                RefreshAdapters(); UpdateDnsDisplay();
                MessageBox.Show(ParentForm, "DNS reset to automatic/DHCP for " + adapter.Name + ".", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else AppendOutput("[" + Now() + "] DNS reset did not complete.");
            SetStatus("Ready", false);
        }

        private bool RunCmd(string fileName, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = fileName, Arguments = arguments, CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                using (Process p = new Process())
                {
                    p.StartInfo = psi; p.Start();
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    if (!String.IsNullOrWhiteSpace(stdout)) AppendOutput(stdout.Trim());
                    if (p.ExitCode == 0) return true;
                    string err = String.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                    AppendOutput("ERROR: " + (String.IsNullOrWhiteSpace(err) ? fileName + " failed with code " + p.ExitCode : err.Trim()));
                    return false;
                }
            }
            catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); return false; }
        }

        // ── network scan ──────────────────────────────────────────────────────

        private void RunNetworkScan()
        {
            if (_isRunning) { MessageBox.Show(ParentForm, "A task is already running.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            AdapterItem adapter = SelectedAdapter();
            if (adapter == null) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus("Running local network scan", true);
            _lastScanRows = new List<DeviceRow>();

            Thread worker = new Thread(delegate()
            {
                try
                {
                    List<DeviceRow> rows = ScanNetwork(adapter);
                    _lastScanRows = rows;
                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        string csvPath, txtPath;
                        ExportLogs(rows, _lastScanNote, _lastDnsSummary, out csvPath, out txtPath);
                        AppendOutput("[" + Now() + "] Scan complete. Devices found: " + rows.Count);
                        AppendOutput("[" + Now() + "] CSV: " + csvPath);
                        AppendOutput("[" + Now() + "] TXT: " + txtPath);
                    }));
                }
                catch (Exception ex) { AppendOutput("ERROR: Scan failed: " + ex.Message); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); SetStatus("Ready", false); })); }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        private List<DeviceRow> ScanNetwork(AdapterItem adapter)
        {
            // Parse the selected CIDR prefix from the combo (e.g. "/24  (254 hosts)" -> 24)
            int cidrPrefix = 24;
            try
            {
                string cidrText = "";
                if (_cidrCombo.InvokeRequired)
                    _cidrCombo.Invoke(new MethodInvoker(delegate() { cidrText = _cidrCombo.SelectedItem != null ? _cidrCombo.SelectedItem.ToString() : "/24"; }));
                else
                    cidrText = _cidrCombo.SelectedItem != null ? _cidrCombo.SelectedItem.ToString() : "/24";
                // Extract the number after the slash
                int slash = cidrText.IndexOf('/');
                int space = cidrText.IndexOf(' ', slash);
                cidrPrefix = int.Parse(space > slash ? cidrText.Substring(slash + 1, space - slash - 1) : cidrText.Substring(slash + 1));
            }
            catch { cidrPrefix = 24; }

            AppendOutput("[" + Now() + "] Starting scan on: " + adapter.Name);
            AppendOutput("[" + Now() + "] Local IP: " + adapter.IpAddress + " | Mask: " + adapter.SubnetMask);
            List<IPAddress> hosts = BuildHostList(adapter.IpAddress, adapter.SubnetMask, cidrPrefix, out _lastScanNote);
            AppendOutput("[" + Now() + "] " + _lastScanNote);

            // Read stealth setting from UI thread
            bool stealth = false;
            try
            {
                if (_stealthCheck.InvokeRequired)
                    _stealthCheck.Invoke(new MethodInvoker(delegate() { stealth = _stealthCheck.Checked; }));
                else
                    stealth = _stealthCheck.Checked;
            }
            catch { stealth = false; }

            int threads = stealth ? 8 : 64;
            int pingDelayMs = stealth ? 15 : 0;
            AppendOutput("[" + Now() + "] Mode: " + (stealth ? "Stealth (" + threads + " threads, " + pingDelayMs + "ms delay)" : "Normal (64 threads)"));
            AppendOutput("[" + Now() + "] Checking " + hosts.Count + " address(es)...");

            List<IPAddress> alive = new List<IPAddress>();
            object lck = new object();
            int checkedCount = 0;

            Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = threads }, delegate(IPAddress ip)
            {
                if (pingDelayMs > 0) Thread.Sleep(pingDelayMs);
                if (PingHost(ip)) lock (lck) { alive.Add(ip); }
                int done = Interlocked.Increment(ref checkedCount);
                if (done % 25 == 0) AppendOutput("[" + Now() + "] Checked " + done + "/" + hosts.Count + "...");
            });

            Dictionary<string, string> arp = GetArpTable();
            Dictionary<string, string> known = LoadKnownDevices();
            string now = DateTime.Now.ToString("s");
            List<DeviceRow> rows = new List<DeviceRow>();

            foreach (IPAddress ip in alive.OrderBy(a => AddressToUInt32(a)))
            {
                string ipText = ip.ToString();
                string mac = arp.ContainsKey(ipText) ? arp[ipText] : "";
                string host = ResolveHostname(ipText);
                List<string> services = CheckOpenPorts(ipText);
                string key = String.IsNullOrWhiteSpace(mac) ? ipText : mac;
                bool isNew = !known.ContainsKey(key);

                DeviceRow row = new DeviceRow { Timestamp = now, Adapter = adapter.Name, IpAddress = ipText,
                    MacAddress = String.IsNullOrWhiteSpace(mac) ? "Unavailable" : mac,
                    Hostname = String.IsNullOrWhiteSpace(host) ? "Unavailable" : host,
                    Status = "Reachable",
                    OpenServices = services.Count == 0 ? "None detected" : String.Join(", ", services.ToArray()),
                    RiskNotes = BuildRiskNotes(isNew, services, host) };
                rows.Add(row);
                known[key] = now + "|" + ipText + "|" + mac + "|" + host;
                AppendOutput("[" + Now() + "] DEVICE | IP: " + row.IpAddress + " | MAC: " + row.MacAddress + " | HOST: " + row.Hostname + " | SERVICES: " + row.OpenServices + " | NOTES: " + row.RiskNotes);
            }

            SaveKnownDevices(known);
            return rows;
        }

        private static List<IPAddress> BuildHostList(IPAddress localIp, IPAddress subnetMask, int requestedPrefix, out string scanNote)
        {
            uint ip   = AddressToUInt32(localIp);
            uint mask = AddressToUInt32(subnetMask);

            // Use the requested CIDR prefix, but never go broader than /22 (safety cap)
            int prefix = requestedPrefix;
            if (prefix < 22) prefix = 22;
            if (prefix > 30) prefix = 30;

            mask = PrefixToMask(prefix);
            uint network   = ip & mask;
            uint broadcast = network | ~mask;

            List<IPAddress> hosts = new List<IPAddress>();
            if (broadcast <= network + 1) { scanNote = "No usable local host range available."; return hosts; }

            for (uint cur = network + 1; cur < broadcast; cur++) hosts.Add(UInt32ToAddress(cur));

            int hostCount = (int)(broadcast - network - 1);
            scanNote = String.Format("Scanning {0}/{1}  ({2} addresses)  —  only scan networks you own or have permission to assess.",
                UInt32ToAddress(network), prefix, hostCount);
            return hosts;
        }

        private static bool PingHost(IPAddress ip) { try { return new Ping().Send(ip, 350).Status == IPStatus.Success; } catch { return false; } }

        private static Dictionary<string, string> GetArpTable()
        {
            Dictionary<string, string> arp = new Dictionary<string, string>();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = "arp.exe", Arguments = "-a", CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    Regex rx = new Regex(@"(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[a-fA-F0-9]{2}(?:-[a-fA-F0-9]{2}){5})\s+\w+");
                    foreach (Match m in rx.Matches(output))
                        arp[m.Groups["ip"].Value] = m.Groups["mac"].Value.ToUpperInvariant().Replace("-", ":");
                }
            }
            catch { }
            return arp;
        }

        private string ResolveHostname(string ip) { try { return Dns.GetHostEntry(ip).HostName; } catch { return ""; } }

        private List<string> CheckOpenPorts(string ip)
        {
            List<string> open = new List<string>();
            foreach (KeyValuePair<int, string> kv in _commonPorts)
                if (IsPortOpen(ip, kv.Key, 300)) open.Add(kv.Key + "/" + kv.Value);
            return open;
        }

        private static bool IsPortOpen(string ip, int port, int ms)
        {
            try { using (TcpClient c = new TcpClient()) { IAsyncResult r = c.BeginConnect(ip, port, null, null); if (!r.AsyncWaitHandle.WaitOne(ms)) return false; c.EndConnect(r); return true; } }
            catch { return false; }
        }

        private static string BuildRiskNotes(bool isNew, List<string> services, string hostname)
        {
            List<string> notes = new List<string>();
            if (isNew) notes.Add("New or unknown device");
            if (String.IsNullOrWhiteSpace(hostname)) notes.Add("Hostname unavailable");
            foreach (string s in services)
            {
                if (s.StartsWith("3389/")) notes.Add("Remote Desktop visible");
                else if (s.StartsWith("445/")) notes.Add("File sharing visible");
                else if (s.StartsWith("22/")) notes.Add("SSH visible");
                else if (s.StartsWith("80/") || s.StartsWith("443/")) notes.Add("Web interface visible");
            }
            return notes.Count == 0 ? "No basic warning notes" : String.Join("; ", notes.Distinct().ToArray());
        }

        private Dictionary<string, string> LoadKnownDevices()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            try { if (File.Exists(_knownDevicesFile)) foreach (string line in File.ReadAllLines(_knownDevicesFile)) { if (String.IsNullOrWhiteSpace(line)) continue; int i = line.IndexOf('='); if (i > 0) d[line.Substring(0, i)] = line.Substring(i + 1); } }
            catch { }
            return d;
        }

        private void SaveKnownDevices(Dictionary<string, string> d)
        {
            try { File.WriteAllLines(_knownDevicesFile, d.Select(kv => kv.Key + "=" + kv.Value).ToArray()); }
            catch (Exception ex) { AppendOutput("ERROR saving known devices: " + ex.Message); }
        }

        private void ExportLastScan()
        {
            if (_lastScanRows == null || _lastScanRows.Count == 0) { MessageBox.Show(ParentForm, "Run a network scan first.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            string csvPath, txtPath;
            ExportLogs(_lastScanRows, _lastScanNote, _lastDnsSummary, out csvPath, out txtPath);
            AppendOutput("[" + Now() + "] CSV: " + csvPath);
            AppendOutput("[" + Now() + "] TXT: " + txtPath);
            MessageBox.Show(ParentForm, "Saved:\r\n" + csvPath + "\r\n\r\n" + txtPath, "Logs Exported", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ExportLogs(List<DeviceRow> rows, string scanNote, string dnsSummary, out string csvPath, out string txtPath)
        {
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            csvPath = Path.Combine(_logsDir, "network_shield_" + stamp + ".csv");
            txtPath = Path.Combine(_logsDir, "network_shield_" + stamp + ".log");

            StringBuilder csv = new StringBuilder();
            csv.AppendLine("timestamp,adapter,ip_address,mac_address,hostname,status,open_services,risk_notes");
            foreach (DeviceRow row in rows)
                csv.AppendLine(String.Join(",", Csv(row.Timestamp), Csv(row.Adapter), Csv(row.IpAddress), Csv(row.MacAddress), Csv(row.Hostname), Csv(row.Status), Csv(row.OpenServices), Csv(row.RiskNotes)));
            File.WriteAllText(csvPath, csv.ToString(), Encoding.UTF8);

            StringBuilder txt = new StringBuilder();
            txt.AppendLine("============================================================");
            txt.AppendLine("Frontline Tech Consulting, LLC – " + AppName + " v" + AppVersion);
            txt.AppendLine("Generated: " + DateTime.Now.ToString("s"));
            txt.AppendLine("DNS Summary: " + dnsSummary);
            txt.AppendLine("Scan Note: " + scanNote);
            txt.AppendLine("Devices Found: " + rows.Count);
            txt.AppendLine("============================================================");
            txt.AppendLine();
            foreach (DeviceRow row in rows)
            {
                txt.AppendLine("DEVICE");
                txt.AppendLine("  Time:          " + row.Timestamp);
                txt.AppendLine("  Adapter:       " + row.Adapter);
                txt.AppendLine("  IP Address:    " + row.IpAddress);
                txt.AppendLine("  MAC Address:   " + row.MacAddress);
                txt.AppendLine("  Hostname:      " + row.Hostname);
                txt.AppendLine("  Status:        " + row.Status);
                txt.AppendLine("  Open Services: " + row.OpenServices);
                txt.AppendLine("  Notes:         " + row.RiskNotes);
                txt.AppendLine("------------------------------------------------------------");
            }
            File.WriteAllText(txtPath, txt.ToString(), Encoding.UTF8);
        }

        private static string Csv(string v) { if (v == null) v = ""; return "\"" + v.Replace("\"", "\"\"") + "\""; }

        private void ShowDeviceGuide()
        {
            MessageBox.Show(ParentForm,
                "Device Guide\r\n\r\n" +
                "New or unknown device: Not seen in the app's previous known-device list.\r\n\r\n" +
                "Hostname unavailable: Windows could not resolve a friendly name.\r\n\r\n" +
                "Remote Desktop visible: TCP 3389 appeared open.\r\n\r\n" +
                "File sharing visible: TCP 445 appeared open.\r\n\r\n" +
                "Web interface visible: TCP 80 or 443 appeared open. Common for routers, printers, and cameras.\r\n\r\n" +
                "This is a basic visibility tool, not a full vulnerability scanner.",
                "Device Guide", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ShowDnsGuide()
        {
            MessageBox.Show(ParentForm,
                "DNS Guide\r\n\r\n" +
                "AdGuard DNS: Helps block ads and trackers at the DNS level.\r\n\r\n" +
                "Cloudflare Malware DNS: Uses Cloudflare's malware-blocking DNS profile.\r\n\r\n" +
                "Quad9 Security DNS: Uses Quad9 security DNS for malicious-domain blocking.\r\n\r\n" +
                "Reset DNS DHCP: Returns the selected adapter to automatic DNS from the router.",
                "DNS Guide", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void OpenLogsFolder() { Directory.CreateDirectory(_logsDir); Process.Start(new ProcessStartInfo { FileName = _logsDir, UseShellExecute = true }); }

        private void ClearDeviceHistory()
        {
            if (!File.Exists(_knownDevicesFile))
            {
                MessageBox.Show(ParentForm, "No device history file found.\r\nRun a network scan first to create one.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            // Show current file size and entry count for context
            int lineCount = 0;
            long fileSize = 0;
            try
            {
                string[] lines = File.ReadAllLines(_knownDevicesFile);
                lineCount = lines.Length;
                fileSize = new FileInfo(_knownDevicesFile).Length;
            }
            catch { }

            if (MessageBox.Show(ParentForm,
                String.Format("This will clear the known device history.\r\n\r\n" +
                    "File: {0}\r\n" +
                    "Entries: {1}  ({2} bytes)\r\n\r\n" +
                    "After clearing, all devices will appear as 'New or unknown'\r\n" +
                    "on the next scan — useful when moving to a new network\r\n" +
                    "or handing a machine off to a new owner.\r\n\r\n" +
                    "Proceed?", _knownDevicesFile, lineCount, fileSize),
                "Clear Device History", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            try
            {
                // Back up before deleting
                string backup = Path.Combine(_logsDir, "known_devices_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                File.Copy(_knownDevicesFile, backup, true);
                File.Delete(_knownDevicesFile);
                AppendOutput("[" + Now() + "] Device history cleared. Backup saved: " + backup);
                MessageBox.Show(ParentForm, "Device history cleared.\r\nBackup saved to logs folder.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ParentForm, "Failed to clear device history:\r\n" + ex.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenNetworkSettings()
        {
            try { Process.Start("ncpa.cpl"); }
            catch { try { Process.Start(new ProcessStartInfo { FileName = "ms-settings:network", UseShellExecute = true }); } catch { MessageBox.Show(ParentForm, "Could not open Windows network settings.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); } }
        }

        // ── shared helpers ────────────────────────────────────────────────────

        private void AppendOutput(string text)
        {
            if (_outputBox == null) return;
            if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; }
            _outputBox.AppendText(text + Environment.NewLine);
            _outputBox.SelectionStart = _outputBox.TextLength;
            _outputBox.ScrollToCaret();
        }

        private void SetButtonsEnabled(bool enabled)
        {
            if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; }
            foreach (Button b in _buttons) b.Enabled = enabled;
        }

        private void SetStatus(string text, bool running)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; }
            _statusLabel.Text = text;
            if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; }
            else          { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; }
        }

        private static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        private static uint AddressToUInt32(IPAddress a) { byte[] b = a.GetAddressBytes(); if (BitConverter.IsLittleEndian) Array.Reverse(b); return BitConverter.ToUInt32(b, 0); }
        private static IPAddress UInt32ToAddress(uint v) { byte[] b = BitConverter.GetBytes(v); if (BitConverter.IsLittleEndian) Array.Reverse(b); return new IPAddress(b); }
        private static int MaskToPrefix(uint mask) { int p = 0; for (int i = 31; i >= 0; i--) { if ((mask & (1u << i)) != 0) p++; else break; } return p; }
        private static uint PrefixToMask(int prefix) { if (prefix <= 0) return 0; if (prefix >= 32) return UInt32.MaxValue; return UInt32.MaxValue << (32 - prefix); }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  System Health tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class SystemHealthPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        public SystemHealthPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("System Health ready. Click 'Full Health Snapshot' for a complete overview.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.BackColor = _bg;
            root.RowCount = 3;
            root.ColumnCount = 1;
            root.Padding = new Padding(0, 8, 0, 0);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 136));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);
            root.Controls.Add(BuildButtonGrid(), 0, 0);
            root.Controls.Add(BuildStatusPanel(), 0, 1);
            root.Controls.Add(BuildOutputBox(), 0, 2);
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel();
            grid.Dock = DockStyle.Fill;
            grid.BackColor = _panel2;
            grid.Padding = new Padding(10);
            grid.ColumnCount = 4;
            grid.RowCount = 2;
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            for (int r = 0; r < 2; r++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

            AddBtn(grid, 0, 0, "Full Health Snapshot", "Run all health checks and save a log",   () => RunFullSnapshot());
            AddBtn(grid, 1, 0, "Disk Space",           "Show free/used space on all drives",      () => RunDiskSpace());
            AddBtn(grid, 2, 0, "RAM & CPU",            "Show memory usage and CPU info",           () => RunRamCpu());
            AddBtn(grid, 3, 0, "System Info",          "OS version, uptime, computer name",        () => RunSystemInfo());

            AddBtn(grid, 0, 1, "Pending Reboot?",      "Check if Windows is waiting for a reboot",() => RunPendingReboot());
            AddBtn(grid, 1, 1, "Battery Status",       "Show battery health (laptops)",            () => RunBattery());
            AddBtn(grid, 2, 1, "Event Log Errors",     "Show last 20 critical/error events",       () => RunEventLogErrors());
            AddBtn(grid, 3, 1, "Logs Folder",          "Open saved health logs",                   () => OpenLogsFolder());

            return grid;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn);
            grid.Controls.Add(btn, col, row);
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── checks ────────────────────────────────────────────────────────────

        private void RunFullSnapshot()
        {
            if (_isRunning) return;
            RunAsync("Full Health Snapshot", delegate(StringBuilder sb)
            {
                CollectSystemInfo(sb);
                sb.AppendLine();
                CollectDiskSpace(sb);
                sb.AppendLine();
                CollectRamCpu(sb);
                sb.AppendLine();
                CollectPendingReboot(sb);
                sb.AppendLine();
                CollectBattery(sb);
                sb.AppendLine();
                CollectEventLogErrors(sb);
            });
        }

        private void RunDiskSpace()        { RunAsync("Disk Space",        CollectDiskSpace); }
        private void RunRamCpu()           { RunAsync("RAM & CPU",         CollectRamCpu); }
        private void RunSystemInfo()       { RunAsync("System Info",       CollectSystemInfo); }
        private void RunPendingReboot()    { RunAsync("Pending Reboot",    CollectPendingReboot); }
        private void RunBattery()          { RunAsync("Battery Status",    CollectBattery); }
        private void RunEventLogErrors()   { RunAsync("Event Log Errors",  CollectEventLogErrors); }

        private void RunAsync(string taskName, Action<StringBuilder> work)
        {
            if (_isRunning) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus("Running: " + taskName, true);
            Thread t = new Thread(delegate()
            {
                string logFile = Path.Combine(_logsDir, "health_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + SafeName(taskName) + ".log");
                try
                {
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("============================================================");
                    sb.AppendLine("Frontline Suite – System Health");
                    sb.AppendLine("Task: " + taskName);
                    sb.AppendLine("Generated: " + DateTime.Now.ToString("s"));
                    sb.AppendLine("============================================================");
                    sb.AppendLine();
                    work(sb);
                    string result = sb.ToString();
                    File.WriteAllText(logFile, result, Encoding.UTF8);
                    AppendOutput(result);
                    AppendOutput("[" + Now() + "] Log saved: " + logFile);
                }
                catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); SetStatus("Ready", false); })); }
            });
            t.IsBackground = true; t.Start();
        }

        private void CollectSystemInfo(StringBuilder sb)
        {
            sb.AppendLine("── System Info ─────────────────────────────────────────────");
            try
            {
                string ps = "Get-ComputerInfo | Select-Object CsName,WindowsProductName,WindowsVersion,OsArchitecture,OsLastBootUpTime | Format-List";
                string result = RunPs(ps);
                sb.AppendLine(result);

                // Uptime via WMI (avoids TickCount64 which requires .NET 5+)
                try
                {
                    string psUp = "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty ToString";
                    string upResult = RunPs("$b=(gcim Win32_OperatingSystem).LastBootUpTime; $u=(Get-Date)-$b; '{0}d {1}h {2}m' -f [int]$u.TotalDays,$u.Hours,$u.Minutes").Trim();
                    sb.AppendLine("Uptime:  " + upResult);
                }
                catch { }
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private void CollectDiskSpace(StringBuilder sb)
        {
            sb.AppendLine("── Disk Space ──────────────────────────────────────────────");
            try
            {
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    if (!drive.IsReady) continue;
                    double total = drive.TotalSize / 1073741824.0;
                    double free  = drive.AvailableFreeSpace / 1073741824.0;
                    double used  = total - free;
                    double pct   = total > 0 ? (used / total) * 100.0 : 0;
                    string warn  = pct > 90 ? " *** LOW DISK ***" : pct > 75 ? " (getting full)" : "";
                    sb.AppendLine(String.Format("{0,-6} {1,-30}  Total: {2,7:F1} GB  Used: {3,7:F1} GB  Free: {4,7:F1} GB  ({5:F0}%){6}",
                        drive.Name, drive.VolumeLabel, total, used, free, pct, warn));
                }
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private void CollectRamCpu(StringBuilder sb)
        {
            sb.AppendLine("── RAM & CPU ────────────────────────────────────────────────");
            try
            {
                string ps = "$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem; $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1; " +
                            "[PSCustomObject]@{ 'CPU Name' = $cpu.Name; 'CPU Cores' = $cpu.NumberOfCores; 'CPU LogicalProc' = $cpu.NumberOfLogicalProcessors; " +
                            "'RAM Total GB' = [math]::Round($cs.TotalPhysicalMemory/1GB,2); " +
                            "'RAM Available GB' = [math]::Round($os.FreePhysicalMemory/1MB,2); " +
                            "'RAM Used %' = [math]::Round((($cs.TotalPhysicalMemory - ($os.FreePhysicalMemory*1KB))/$cs.TotalPhysicalMemory)*100,1) } | Format-List";
                sb.AppendLine(RunPs(ps));
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private void CollectPendingReboot(StringBuilder sb)
        {
            sb.AppendLine("── Pending Reboot Check ─────────────────────────────────────");
            try
            {
                string ps =
                    "$reasons = @();" +
                    "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $reasons += 'Component-Based Servicing reboot pending' };" +
                    "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $reasons += 'Windows Update reboot required' };" +
                    "if (Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations; if ($v) { $reasons += 'Pending file rename operations exist' } };" +
                    "if ($reasons.Count -eq 0) { 'No pending reboot detected.' } else { 'REBOOT PENDING: ' + ($reasons -join '; ') }";
                sb.AppendLine(RunPs(ps).Trim());
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private void CollectBattery(StringBuilder sb)
        {
            sb.AppendLine("── Battery Status ───────────────────────────────────────────");
            try
            {
                string ps = "$b = Get-CimInstance Win32_Battery; if ($b) { $b | Select-Object Name,EstimatedChargeRemaining,BatteryStatus,DesignCapacity,FullChargeCapacity | Format-List } else { 'No battery found (desktop or battery info unavailable).' }";
                sb.AppendLine(RunPs(ps).Trim());
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private void CollectEventLogErrors(StringBuilder sb)
        {
            sb.AppendLine("── Event Log – Last 20 Critical/Error Events ────────────────");
            try
            {
                string ps = "Get-EventLog -LogName System -EntryType Error,Warning -Newest 20 | Select-Object TimeGenerated,EntryType,Source,Message | Format-Table -AutoSize -Wrap";
                sb.AppendLine(RunPs(ps).Trim());
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }
        }

        private string RunPs(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + Q(command),
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8
                };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return output;
                }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        private void OpenLogsFolder() { Process.Start("explorer.exe", Q(_logsDir)); }

        private void AppendOutput(string text)
        {
            if (_outputBox == null) return;
            if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; }
            _outputBox.AppendText(text + Environment.NewLine);
            _outputBox.SelectionStart = _outputBox.TextLength;
            _outputBox.ScrollToCaret();
        }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
        private static string SafeName(string v) { StringBuilder sb = new StringBuilder(); foreach (char c in v) sb.Append(Char.IsLetterOrDigit(c) ? c : '_'); return sb.ToString().Trim('_'); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Startup Manager tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class StartupPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private ListView _listView;
        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        // Holds reg path + value name for disable/enable actions
        private class StartupEntry
        {
            public string Name;
            public string Command;
            public string Location;   // display
            public string RegHive;    // HKCU or HKLM
            public string RegPath;
            public string RegValue;
            public bool   Enabled;
        }
        private List<StartupEntry> _entries = new List<StartupEntry>();

        public StartupPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Startup Manager ready. Click 'Refresh List' to load startup entries.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 4, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 48));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 52));
            Controls.Add(root);
            root.Controls.Add(BuildButtonGrid(), 0, 0);
            root.Controls.Add(BuildListView(), 0, 1);
            root.Controls.Add(BuildStatusPanel(), 0, 2);
            root.Controls.Add(BuildOutputBox(), 0, 3);
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10), ColumnCount = 4, RowCount = 1 };
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            AddBtn(grid, 0, 0, "Refresh List",       "Load all current startup entries",          () => LoadStartupEntries());
            AddBtn(grid, 1, 0, "Disable Selected",   "Disable the selected startup entry",        () => ToggleSelected(false));
            AddBtn(grid, 2, 0, "Enable Selected",    "Re-enable the selected startup entry",      () => ToggleSelected(true));
            AddBtn(grid, 3, 0, "Export to Log",      "Save startup list to a text log file",      () => ExportList());

            return grid;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn); grid.Controls.Add(btn, col, row);
        }

        private Control BuildListView()
        {
            _listView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text, Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.FixedSingle, MultiSelect = false };
            _listView.Columns.Add("Status",   70);
            _listView.Columns.Add("Name",    220);
            _listView.Columns.Add("Command", 500);
            _listView.Columns.Add("Location",180);
            return _listView;
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── logic ─────────────────────────────────────────────────────────────

        private void LoadStartupEntries()
        {
            if (_isRunning) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus("Loading startup entries...", true);
            Thread t = new Thread(delegate()
            {
                try
                {
                    List<StartupEntry> entries = new List<StartupEntry>();
                    ReadRunKey(entries, Registry.CurrentUser,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", true);
                    ReadRunKey(entries, Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", true);
                    ReadRunKey(entries, Registry.CurrentUser,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", true);
                    ReadDisabledKey(entries, Registry.CurrentUser,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "HKCU Run");
                    ReadDisabledKey(entries, Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "HKLM Run");

                    _entries = entries;
                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        _listView.Items.Clear();
                        foreach (StartupEntry e in entries)
                        {
                            ListViewItem item = new ListViewItem(e.Enabled ? "Enabled" : "DISABLED");
                            item.ForeColor = e.Enabled ? _green : Color.FromArgb(220, 80, 60);
                            item.SubItems.Add(e.Name);
                            item.SubItems.Add(e.Command);
                            item.SubItems.Add(e.Location);
                            item.Tag = e;
                            _listView.Items.Add(item);
                        }
                        AppendOutput("[" + Now() + "] Loaded " + entries.Count + " startup entry/entries.");
                    }));
                }
                catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); SetStatus("Ready", false); })); }
            });
            t.IsBackground = true; t.Start();
        }

        private void ReadRunKey(List<StartupEntry> entries, RegistryKey hive, string path, string location, bool enabled)
        {
            try
            {
                using (RegistryKey key = hive.OpenSubKey(path))
                {
                    if (key == null) return;
                    foreach (string valueName in key.GetValueNames())
                    {
                        entries.Add(new StartupEntry
                        {
                            Name = valueName,
                            Command = key.GetValue(valueName, "").ToString(),
                            Location = location,
                            RegHive = hive == Registry.CurrentUser ? "HKCU" : "HKLM",
                            RegPath = path,
                            RegValue = valueName,
                            Enabled = enabled
                        });
                    }
                }
            }
            catch { }
        }

        // Reads StartupApproved keys to find disabled entries (value data starting with 03)
        private void ReadDisabledKey(List<StartupEntry> entries, RegistryKey hive, string path, string locationFilter)
        {
            try
            {
                using (RegistryKey key = hive.OpenSubKey(path))
                {
                    if (key == null) return;
                    foreach (string valueName in key.GetValueNames())
                    {
                        byte[] data = key.GetValue(valueName) as byte[];
                        if (data == null || data.Length == 0) continue;
                        bool disabled = (data[0] == 3);
                        if (!disabled) continue;
                        // Mark matching entry in the list as disabled
                        foreach (StartupEntry e in entries)
                        {
                            if (String.Equals(e.Name, valueName, StringComparison.OrdinalIgnoreCase) && e.Location == locationFilter)
                                e.Enabled = false;
                        }
                    }
                }
            }
            catch { }
        }

        private void ToggleSelected(bool enable)
        {
            if (_listView.SelectedItems.Count == 0) { MessageBox.Show(ParentForm, "Select an entry first.", "Startup Manager", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            StartupEntry entry = _listView.SelectedItems[0].Tag as StartupEntry;
            if (entry == null) return;

            string verb = enable ? "enable" : "disable";
            if (MessageBox.Show(ParentForm, "Are you sure you want to " + verb + " startup entry:\r\n\r\n" + entry.Name + "\r\n\r\nChanges take effect on next login.", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            try
            {
                // Write to StartupApproved key
                string hiveName = entry.RegHive == "HKCU" ? "HKCU" : "HKLM";
                string approvedPath = (entry.RegHive == "HKCU" ? "" : "") +
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

                RegistryKey hive = entry.RegHive == "HKCU"
                    ? Registry.CurrentUser
                    : Registry.LocalMachine;

                using (RegistryKey key = hive.CreateSubKey(approvedPath))
                {
                    if (key == null) { AppendOutput("ERROR: Could not open StartupApproved registry key."); return; }
                    byte[] data = new byte[12];
                    data[0] = enable ? (byte)2 : (byte)3;
                    key.SetValue(entry.Name, data, RegistryValueKind.Binary);
                }

                entry.Enabled = enable;
                AppendOutput("[" + Now() + "] " + (enable ? "Enabled" : "Disabled") + " startup entry: " + entry.Name);
                LoadStartupEntries();
            }
            catch (Exception ex)
            {
                AppendOutput("ERROR: " + ex.Message + "\r\nTry running as Administrator.");
            }
        }

        private void ExportList()
        {
            if (_entries.Count == 0) { MessageBox.Show(ParentForm, "Load the startup list first.", "Startup Manager", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            string logFile = Path.Combine(_logsDir, "startup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("============================================================");
            sb.AppendLine("Frontline Suite – Startup Manager Export");
            sb.AppendLine("Generated: " + DateTime.Now.ToString("s"));
            sb.AppendLine("============================================================");
            sb.AppendLine();
            foreach (StartupEntry e in _entries)
            {
                sb.AppendLine(String.Format("{0,-10} {1,-40} {2}", e.Enabled ? "Enabled" : "DISABLED", e.Name, e.Command));
                sb.AppendLine("           Location: " + e.Location);
                sb.AppendLine();
            }
            File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8);
            AppendOutput("[" + Now() + "] Exported: " + logFile);
            MessageBox.Show(ParentForm, "Saved:\r\n" + logFile, "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void AppendOutput(string text) { if (_outputBox == null) return; if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; } _outputBox.AppendText(text + Environment.NewLine); _outputBox.SelectionStart = _outputBox.TextLength; _outputBox.ScrollToCaret(); }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Windows Update tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class WindowsUpdatePanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        public WindowsUpdatePanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Windows Update tab ready.");
            AppendOutput("Note: Installing updates requires the PSWindowsUpdate module or Windows Update Agent.");
            AppendOutput("All actions here use built-in Windows tools — no third-party software.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 3, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 136));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);
            root.Controls.Add(BuildButtonGrid(), 0, 0);
            root.Controls.Add(BuildStatusPanel(), 0, 1);
            root.Controls.Add(BuildOutputBox(), 0, 2);
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10), ColumnCount = 4, RowCount = 2 };
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            for (int r = 0; r < 2; r++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

            AddBtn(grid, 0, 0, "Update History",      "Show recently installed Windows updates",          () => RunHistory());
            AddBtn(grid, 1, 0, "Last Update Date",    "Show when Windows was last successfully updated",  () => RunLastUpdateDate());
            AddBtn(grid, 2, 0, "Pending Reboot?",     "Check if a Windows Update reboot is pending",      () => RunPendingReboot());
            AddBtn(grid, 3, 0, "Open Windows Update", "Open Windows Update in Settings",                  () => OpenWindowsUpdate());

            AddBtn(grid, 0, 1, "Reset WU Agent",      "Reset Windows Update components (advanced)",       () => RunResetWuAgent());
            AddBtn(grid, 1, 1, "Clear WU Cache",      "Clear Windows Update download cache",              () => RunClearWuCache());
            AddBtn(grid, 2, 1, "Update Services",     "Show status of Windows Update services",           () => RunUpdateServices());
            AddBtn(grid, 3, 1, "Logs Folder",         "Open saved Windows Update logs",                   () => OpenLogsFolder());

            return grid;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn); grid.Controls.Add(btn, col, row);
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68)); p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── actions ───────────────────────────────────────────────────────────

        private void RunHistory()
        {
            RunAsync("Update History", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Recent Windows Update History (last 25) ──────────────────");
                string ps = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 25 | Format-Table HotFixID,InstalledOn,Description,InstalledBy -AutoSize";
                sb.AppendLine(RunPs(ps).Trim());
            });
        }

        private void RunLastUpdateDate()
        {
            RunAsync("Last Update Date", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Last Successful Windows Update ───────────────────────────");
                string ps =
                    "$wu = New-Object -ComObject Microsoft.Update.AutoUpdate;" +
                    "$results = $wu.Results;" +
                    "'Last Search:  ' + $results.LastSearchSuccessDate;" +
                    "'Last Install: ' + $results.LastInstallationSuccessDate";
                sb.AppendLine(RunPs(ps).Trim());
                sb.AppendLine();
                sb.AppendLine("── Most Recent HotFix Installed ─────────────────────────────");
                string ps2 = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-List";
                sb.AppendLine(RunPs(ps2).Trim());
            });
        }

        private void RunPendingReboot()
        {
            RunAsync("Pending Reboot", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Windows Update Reboot Check ──────────────────────────────");
                string ps =
                    "$reasons = @();" +
                    "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $reasons += 'Windows Update reboot required' };" +
                    "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $reasons += 'Component Based Servicing reboot pending' };" +
                    "if ($reasons.Count -eq 0) { 'No Windows Update pending reboot detected.' } else { 'REBOOT PENDING: ' + ($reasons -join '; ') }";
                sb.AppendLine(RunPs(ps).Trim());
            });
        }

        private void RunUpdateServices()
        {
            RunAsync("Update Services", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Windows Update Related Services ──────────────────────────");
                string ps = "Get-Service wuauserv,bits,cryptsvc,trustedinstaller -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize";
                sb.AppendLine(RunPs(ps).Trim());
            });
        }

        private void RunResetWuAgent()
        {
            if (MessageBox.Show(ParentForm,
                "This will stop Windows Update services, rename the SoftwareDistribution and catroot2 folders, and restart services.\r\n\r\nThis resets the Windows Update cache and can fix stuck updates.\r\n\r\nAdministrator permission required. Continue?",
                "Reset Windows Update Agent", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            RunAsync("Reset WU Agent", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Resetting Windows Update Agent ───────────────────────────");
                string[] cmds = {
                    "net stop wuauserv",
                    "net stop cryptsvc",
                    "net stop bits",
                    "net stop msiserver",
                    "ren %SystemRoot%\\SoftwareDistribution SoftwareDistribution.old",
                    "ren %SystemRoot%\\System32\\catroot2 catroot2.old",
                    "net start wuauserv",
                    "net start cryptsvc",
                    "net start bits",
                    "net start msiserver"
                };
                foreach (string cmd in cmds)
                {
                    sb.AppendLine("> " + cmd);
                    sb.AppendLine(RunCmd("cmd.exe", "/c " + cmd).Trim());
                }
                sb.AppendLine();
                sb.AppendLine("Windows Update Agent reset complete. Try checking for updates now.");
            });
        }

        private void RunClearWuCache()
        {
            if (MessageBox.Show(ParentForm,
                "This will stop the Windows Update service and delete the contents of the SoftwareDistribution\\Download folder.\r\n\r\nThis forces Windows Update to re-download updates but does not affect installed updates.\r\n\r\nContinue?",
                "Clear Windows Update Cache", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            RunAsync("Clear WU Cache", delegate(StringBuilder sb)
            {
                sb.AppendLine("── Clearing Windows Update Download Cache ────────────────────");
                sb.AppendLine(RunCmd("cmd.exe", "/c net stop wuauserv").Trim());
                string dlPath = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "SoftwareDistribution", "Download");
                try
                {
                    if (Directory.Exists(dlPath))
                    {
                        foreach (string f in Directory.GetFiles(dlPath, "*", SearchOption.AllDirectories)) { try { File.Delete(f); } catch { } }
                        foreach (string d in Directory.GetDirectories(dlPath)) { try { Directory.Delete(d, true); } catch { } }
                        sb.AppendLine("Cleared: " + dlPath);
                    }
                    else sb.AppendLine("Download folder not found: " + dlPath);
                }
                catch (Exception ex) { sb.AppendLine("ERROR clearing cache: " + ex.Message); }
                sb.AppendLine(RunCmd("cmd.exe", "/c net start wuauserv").Trim());
                sb.AppendLine("Cache cleared. Open Windows Update to re-download pending updates.");
            });
        }

        private void OpenWindowsUpdate()
        {
            try { Process.Start(new ProcessStartInfo { FileName = "ms-settings:windowsupdate", UseShellExecute = true }); }
            catch { MessageBox.Show(ParentForm, "Could not open Windows Update settings.", "Windows Update", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void OpenLogsFolder() { Process.Start("explorer.exe", Q(_logsDir)); }

        private void RunAsync(string taskName, Action<StringBuilder> work)
        {
            if (_isRunning) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus("Running: " + taskName, true);
            Thread t = new Thread(delegate()
            {
                string logFile = Path.Combine(_logsDir, "winupdate_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + SafeName(taskName) + ".log");
                try
                {
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("============================================================");
                    sb.AppendLine("Frontline Suite – Windows Update");
                    sb.AppendLine("Task: " + taskName);
                    sb.AppendLine("Generated: " + DateTime.Now.ToString("s"));
                    sb.AppendLine("============================================================");
                    sb.AppendLine();
                    work(sb);
                    string result = sb.ToString();
                    File.WriteAllText(logFile, result, Encoding.UTF8);
                    AppendOutput(result);
                    AppendOutput("[" + Now() + "] Log saved: " + logFile);
                }
                catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); SetStatus("Ready", false); })); }
            });
            t.IsBackground = true; t.Start();
        }

        private string RunPs(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = "powershell.exe", Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + Q(command), CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
                using (Process p = Process.Start(psi)) { string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o; }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        private string RunCmd(string fileName, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = fileName, Arguments = arguments, CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                using (Process p = Process.Start(psi)) { string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); p.WaitForExit(); return o; }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        private void AppendOutput(string text) { if (_outputBox == null) return; if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; } _outputBox.AppendText(text + Environment.NewLine); _outputBox.SelectionStart = _outputBox.TextLength; _outputBox.ScrollToCaret(); }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
        private static string SafeName(string v) { StringBuilder sb = new StringBuilder(); foreach (char c in v) sb.Append(Char.IsLetterOrDigit(c) ? c : '_'); return sb.ToString().Trim('_'); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Event Log Viewer tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class EventLogPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private ListView _listView;
        private TextBox _detailBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private ComboBox _logCombo;
        private ComboBox _levelCombo;
        private NumericUpDown _countSpinner;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        private class EventEntry
        {
            public string Time;
            public string Level;
            public string Source;
            public string EventId;
            public string Message;
        }

        public EventLogPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendDetail("Event Log Viewer ready.\r\nSelect a log, level, and count, then click Load Events.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 4, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            Controls.Add(root);
            root.Controls.Add(BuildFilterBar(), 0, 0);
            root.Controls.Add(BuildListView(), 0, 1);
            root.Controls.Add(BuildStatusPanel(), 0, 2);
            root.Controls.Add(BuildDetailBox(), 0, 3);
        }

        private Control BuildFilterBar()
        {
            TableLayoutPanel bar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10, 8, 10, 8), ColumnCount = 8 };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 55));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 50));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            bar.Controls.Add(Lbl("Log:"), 0, 0);
            _logCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text };
            _logCombo.Items.AddRange(new object[] { "System", "Application", "Security" });
            _logCombo.SelectedIndex = 0;
            bar.Controls.Add(_logCombo, 1, 0);

            bar.Controls.Add(Lbl("Level:"), 2, 0);
            _levelCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text };
            _levelCombo.Items.AddRange(new object[] { "Error + Warning", "Error only", "Warning only", "All entries" });
            _levelCombo.SelectedIndex = 0;
            bar.Controls.Add(_levelCombo, 3, 0);

            bar.Controls.Add(Lbl("Count:"), 4, 0);
            _countSpinner = new NumericUpDown { Minimum = 10, Maximum = 500, Value = 50, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text, Dock = DockStyle.Fill };
            bar.Controls.Add(_countSpinner, 5, 0);

            Button load = StyledBtn("Load Events");
            load.Click += delegate { LoadEvents(); };
            _buttons.Add(load);
            bar.Controls.Add(load, 6, 0);

            Button export = StyledBtn("Export to Log");
            export.Click += delegate { ExportEvents(); };
            _buttons.Add(export);
            bar.Controls.Add(export, 7, 0);

            return bar;
        }

        private Label Lbl(string t) { return new Label { Text = t, ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold) }; }

        private Button StyledBtn(string text)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6, 0, 0, 0), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            return btn;
        }

        private Control BuildListView()
        {
            _listView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text, Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.FixedSingle, MultiSelect = false };
            _listView.Columns.Add("Time",     160);
            _listView.Columns.Add("Level",     70);
            _listView.Columns.Add("Source",   200);
            _listView.Columns.Add("Event ID",  75);
            _listView.Columns.Add("Message",  600);
            _listView.SelectedIndexChanged += delegate
            {
                if (_listView.SelectedItems.Count == 0) return;
                EventEntry e = _listView.SelectedItems[0].Tag as EventEntry;
                if (e != null) _detailBox.Text = "[" + e.Time + "]  " + e.Level + "  |  Source: " + e.Source + "  |  ID: " + e.EventId + "\r\n\r\n" + e.Message;
            };
            return _listView;
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68)); p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildDetailBox()
        {
            _detailBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = true, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.FixedSingle };
            return _detailBox;
        }

        // ── logic ─────────────────────────────────────────────────────────────

        private string _logName  = "System";
        private string _levelFilter = "Error + Warning";
        private int    _count    = 50;
        private List<EventEntry> _entries = new List<EventEntry>();

        private void LoadEvents()
        {
            if (_isRunning) return;
            _logName     = _logCombo.SelectedItem.ToString();
            _levelFilter = _levelCombo.SelectedItem.ToString();
            _count       = (int)_countSpinner.Value;

            _isRunning = true; SetButtonsEnabled(false); SetStatus("Loading " + _logName + " events...", true);
            Thread t = new Thread(delegate()
            {
                try
                {
                    string entryType;
                    switch (_levelFilter)
                    {
                        case "Error only":    entryType = "Error";          break;
                        case "Warning only":  entryType = "Warning";        break;
                        case "All entries":   entryType = "";               break;
                        default:              entryType = "Error,Warning";  break;
                    }

                    string filter = String.IsNullOrEmpty(entryType) ? "" : " -EntryType " + entryType;
                    string ps = "Get-EventLog -LogName " + _logName + filter + " -Newest " + _count +
                                " | Select-Object TimeGenerated,EntryType,Source,EventID,Message" +
                                " | ConvertTo-Csv -NoTypeInformation";
                    string raw = RunPs(ps);
                    List<EventEntry> entries = ParseCsvEvents(raw);
                    _entries = entries;

                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        _listView.BeginUpdate();
                        _listView.Items.Clear();
                        foreach (EventEntry e in entries)
                        {
                            ListViewItem item = new ListViewItem(e.Time);
                            item.ForeColor = e.Level.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0
                                ? Color.FromArgb(220, 80, 60)
                                : Color.FromArgb(244, 190, 60);
                            item.SubItems.Add(e.Level);
                            item.SubItems.Add(e.Source);
                            item.SubItems.Add(e.EventId);
                            item.SubItems.Add(e.Message.Replace("\r","").Replace("\n"," "));
                            item.Tag = e;
                            _listView.Items.Add(item);
                        }
                        _listView.EndUpdate();
                        SetStatus("Loaded " + entries.Count + " events from " + _logName, false);
                        AppendDetail("Loaded " + entries.Count + " events. Click a row to see full message.");
                    }));
                }
                catch (Exception ex) { AppendDetail("ERROR: " + ex.Message); SetStatus("Error", false); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); })); }
            });
            t.IsBackground = true; t.Start();
        }

        private List<EventEntry> ParseCsvEvents(string csv)
        {
            List<EventEntry> list = new List<EventEntry>();
            if (String.IsNullOrWhiteSpace(csv)) return list;
            string[] lines = csv.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            // skip header
            for (int i = 1; i < lines.Length; i++)
            {
                string[] cols = SplitCsvLine(lines[i].Trim());
                if (cols.Length < 5) continue;
                EventEntry e = new EventEntry
                {
                    Time    = Unquote(cols[0]),
                    Level   = Unquote(cols[1]),
                    Source  = Unquote(cols[2]),
                    EventId = Unquote(cols[3]),
                    Message = Unquote(cols[4])
                };
                list.Add(e);
            }
            return list;
        }

        private static string[] SplitCsvLine(string line)
        {
            List<string> fields = new List<string>();
            bool inQuote = false;
            StringBuilder cur = new StringBuilder();
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"')
                {
                    if (inQuote && i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; }
                    else inQuote = !inQuote;
                }
                else if (c == ',' && !inQuote) { fields.Add(cur.ToString()); cur.Clear(); }
                else cur.Append(c);
            }
            fields.Add(cur.ToString());
            return fields.ToArray();
        }

        private static string Unquote(string s) { s = s.Trim(); if (s.StartsWith("\"") && s.EndsWith("\"")) s = s.Substring(1, s.Length - 2); return s.Replace("\"\"", "\""); }

        private void ExportEvents()
        {
            if (_entries.Count == 0) { MessageBox.Show(ParentForm, "Load events first.", "Event Log Viewer", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            string logFile = Path.Combine(_logsDir, "eventlog_" + _logName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("============================================================");
            sb.AppendLine("Frontline Suite – Event Log Export");
            sb.AppendLine("Log: " + _logName + "  |  Filter: " + _levelFilter + "  |  Count: " + _entries.Count);
            sb.AppendLine("Generated: " + DateTime.Now.ToString("s"));
            sb.AppendLine("============================================================");
            sb.AppendLine();
            foreach (EventEntry e in _entries)
            {
                sb.AppendLine("[" + e.Time + "]  " + e.Level.PadRight(10) + "  ID:" + e.EventId.PadRight(8) + "  " + e.Source);
                sb.AppendLine("  " + e.Message.Replace("\n", "\n  "));
                sb.AppendLine("------------------------------------------------------------");
            }
            File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8);
            AppendDetail("[" + Now() + "] Exported: " + logFile);
            MessageBox.Show(ParentForm, "Saved:\r\n" + logFile, "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private string RunPs(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = "powershell.exe", Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + Q(command), CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
                using (Process p = Process.Start(psi)) { string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o; }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        private void AppendDetail(string text) { if (_detailBox == null) return; if (_detailBox.InvokeRequired) { _detailBox.BeginInvoke(new Action<string>(AppendDetail), text); return; } _detailBox.AppendText(text + Environment.NewLine); }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Junk Cleaner tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class JunkCleanerPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private TextBox _outputBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        // Targets: (display label, path, recursive)
        private static readonly Tuple<string, string, bool>[] _targets = new[]
        {
            Tuple.Create("User Temp (%TEMP%)",                  Environment.GetEnvironmentVariable("TEMP") ?? "", true),
            Tuple.Create("Windows Temp (C:\\Windows\\Temp)",    Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp"), true),
            Tuple.Create("Prefetch (C:\\Windows\\Prefetch)",    Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Prefetch"), false),
            Tuple.Create("IE/Edge Cache (WebCache)",            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WebCache"), false),
            Tuple.Create("Thumbnail Cache (thumbcache_*.db)",   Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\Explorer"), false),
            Tuple.Create("Windows Error Reports",               Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WER\ReportArchive"), true),
            Tuple.Create("Recent Files list",                   Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent"), false),
        };

        public JunkCleanerPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Junk Cleaner ready.");
            AppendOutput("Use 'Scan (Preview)' to see what will be removed before cleaning.");
            AppendOutput("Files in use will be skipped automatically.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 3, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);
            root.Controls.Add(BuildButtonGrid(), 0, 0);
            root.Controls.Add(BuildStatusPanel(), 0, 1);
            root.Controls.Add(BuildOutputBox(), 0, 2);
        }

        private Control BuildButtonGrid()
        {
            TableLayoutPanel grid = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10), ColumnCount = 4, RowCount = 1 };
            for (int c = 0; c < 4; c++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            AddBtn(grid, 0, 0, "Scan (Preview)",    "Show what would be removed without deleting anything", () => RunScan(preview: true));
            AddBtn(grid, 1, 0, "Clean All",         "Delete all junk from all targets (with confirmation)",  () => RunClean(all: true));
            AddBtn(grid, 2, 0, "Run Disk Cleanup",  "Open Windows built-in Disk Cleanup (cleanmgr)",         () => RunDiskCleanup());
            AddBtn(grid, 3, 0, "Logs Folder",       "Open saved cleaner logs",                               () => OpenLogsFolder());

            return grid;
        }

        private void AddBtn(TableLayoutPanel grid, int col, int row, string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn); grid.Controls.Add(btn, col, row);
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68)); p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── logic ─────────────────────────────────────────────────────────────

        private void RunScan(bool preview)
        {
            if (_isRunning) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus(preview ? "Scanning..." : "Cleaning...", true);

            Thread t = new Thread(delegate()
            {
                string logFile = Path.Combine(_logsDir, (preview ? "junk_scan_" : "junk_clean_") + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
                StringBuilder log = new StringBuilder();
                long totalSize = 0; int totalFiles = 0;

                log.AppendLine("============================================================");
                log.AppendLine("Frontline Suite – Junk Cleaner " + (preview ? "Scan Preview" : "Clean"));
                log.AppendLine("Generated: " + DateTime.Now.ToString("s"));
                log.AppendLine("============================================================");
                log.AppendLine();

                foreach (var target in _targets)
                {
                    string label = target.Item1;
                    string path  = target.Item2;
                    bool recurse = target.Item3;

                    if (String.IsNullOrEmpty(path) || !Directory.Exists(path))
                    {
                        AppendOutput("[SKIP] " + label + " — path not found");
                        log.AppendLine("[SKIP] " + label + " — path not found");
                        continue;
                    }

                    AppendOutput("── " + label);
                    log.AppendLine("── " + label + " (" + path + ")");

                    try
                    {
                        SearchOption opt = recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                        string[] files = Directory.GetFiles(path, "*", opt);
                        long sectionSize = 0; int sectionFiles = 0;

                        // For thumbnail cache, only target thumbcache_*.db files
                        if (label.Contains("Thumbnail"))
                            files = Array.FindAll(files, f => Path.GetFileName(f).StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase) && f.EndsWith(".db", StringComparison.OrdinalIgnoreCase));

                        int skipped = 0; int accessDenied = 0;

                        foreach (string file in files)
                        {
                            try
                            {
                                FileInfo fi = new FileInfo(file);
                                sectionSize += fi.Length;
                                sectionFiles++;
                                if (!preview)
                                {
                                    fi.Delete();
                                    log.AppendLine("  DEL " + file);
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                // System/protected file — count separately, don't log path (could be sensitive)
                                accessDenied++;
                                log.AppendLine("  SKIP (access denied): " + Path.GetFileName(file));
                            }
                            catch (IOException)
                            {
                                // File in use by another process
                                skipped++;
                            }
                            catch
                            {
                                skipped++;
                            }
                        }

                        totalSize  += sectionSize;
                        totalFiles += sectionFiles;
                        string summary = String.Format("  {0} file(s), {1:F2} MB", sectionFiles, sectionSize / 1048576.0);
                        if (skipped > 0)     summary += "  (" + skipped + " in use/skipped)";
                        if (accessDenied > 0) summary += "  (" + accessDenied + " access denied)";
                        AppendOutput(summary);
                        log.AppendLine(summary);
                    }
                    catch (Exception ex)
                    {
                        AppendOutput("  ERROR: " + ex.Message);
                        log.AppendLine("  ERROR: " + ex.Message);
                    }
                }

                string total = String.Format("\r\n{0}: {1} file(s), {2:F2} MB total", preview ? "PREVIEW TOTAL" : "CLEANED", totalFiles, totalSize / 1048576.0);
                AppendOutput(total);
                log.AppendLine(total);

                File.WriteAllText(logFile, log.ToString(), Encoding.UTF8);
                AppendOutput("[" + Now() + "] Log saved: " + logFile);
                BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); SetStatus("Ready", false); }));
            });
            t.IsBackground = true; t.Start();
        }

        private void RunClean(bool all)
        {
            if (MessageBox.Show(ParentForm,
                "This will permanently delete temporary and junk files from:\r\n\r\n" +
                "• User Temp folder\r\n• Windows Temp folder\r\n• Prefetch cache\r\n• Web cache\r\n" +
                "• Thumbnail cache\r\n• Windows Error Reports\r\n• Recent Files list\r\n\r\n" +
                "Files currently in use will be skipped automatically.\r\n\r\nProceed?",
                "Confirm Clean", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            RunScan(preview: false);
        }

        private void RunDiskCleanup()
        {
            try { Process.Start("cleanmgr.exe"); }
            catch { MessageBox.Show(ParentForm, "Could not launch Disk Cleanup.", "Junk Cleaner", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void OpenLogsFolder() { Process.Start("explorer.exe", Q(_logsDir)); }

        private void AppendOutput(string text) { if (_outputBox == null) return; if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; } _outputBox.AppendText(text + Environment.NewLine); _outputBox.SelectionStart = _outputBox.TextLength; _outputBox.ScrollToCaret(); }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Hosts File Viewer / Editor tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class HostsFilePanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green = Color.FromArgb(107, 218, 143);
        private readonly string _logsDir;

        private TextBox _editor;
        private Label _statusLabel;
        private Label _infoLabel;
        private readonly List<Button> _buttons = new List<Button>();

        private static readonly string HostsPath = Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
            @"System32\drivers\etc\hosts");

        private static readonly string DefaultHosts =
            "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
            "#\r\n" +
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
            "#\r\n" +
            "# This file contains the mappings of IP addresses to host names. Each\r\n" +
            "# entry should be kept on an individual line. The IP address should\r\n" +
            "# be placed in the first column followed by the corresponding host name.\r\n" +
            "# The IP address and the host name should be separated by at least one\r\n" +
            "# space.\r\n" +
            "#\r\n" +
            "# Additionally, comments (such as these) may be inserted on individual\r\n" +
            "# lines or following the machine name denoted by a '#' symbol.\r\n" +
            "#\r\n" +
            "# For example:\r\n" +
            "#\r\n" +
            "#      102.54.94.97     rhino.acme.com          # source server\r\n" +
            "#       38.25.63.10     x.acme.com              # x client host\r\n" +
            "\r\n" +
            "# localhost name resolution is handled within DNS itself.\r\n" +
            "#\t127.0.0.1       localhost\r\n" +
            "#\t::1             localhost\r\n";

        public HostsFilePanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            LoadHosts();
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 3, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            Controls.Add(root);
            root.Controls.Add(BuildToolbar(), 0, 0);
            root.Controls.Add(BuildEditor(), 0, 1);
            root.Controls.Add(BuildStatusBar(), 0, 2);
        }

        private Control BuildToolbar()
        {
            TableLayoutPanel bar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10, 8, 10, 8), ColumnCount = 7 };
            for (int c = 0; c < 7; c++) bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 7));

            Button load    = Btn("Reload File",    "Reload the hosts file from disk",                         () => LoadHosts());
            Button save    = Btn("Save Changes",   "Save edits back to the hosts file (requires Admin)",      () => SaveHosts());
            Button backup  = Btn("Backup",         "Save a timestamped backup of the current hosts file",     () => BackupHosts());
            Button restore = Btn("Reset to Default","Replace hosts file with Windows clean default",          () => ResetHosts());
            Button flush   = Btn("Flush DNS",      "Run ipconfig /flushdns after saving",                     () => FlushDns());
            Button analyze = Btn("Analyze",        "Highlight suspicious or non-default entries",             () => AnalyzeHosts());
            Button openDir = Btn("Open Folder",    "Open the hosts file folder in Explorer",                  () => OpenHostsFolder());

            bar.Controls.Add(load,    0, 0);
            bar.Controls.Add(save,    1, 0);
            bar.Controls.Add(backup,  2, 0);
            bar.Controls.Add(restore, 3, 0);
            bar.Controls.Add(flush,   4, 0);
            bar.Controls.Add(analyze, 5, 0);
            bar.Controls.Add(openDir, 6, 0);

            return bar;
        }

        private Button Btn(string text, string tip, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(4, 0, 4, 0), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            new ToolTip { InitialDelay = 250, ReshowDelay = 100 }.SetToolTip(btn, tip);
            _buttons.Add(btn);
            return btn;
        }

        private Control BuildEditor()
        {
            _editor = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = false,
                BackColor = Color.FromArgb(5, 7, 9),
                ForeColor = _green,
                Font = new Font("Consolas", 10F),
                BorderStyle = BorderStyle.FixedSingle,
                AcceptsReturn = true,
                AcceptsTab = true
            };
            return _editor;
        }

        private Control BuildStatusBar()
        {
            TableLayoutPanel bar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel, ColumnCount = 2, Padding = new Padding(8, 0, 8, 0) };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 9F) };
            _infoLabel   = new Label { Text = "", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleRight, Font = new Font("Segoe UI", 9F) };
            bar.Controls.Add(_statusLabel, 0, 0);
            bar.Controls.Add(_infoLabel,   1, 0);
            return bar;
        }

        // ── logic ─────────────────────────────────────────────────────────────

        private void LoadHosts()
        {
            try
            {
                if (!File.Exists(HostsPath)) { _editor.Text = "# Hosts file not found at: " + HostsPath; SetStatus("File not found"); return; }
                _editor.Text = File.ReadAllText(HostsPath);
                int activeLines = _editor.Lines.Count(l => !String.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#"));
                SetStatus("Loaded: " + HostsPath);
                _infoLabel.Text = activeLines + " active entr" + (activeLines == 1 ? "y" : "ies");
            }
            catch (Exception ex) { SetStatus("ERROR: " + ex.Message); }
        }

        private void SaveHosts()
        {
            if (!IsAdministrator())
            {
                MessageBox.Show(ParentForm, "Administrator permission is required to edit the hosts file.\r\nRun Frontline Suite as Administrator.", "Hosts File", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (MessageBox.Show(ParentForm, "Save changes to:\r\n" + HostsPath + "\r\n\r\nA backup will be created first.", "Save Hosts File", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try
            {
                BackupHosts(silent: true);
                File.WriteAllText(HostsPath, _editor.Text, Encoding.UTF8);
                SetStatus("Saved successfully.");
                MessageBox.Show(ParentForm, "Hosts file saved.\r\nRun 'Flush DNS' to apply changes immediately.", "Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show(ParentForm, "Save failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void BackupHosts(bool silent = false)
        {
            try
            {
                if (!File.Exists(HostsPath)) { if (!silent) MessageBox.Show(ParentForm, "Hosts file not found.", "Backup", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                string dest = Path.Combine(_logsDir, "hosts_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                File.Copy(HostsPath, dest, true);
                if (!silent) { SetStatus("Backup saved: " + dest); MessageBox.Show(ParentForm, "Backup saved:\r\n" + dest, "Backup Complete", MessageBoxButtons.OK, MessageBoxIcon.Information); }
            }
            catch (Exception ex) { if (!silent) MessageBox.Show(ParentForm, "Backup failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void ResetHosts()
        {
            if (!IsAdministrator()) { MessageBox.Show(ParentForm, "Administrator permission required.", "Hosts File", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (MessageBox.Show(ParentForm, "This will replace the hosts file with the Windows default.\r\n\r\nAll current entries (including any blocks or redirects) will be removed.\r\nA backup will be saved first.\r\n\r\nProceed?", "Reset to Default", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                BackupHosts(silent: true);
                File.WriteAllText(HostsPath, DefaultHosts, Encoding.ASCII);
                LoadHosts();
                SetStatus("Hosts file reset to Windows default.");
                MessageBox.Show(ParentForm, "Hosts file reset to default.\r\nRun 'Flush DNS' to apply.", "Reset Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show(ParentForm, "Reset failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void FlushDns()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo { FileName = "ipconfig.exe", Arguments = "/flushdns", CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                using (Process p = Process.Start(psi)) { string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); SetStatus("DNS flushed. " + o.Trim()); }
                MessageBox.Show(ParentForm, "DNS cache flushed successfully.", "Flush DNS", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show(ParentForm, "Flush failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void AnalyzeHosts()
        {
            List<string> suspicious = new List<string>();
            List<string> active = new List<string>();

            foreach (string line in _editor.Lines)
            {
                string trimmed = line.Trim();
                if (String.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;
                active.Add(trimmed);

                // Flag anything that isn't the standard localhost entries
                bool isLocalhost = trimmed.StartsWith("127.0.0.1") || trimmed.StartsWith("::1") || trimmed.StartsWith("0.0.0.0");
                if (!isLocalhost) { suspicious.Add(trimmed); continue; }

                // Flag redirects of well-known domains
                string lower = trimmed.ToLowerInvariant();
                string[] watched = { "google", "microsoft", "windows", "apple", "amazon", "facebook", "paypal", "bank" };
                foreach (string w in watched) { if (lower.Contains(w)) { suspicious.Add("!! WATCHED DOMAIN: " + trimmed); break; } }
            }

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("── Hosts File Analysis ──────────────────────────────────────");
            sb.AppendLine("Active entries (non-comment):  " + active.Count);
            sb.AppendLine("Entries that may need review:  " + suspicious.Count);
            sb.AppendLine();
            if (suspicious.Count == 0) { sb.AppendLine("No suspicious entries detected. File appears clean."); }
            else { sb.AppendLine("Entries to review:"); foreach (string s in suspicious) sb.AppendLine("  " + s); }
            sb.AppendLine();
            sb.AppendLine("Note: Ad-blockers and security tools legitimately add many entries.");
            sb.AppendLine("Review flagged lines manually before removing anything.");

            Form f = new Form { Text = "Hosts File Analysis", Size = new Size(800, 500), StartPosition = FormStartPosition.CenterParent, BackColor = _bg, ForeColor = _text, Font = new Font("Segoe UI", 10F) };
            TextBox tb = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), Text = sb.ToString() };
            f.Controls.Add(tb);
            f.ShowDialog(ParentForm);
        }

        private void OpenHostsFolder()
        {
            string dir = Path.GetDirectoryName(HostsPath);
            if (Directory.Exists(dir)) Process.Start("explorer.exe", Q(dir));
        }

        private void SetStatus(string text) { if (InvokeRequired) { BeginInvoke(new Action<string>(SetStatus), text); return; } _statusLabel.Text = text; }
        private static bool IsAdministrator() { try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Firewall Manager tab
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class FirewallPanel : UserControl
    {
        private readonly Color _bg, _panel, _panel2, _orange, _blue, _text, _muted;
        private readonly Color _green  = Color.FromArgb(107, 218, 143);
        private readonly Color _red    = Color.FromArgb(220, 80,  60);
        private readonly Color _yellow = Color.FromArgb(244, 190, 60);
        private readonly string _logsDir;

        private ListView   _listView;
        private TextBox    _outputBox;
        private Label      _statusLabel;
        private ProgressBar _progressBar;
        private ComboBox   _directionCombo;
        private ComboBox   _filterCombo;
        private TextBox    _searchBox;
        private readonly List<Button> _buttons = new List<Button>();
        private bool _isRunning;

        private class FwRule
        {
            public string Name;
            public string Direction;   // Inbound / Outbound
            public string Action;      // Allow / Block
            public string Enabled;     // True / False
            public string Profile;     // Domain, Private, Public, Any
            public string Protocol;
            public string LocalPort;
            public string RemotePort;
            public string Program;
        }

        private List<FwRule> _allRules = new List<FwRule>();

        public FirewallPanel(string logsDir, Color bg, Color panel, Color panel2,
            Color orange, Color blue, Color text, Color muted)
        {
            _logsDir = logsDir;
            _bg = bg; _panel = panel; _panel2 = panel2;
            _orange = orange; _blue = blue; _text = text; _muted = muted;
            Dock = DockStyle.Fill;
            BackColor = _bg;
            Build();
            AppendOutput("Firewall Manager ready.");
            AppendOutput(IsAdministrator()
                ? "Running as Administrator — enable/disable actions available."
                : "WARNING: Not running as Administrator. Rule changes will be unavailable.");
            AppendOutput("Click 'Load Rules' to populate the list.");
        }

        private void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, RowCount = 4, ColumnCount = 1, Padding = new Padding(0, 8, 0, 0) };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 62));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 38));
            Controls.Add(root);
            root.Controls.Add(BuildToolbar(), 0, 0);
            root.Controls.Add(BuildListView(), 0, 1);
            root.Controls.Add(BuildStatusPanel(), 0, 2);
            root.Controls.Add(BuildOutputBox(), 0, 3);
        }

        private Control BuildToolbar()
        {
            TableLayoutPanel bar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _panel2, Padding = new Padding(10, 8, 10, 8), ColumnCount = 10 };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 75));   // Direction label
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));  // Direction combo
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 55));   // Filter label
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));  // Filter combo
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 55));   // Search label
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));   // Search box
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));  // Load
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));  // Disable Selected
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));  // Enable Selected
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));  // Export

            bar.Controls.Add(Lbl("Direction:"), 0, 0);
            _directionCombo = Combo(new[] { "Both", "Inbound", "Outbound" });
            _directionCombo.SelectedIndexChanged += delegate { ApplyFilter(); };
            bar.Controls.Add(_directionCombo, 1, 0);

            bar.Controls.Add(Lbl("Show:"), 2, 0);
            _filterCombo = Combo(new[] { "All rules", "Enabled only", "Disabled only", "Block rules", "Allow rules" });
            _filterCombo.SelectedIndexChanged += delegate { ApplyFilter(); };
            bar.Controls.Add(_filterCombo, 3, 0);

            bar.Controls.Add(Lbl("Search:"), 4, 0);
            _searchBox = new TextBox { Dock = DockStyle.Fill, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text, Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.FixedSingle };
            _searchBox.TextChanged += delegate { ApplyFilter(); };
            bar.Controls.Add(_searchBox, 5, 0);

            Button load    = Btn("Load Rules",      () => LoadRules());
            Button disable = Btn("Disable Selected",() => ToggleSelected(false));
            Button enable  = Btn("Enable Selected", () => ToggleSelected(true));
            Button export  = Btn("Export List",     () => ExportRules());

            _buttons.Add(load); _buttons.Add(disable); _buttons.Add(enable); _buttons.Add(export);
            bar.Controls.Add(load,    6, 0);
            bar.Controls.Add(disable, 7, 0);
            bar.Controls.Add(enable,  8, 0);
            bar.Controls.Add(export,  9, 0);

            return bar;
        }

        private Label Lbl(string t)
        {
            return new Label { Text = t, ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold) };
        }

        private ComboBox Combo(string[] items)
        {
            ComboBox cb = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text };
            cb.Items.AddRange(items); cb.SelectedIndex = 0;
            return cb;
        }

        private Button Btn(string text, Action action)
        {
            Button btn = new Button { Text = text, Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0), BackColor = _panel, ForeColor = _text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderColor = _orange; btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 39, 56);
            btn.Click += delegate { action(); };
            return btn;
        }

        private Control BuildListView()
        {
            _listView = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                GridLines = true, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text,
                Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.FixedSingle,
                MultiSelect = false, VirtualMode = false
            };
            _listView.Columns.Add("Status",     70);
            _listView.Columns.Add("Direction",  80);
            _listView.Columns.Add("Action",     65);
            _listView.Columns.Add("Name",      300);
            _listView.Columns.Add("Protocol",   70);
            _listView.Columns.Add("Local Port", 90);
            _listView.Columns.Add("Profile",   120);
            _listView.Columns.Add("Program",   300);
            _listView.SelectedIndexChanged += delegate
            {
                if (_listView.SelectedItems.Count == 0) return;
                FwRule r = _listView.SelectedItems[0].Tag as FwRule;
                if (r == null) return;
                AppendOutput(String.Format("[Selected] {0} | {1} | {2} | Enabled:{3} | Proto:{4} | LPort:{5} | RPort:{6} | Profile:{7}",
                    r.Name, r.Direction, r.Action, r.Enabled, r.Protocol, r.LocalPort, r.RemotePort, r.Profile));
                if (!String.IsNullOrWhiteSpace(r.Program) && r.Program != "Any")
                    AppendOutput("  Program: " + r.Program);
            };
            return _listView;
        }

        private Control BuildStatusPanel()
        {
            TableLayoutPanel p = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = _bg, ColumnCount = 2, Padding = new Padding(0, 8, 0, 4) };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68)); p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            _statusLabel = new Label { Text = "Ready", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            p.Controls.Add(_statusLabel, 0, 0);
            _progressBar = new ProgressBar { Dock = DockStyle.Fill, Style = ProgressBarStyle.Blocks, Minimum = 0, Maximum = 100, Value = 0 };
            p.Controls.Add(_progressBar, 1, 0);
            return p;
        }

        private Control BuildOutputBox()
        {
            _outputBox = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _green, Font = new Font("Consolas", 10F), BorderStyle = BorderStyle.FixedSingle };
            return _outputBox;
        }

        // ── logic ─────────────────────────────────────────────────────────────

        private void LoadRules()
        {
            if (_isRunning) return;
            _isRunning = true; SetButtonsEnabled(false); SetStatus("Loading firewall rules...", true);

            Thread t = new Thread(delegate()
            {
                try
                {
                    // Use netsh to dump all rules as a parseable block
                    string raw = RunCmd("netsh", "advfirewall firewall show rule name=all verbose");
                    List<FwRule> rules = ParseNetshRules(raw);
                    _allRules = rules;

                    BeginInvoke(new MethodInvoker(delegate()
                    {
                        ApplyFilter();
                        AppendOutput("[" + Now() + "] Loaded " + rules.Count + " firewall rules.");
                        SetStatus("Loaded " + rules.Count + " rules", false);
                    }));
                }
                catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
                finally { BeginInvoke(new MethodInvoker(delegate() { _isRunning = false; SetButtonsEnabled(true); if (_statusLabel.Text.StartsWith("Loading")) SetStatus("Ready", false); })); }
            });
            t.IsBackground = true; t.Start();
        }

        private List<FwRule> ParseNetshRules(string raw)
        {
            List<FwRule> rules = new List<FwRule>();
            if (String.IsNullOrWhiteSpace(raw)) return rules;

            // netsh outputs blocks separated by blank lines; each block is one rule
            string[] blocks = raw.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string block in blocks)
            {
                if (!block.Contains("Rule Name:")) continue;
                FwRule r = new FwRule();
                foreach (string rawLine in block.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int colon = rawLine.IndexOf(':');
                    if (colon < 0) continue;
                    string key = rawLine.Substring(0, colon).Trim().ToLowerInvariant();
                    string val = rawLine.Substring(colon + 1).Trim();
                    switch (key)
                    {
                        case "rule name":   r.Name      = val; break;
                        case "direction":   r.Direction = val; break;
                        case "action":      r.Action    = val; break;
                        case "enabled":     r.Enabled   = val; break;
                        case "profiles":    r.Profile   = val; break;
                        case "protocol":    r.Protocol  = val; break;
                        case "localport":   r.LocalPort = val; break;
                        case "remoteport":  r.RemotePort= val; break;
                        case "program":     r.Program   = val; break;
                    }
                }
                if (!String.IsNullOrWhiteSpace(r.Name)) rules.Add(r);
            }
            return rules;
        }

        private void ApplyFilter()
        {
            if (_allRules == null || _allRules.Count == 0) return;

            string dir    = _directionCombo.SelectedItem != null ? _directionCombo.SelectedItem.ToString() : "Both";
            string filter = _filterCombo.SelectedItem    != null ? _filterCombo.SelectedItem.ToString()    : "All rules";
            string search = _searchBox.Text.Trim().ToLowerInvariant();

            IEnumerable<FwRule> filtered = _allRules;

            if (dir != "Both")
                filtered = filtered.Where(r => String.Equals(r.Direction, dir, StringComparison.OrdinalIgnoreCase));

            switch (filter)
            {
                case "Enabled only":  filtered = filtered.Where(r => String.Equals(r.Enabled, "Yes", StringComparison.OrdinalIgnoreCase)); break;
                case "Disabled only": filtered = filtered.Where(r => !String.Equals(r.Enabled, "Yes", StringComparison.OrdinalIgnoreCase)); break;
                case "Block rules":   filtered = filtered.Where(r => String.Equals(r.Action, "Block", StringComparison.OrdinalIgnoreCase)); break;
                case "Allow rules":   filtered = filtered.Where(r => String.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase)); break;
            }

            if (!String.IsNullOrEmpty(search))
                filtered = filtered.Where(r =>
                    (r.Name    ?? "").ToLowerInvariant().Contains(search) ||
                    (r.Program ?? "").ToLowerInvariant().Contains(search) ||
                    (r.LocalPort ?? "").ToLowerInvariant().Contains(search));

            List<FwRule> results = filtered.ToList();

            _listView.BeginUpdate();
            _listView.Items.Clear();
            foreach (FwRule r in results)
            {
                bool enabled = String.Equals(r.Enabled, "Yes", StringComparison.OrdinalIgnoreCase);
                bool isBlock = String.Equals(r.Action, "Block", StringComparison.OrdinalIgnoreCase);

                ListViewItem item = new ListViewItem(enabled ? "Enabled" : "Disabled");
                item.ForeColor = !enabled ? _muted : isBlock ? _red : _green;
                item.SubItems.Add(r.Direction ?? "");
                item.SubItems.Add(r.Action    ?? "");
                item.SubItems.Add(r.Name      ?? "");
                item.SubItems.Add(r.Protocol  ?? "");
                item.SubItems.Add(r.LocalPort ?? "");
                item.SubItems.Add(r.Profile   ?? "");
                item.SubItems.Add(r.Program   ?? "");
                item.Tag = r;
                _listView.Items.Add(item);
            }
            _listView.EndUpdate();
            SetStatus("Showing " + results.Count + " of " + _allRules.Count + " rules", false);
        }

        private void ToggleSelected(bool enable)
        {
            if (_listView.SelectedItems.Count == 0)
            {
                MessageBox.Show(ParentForm, "Select a rule from the list first.", "Firewall Manager", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (!IsAdministrator())
            {
                MessageBox.Show(ParentForm, "Administrator permission is required to change firewall rules.\r\nRun Frontline Suite as Administrator.", "Firewall Manager", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            FwRule rule = _listView.SelectedItems[0].Tag as FwRule;
            if (rule == null) return;

            string verb = enable ? "enable" : "disable";
            if (MessageBox.Show(ParentForm,
                "Are you sure you want to " + verb + " this firewall rule?\r\n\r\n" + rule.Name,
                "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            try
            {
                string newState = enable ? "yes" : "no";
                string args = "advfirewall firewall set rule name=" + Q(rule.Name) + " new enable=" + newState;
                string result = RunCmd("netsh", args);
                AppendOutput("[" + Now() + "] " + (enable ? "Enabled" : "Disabled") + " rule: " + rule.Name);
                AppendOutput("  " + result.Trim());
                // Refresh
                LoadRules();
            }
            catch (Exception ex) { AppendOutput("ERROR: " + ex.Message); }
        }

        private void ExportRules()
        {
            if (_allRules.Count == 0)
            {
                MessageBox.Show(ParentForm, "Load rules first.", "Firewall Manager", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string logFile = Path.Combine(_logsDir, "firewall_rules_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("============================================================");
            sb.AppendLine("Frontline Suite – Firewall Rules Export");
            sb.AppendLine("Generated: " + DateTime.Now.ToString("s"));
            sb.AppendLine("Total rules: " + _allRules.Count);
            sb.AppendLine("============================================================");
            sb.AppendLine();

            // Group: Block rules first (most security-relevant), then by direction
            var ordered = _allRules
                .OrderBy(r => String.Equals(r.Action, "Block", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(r => r.Direction ?? "")
                .ThenBy(r => String.Equals(r.Enabled, "Yes", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(r => r.Name ?? "");

            foreach (FwRule r in ordered)
            {
                sb.AppendLine(String.Format("{0,-10} {1,-10} {2,-10} {3}", r.Enabled ?? "", r.Direction ?? "", r.Action ?? "", r.Name ?? ""));
                if (!String.IsNullOrWhiteSpace(r.Program) && r.Program != "Any")
                    sb.AppendLine("           Program: " + r.Program);
                if (!String.IsNullOrWhiteSpace(r.LocalPort) && r.LocalPort != "Any")
                    sb.AppendLine("           Port: " + r.LocalPort + " / Protocol: " + (r.Protocol ?? ""));
            }

            File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8);
            AppendOutput("[" + Now() + "] Exported: " + logFile);
            MessageBox.Show(ParentForm, "Saved:\r\n" + logFile, "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private string RunCmd(string fileName, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = fileName, Arguments = arguments,
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.Unicode  // netsh outputs UTF-16
                };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return output;
                }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        private void AppendOutput(string text) { if (_outputBox == null) return; if (_outputBox.InvokeRequired) { _outputBox.BeginInvoke(new Action<string>(AppendOutput), text); return; } _outputBox.AppendText(text + Environment.NewLine); _outputBox.SelectionStart = _outputBox.TextLength; _outputBox.ScrollToCaret(); }
        private void SetButtonsEnabled(bool enabled) { if (InvokeRequired) { BeginInvoke(new Action<bool>(SetButtonsEnabled), enabled); return; } foreach (Button b in _buttons) b.Enabled = enabled; }
        private void SetStatus(string text, bool running) { if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, running); return; } _statusLabel.Text = text; if (running) { _progressBar.Style = ProgressBarStyle.Marquee; _progressBar.MarqueeAnimationSpeed = 30; } else { _progressBar.MarqueeAnimationSpeed = 0; _progressBar.Style = ProgressBarStyle.Blocks; _progressBar.Value = 0; } }
        private static bool IsAdministrator() { try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
        private static string Q(string v) { if (v == null) return "\"\""; return "\"" + v.Replace("\"", "\\\"") + "\""; }
        private static string Now() { return DateTime.Now.ToString("HH:mm:ss"); }
    }
}
