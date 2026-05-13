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

    // ─────────────────────────────────────────────────────────────────────────
    //  Main window – tab container
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class MainForm : Form
    {
        private const string AppName    = "Frontline Suite";
        private const string AppVersion = "1.0.0";

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
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            Controls.Add(root);

            root.Controls.Add(BuildHeader(), 0, 0);

            _tabs = new TabControl();
            _tabs.Dock = DockStyle.Fill;
            _tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            _tabs.ItemSize = new Size(220, 36);
            _tabs.SizeMode = TabSizeMode.Fixed;
            _tabs.Appearance = TabAppearance.Normal;
            _tabs.BackColor = _bg;
            _tabs.Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold);
            _tabs.DrawItem += DrawTab;
            _tabs.Padding = new Point(12, 6);

            TabPage scannerPage = new TabPage("  Security Scanner");
            scannerPage.BackColor = _bg;
            scannerPage.Padding = new Padding(0);
            scannerPage.Controls.Add(new ScannerPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            TabPage shieldPage = new TabPage("  Network Shield");
            shieldPage.BackColor = _bg;
            shieldPage.Padding = new Padding(0);
            shieldPage.Controls.Add(new NetworkPanel(_logsDir, _bg, _panel, _panel2, _orange, _blue, _text, _muted));

            _tabs.TabPages.Add(scannerPage);
            _tabs.TabPages.Add(shieldPage);

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
            title.Location = new Point(92, 14);
            title.Text = "FRONTLINE SUITE";
            title.ForeColor = _text;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold);
            header.Controls.Add(title);

            Label sub = new Label();
            sub.AutoSize = true;
            sub.Location = new Point(96, 55);
            sub.Text = "Security Scanner  •  Network Shield  •  DNS Protection  •  Local Logs";
            sub.ForeColor = _muted;
            sub.Font = new Font("Segoe UI", 10F, FontStyle.Regular);
            header.Controls.Add(sub);

            Label badge = new Label();
            badge.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            badge.AutoSize = false;
            badge.TextAlign = ContentAlignment.MiddleRight;
            badge.Size = new Size(380, 56);
            badge.Text = "C# FALLBACK BUILD v" + AppVersion + "\r\nNo .NET SDK Required";
            badge.ForeColor = _blue;
            badge.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
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
            footer.Text = "Frontline Tech Consulting, LLC  •  Local logs only  •  Only scan networks you own or have permission to assess";
            footer.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            return footer;
        }
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
            panel.ColumnCount = 4;
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 135));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));

            Label lbl = new Label { Text = "Network Adapter", ForeColor = _muted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold) };
            panel.Controls.Add(lbl, 0, 0);

            _adapterCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(5, 7, 9), ForeColor = _text };
            _adapterCombo.SelectedIndexChanged += delegate { UpdateDnsDisplay(); };
            panel.Controls.Add(_adapterCombo, 1, 0);

            _dnsLabel = new Label { Text = "Current DNS: Not checked yet", ForeColor = _termGreen, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Consolas", 9F) };
            panel.Controls.Add(_dnsLabel, 2, 0);

            Button refresh = SmallBtn("Refresh Adapters");
            refresh.Click += delegate { RefreshAdapters(); };
            panel.Controls.Add(refresh, 3, 0);

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
            AddBtn(grid, 2, 2, "Network Settings",       "Open Windows network settings",                       () => OpenNetworkSettings());
            AddBtn(grid, 3, 2, "Clear Console",          "Clear the output window",                             () => { _outputBox.Clear(); AppendOutput(AppName + " console cleared."); });

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
            AppendOutput("[" + Now() + "] Starting scan on: " + adapter.Name);
            AppendOutput("[" + Now() + "] Local IP: " + adapter.IpAddress + " | Mask: " + adapter.SubnetMask);
            List<IPAddress> hosts = BuildHostList(adapter.IpAddress, adapter.SubnetMask, out _lastScanNote);
            AppendOutput("[" + Now() + "] " + _lastScanNote);
            AppendOutput("[" + Now() + "] Checking " + hosts.Count + " address(es)...");

            List<IPAddress> alive = new List<IPAddress>();
            object lck = new object();
            int checkedCount = 0;

            Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = 64 }, delegate(IPAddress ip)
            {
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

        private static List<IPAddress> BuildHostList(IPAddress localIp, IPAddress subnetMask, out string scanNote)
        {
            uint ip = AddressToUInt32(localIp);
            uint mask = AddressToUInt32(subnetMask);
            int prefix = MaskToPrefix(mask);
            if (prefix < 24) { mask = PrefixToMask(24); prefix = 24; }
            uint network = ip & mask;
            uint broadcast = network | ~mask;
            List<IPAddress> hosts = new List<IPAddress>();
            if (broadcast <= network + 1) { scanNote = "No usable local host range available."; return hosts; }
            for (uint cur = network + 1; cur < broadcast; cur++) hosts.Add(UInt32ToAddress(cur));
            scanNote = "Scanning " + UInt32ToAddress(network) + "/" + prefix + ". Only local range.";
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
}
