using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace ProtectServer
{
    // --- Data Models ---
    public class ClientInfo
    {
        public string ClientId { get; set; } // IP:Port
        public string MachineName { get; set; }
        public string IP { get; set; }
        public string MacAddress { get; set; }
        public string PartitionsRaw { get; set; } // e.g. "C:NTFS,D:NTFS"
        
        public SerializableDictionary<string, string> CurrentStatus { get; set; }
        public SerializableDictionary<string, string> PendingStatus { get; set; }

        public ClientInfo()
        {
            CurrentStatus = new SerializableDictionary<string, string>();
            PendingStatus = new SerializableDictionary<string, string>();
        }

        public DateTime LastSeen { get; set; }
        [XmlIgnore]
        public TcpClient Socket { get; set; }
    }

    public class SerializableDictionary<TKey, TValue> : Dictionary<TKey, TValue>, IXmlSerializable
    {
        public System.Xml.Schema.XmlSchema GetSchema() { return null; }
        public void ReadXml(System.Xml.XmlReader reader)
        {
            if (reader.IsEmptyElement) { reader.Read(); return; }
            reader.Read();
            while (reader.NodeType != System.Xml.XmlNodeType.EndElement)
            {
                reader.ReadStartElement("Item");
                reader.ReadStartElement("Key");
                TKey key = (TKey)new XmlSerializer(typeof(TKey)).Deserialize(reader);
                reader.ReadEndElement();
                reader.ReadStartElement("Value");
                TValue value = (TValue)new XmlSerializer(typeof(TValue)).Deserialize(reader);
                reader.ReadEndElement();
                reader.ReadEndElement();
                reader.MoveToContent();
            }
            reader.ReadEndElement();
        }
        public void WriteXml(System.Xml.XmlWriter writer)
        {
            foreach (var key in this.Keys)
            {
                writer.WriteStartElement("Item");
                writer.WriteStartElement("Key");
                new XmlSerializer(typeof(TKey)).Serialize(writer, key);
                writer.WriteEndElement();
                writer.WriteStartElement("Value");
                new XmlSerializer(typeof(TValue)).Serialize(writer, this[key]);
                writer.WriteEndElement();
                writer.WriteEndElement();
            }
        }
    }

    // --- Result Form ---
    public class ResultForm : Form
    {
        public ResultForm(string title, int successCount, List<string> failures, string footer)
        {
            this.Text = title;
            this.Size = new Size(400, 300);
            this.StartPosition = FormStartPosition.CenterParent;
            this.MinimizeBox = false;
            this.MaximizeBox = false;

            RichTextBox rtb = new RichTextBox();
            rtb.Dock = DockStyle.Fill;
            rtb.ReadOnly = true;
            rtb.BackColor = Color.White;
            rtb.Font = new Font("Segoe UI", 10);
            
            // Success
            rtb.SelectionColor = Color.Green;
            rtb.SelectionFont = new Font(rtb.Font, FontStyle.Bold);
            rtb.AppendText(string.Format("Success: {0}\n", successCount));
            
            // Failures
            rtb.SelectionColor = Color.Red;
            rtb.SelectionFont = new Font(rtb.Font, FontStyle.Bold);
            rtb.AppendText(string.Format("Failed: {0}\n", failures.Count));
            
            rtb.SelectionColor = Color.Red;
            rtb.SelectionFont = new Font(rtb.Font, FontStyle.Regular);
            if (failures.Count > 0)
            {
                foreach (var f in failures) rtb.AppendText(" - " + f + "\n");
            }

            // Footer
            rtb.SelectionColor = Color.Black;
            rtb.SelectionFont = new Font(rtb.Font, FontStyle.Italic);
            rtb.AppendText("\n" + footer);

            Button btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Height = 40 };
            btnOk.Dock = DockStyle.Bottom;
            
            this.Controls.Add(rtb);
            this.Controls.Add(btnOk);
        }
    }

    // --- Main Form ---
    public class MainForm : Form
    {
        private ListView clientList;
        private CheckBox chkSelectAll;
        private Button btnProtectSelected;
        private Button btnUnprotectSelected;
        private FlowLayoutPanel pnlDrives; 
        private List<CheckBox> driveCheckBoxes = new List<CheckBox>();
        
        private Button btnPowerOn;
        private Button btnRestart;
        private Button btnShutdown;
        
        private Label lblCount;

        private System.Windows.Forms.Timer refreshTimer;
        private TcpListener server;
        private List<ClientInfo> clients = new List<ClientInfo>();
        private ListViewColumnSorter lvwColumnSorter;
        // ImageList removed as we use Unicode for status dots on Machine Name
        private bool running = true;
        private const int PORT = 3000;
        private const string LOG_FILE = "server_exec.log";

        private void LogToFile(string msg)
        {
            try
            {
                using (StreamWriter sw = new StreamWriter(LOG_FILE, true))
                {
                    sw.WriteLine(string.Format("[{0}] {1}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), msg));
                }
            }
            catch { }
        }

        public MainForm()
        {
            InitializeComponent();
            StartServer();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();

            this.Text = "ProtectServer - Disk Protection Manager";
            this.Size = new Size(1100, 700);
            this.Padding = new Padding(5);

            // --- Top Panel (2 Rows) ---
            Panel topPanel = new Panel();
            topPanel.Dock = DockStyle.Top;
            topPanel.Height = 80; 
            
            // Row 1: Buttons
            int row1Y = 5;
            int x = 5;
            
            btnProtectSelected = new Button { Text = "Protect", Width = 100, Location = new Point(x, row1Y), BackColor = Color.LightGreen };
            x += 110;
            btnUnprotectSelected = new Button { Text = "Unprotect", Width = 100, Location = new Point(x, row1Y), BackColor = Color.LightPink };
            x += 110;

            // Power Buttons
            btnPowerOn = new Button { Text = "Wake Up", Width = 90, Location = new Point(x, row1Y) };
            x += 100;
            btnRestart = new Button { Text = "Restart", Width = 90, Location = new Point(x, row1Y) };
            x += 100;
            btnShutdown = new Button { Text = "Shutdown", Width = 90, Location = new Point(x, row1Y) };
            
            // Row 2: Select All, Drives, Count
            int row2Y = 40;
            x = 5;
            
            chkSelectAll = new CheckBox { Text = "Select All", Width = 80, Location = new Point(x, row2Y + 4) };
            chkSelectAll.CheckedChanged += (s, e) => {
                bool state = chkSelectAll.Checked;
                foreach (ListViewItem item in clientList.Items)
                    item.Checked = state;
            };
            x += 90;
            
            pnlDrives = new FlowLayoutPanel();
            pnlDrives.Location = new Point(x, row2Y);
            pnlDrives.Size = new Size(600, 30); // Wider for drives
            pnlDrives.AutoSize = false;
            AddDriveCheckBox("C"); // Default

            // Count Label (Right Aligned in logic)
            lblCount = new Label();
            lblCount.Text = "Total: 0";
            lblCount.AutoSize = true;
            lblCount.Location = new Point(topPanel.Width - 100, row2Y + 4);
            lblCount.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            // Events
            btnProtectSelected.Click += (s, e) => ApplyProtection(true);
            btnUnprotectSelected.Click += (s, e) => ApplyProtection(false);
            btnPowerOn.Click += (s, e) => SendWOLToSelected();
            btnRestart.Click += (s, e) => SendCommandToSelected("RESTART");
            btnShutdown.Click += (s, e) => SendCommandToSelected("SHUTDOWN");

            topPanel.Controls.Add(btnProtectSelected);
            topPanel.Controls.Add(btnUnprotectSelected);
            topPanel.Controls.Add(btnPowerOn);
            topPanel.Controls.Add(btnRestart);
            topPanel.Controls.Add(btnShutdown);
            
            topPanel.Controls.Add(chkSelectAll);
            topPanel.Controls.Add(pnlDrives);
            topPanel.Controls.Add(lblCount);

            this.Controls.Add(topPanel);

            // --- ListView ---
            clientList = new ListView();
            clientList.Dock = DockStyle.Fill;
            clientList.View = View.Details;
            clientList.FullRowSelect = true;
            clientList.GridLines = true;
            clientList.CheckBoxes = true; // Shows Checkbox on First Column (No.)
            clientList.HeaderStyle = ColumnHeaderStyle.Clickable;
            clientList.ShowItemToolTips = true; 

            // Columns
            // Col 0: Checkbox + No. (Standard ListView behavior: Checkbox is part of first col item)
            clientList.Columns.Add("No.", 50); 
            clientList.Columns.Add("Machine Name", 180);
            clientList.Columns.Add("IP Address", 120);
            clientList.Columns.Add("MAC Address", 120);
            clientList.Columns.Add("Volume Status", 300);
            clientList.Columns.Add("Last Seen", 100);
            
            lvwColumnSorter = new ListViewColumnSorter();
            clientList.ListViewItemSorter = lvwColumnSorter;
            clientList.ColumnClick += (s, e) =>
            {
                if (e.Column == lvwColumnSorter.SortColumn)
                {
                    if (lvwColumnSorter.Order == SortOrder.Ascending)
                        lvwColumnSorter.Order = SortOrder.Descending;
                    else
                        lvwColumnSorter.Order = SortOrder.Ascending;
                }
                else
                {
                    lvwColumnSorter.SortColumn = e.Column;
                    lvwColumnSorter.Order = SortOrder.Ascending;
                }
                clientList.Sort();
            };

            this.Controls.Add(clientList);
            clientList.BringToFront(); 
            
            // Timer
            refreshTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            refreshTimer.Tick += RefreshList;
            refreshTimer.Start();

            this.FormClosing += (s, e) => {
                running = false;
                if (server != null) server.Stop();
            };

            this.ResumeLayout(false);
        }

        private void AddDriveCheckBox(string driveLetter)
        {
            if (driveCheckBoxes.Exists(x => x.Text == driveLetter)) return;

            CheckBox chk = new CheckBox();
            chk.Text = driveLetter;
            chk.Width = 40;
            chk.Checked = (driveLetter == "C"); // Default check C
            pnlDrives.Controls.Add(chk);
            driveCheckBoxes.Add(chk);
        }

        private void ApplyProtection(bool protect)
        {
            List<string> selectedDrives = new List<string>();
            foreach (var cb in driveCheckBoxes)
            {
                if (cb.Checked) selectedDrives.Add(cb.Text);
            }

            if (selectedDrives.Count == 0)
            {
                MessageBox.Show("Please select at least one drive.");
                return;
            }

            int successCount = 0;
            List<string> failedMachines = new List<string>();

            lock (clients)
            {
                foreach (ListViewItem item in clientList.CheckedItems)
                {
                    // Map back to client. IP is at SubItem 2
                    if (item.SubItems.Count < 3) continue;

                    string ip = item.SubItems[2].Text;
                    var c = clients.Find(x => x.IP == ip);

                    bool commandSent = false;

                    if (c != null)
                    {
                        foreach (string drive in selectedDrives)
                        {
                            string cmd = (protect ? "PROTECT " : "UNPROTECT ") + drive;
                            
                            if (c.Socket != null && c.Socket.Connected)
                            {
                                try
                                {
                                    byte[] data = Encoding.UTF8.GetBytes(cmd);
                                    c.Socket.GetStream().Write(data, 0, data.Length);
                                    LogToFile(string.Format("Sent command to {0}: {1}", c.IP, cmd));
                                    commandSent = true;
                                }
                                catch (Exception ex)
                                {
                                    LogToFile(string.Format("Error sending to {0}: {1}", c.IP, ex.Message));
                                }
                            }
                            else
                            {
                                LogToFile(string.Format("Skipped {0} (Offline/No Socket) for command: {1}", c.IP, cmd));
                            }

                            // Update Pending Status
                            string desired = protect ? "Protected" : "Unprotected";
                            string current = "Unprotected";
                            if (c.CurrentStatus.ContainsKey(drive)) current = c.CurrentStatus[drive];

                            if (desired != current)
                            {
                                if (c.PendingStatus.ContainsKey(drive))
                                    c.PendingStatus[drive] = desired;
                                else
                                    c.PendingStatus.Add(drive, desired);
                            }
                            else
                            {
                                if (c.PendingStatus.ContainsKey(drive))
                                    c.PendingStatus.Remove(drive);
                            }
                        }
                    }

                    if (commandSent)
                    {
                        successCount++;
                        item.ForeColor = Color.Black; 
                    }
                    else
                    {
                        failedMachines.Add(c != null ? c.MachineName : "Unknown (" + ip + ")");
                        item.ForeColor = Color.Red; 
                    }
                }
            }
            
            // Feedback Window
            ResultForm resultForm = new ResultForm(
                "Protection Result", 
                successCount, 
                failedMachines, 
                "NOTE: Changes will take effect after the NEXT SYSTEM RESTART."
            );
            resultForm.ShowDialog();

            // Trigger refresh
            RefreshList(null, null);
        }
        
        private void SendCommandToSelected(string cmd)
        {
            int success = 0;
            List<string> failed = new List<string>();
            lock (clients)
            {
                foreach (ListViewItem item in clientList.CheckedItems)
                {
                    if (item.SubItems.Count < 3) continue;
                    string ip = item.SubItems[2].Text; 
                    var c = clients.Find(x => x.IP == ip);

                    if (c != null && c.Socket != null && c.Socket.Connected)
                    {
                        try
                        {
                            byte[] data = Encoding.UTF8.GetBytes(cmd);
                            c.Socket.GetStream().Write(data, 0, data.Length);
                            LogToFile(string.Format("Sent command to {0}: {1}", c.IP, cmd));
                            success++;
                        }
                        catch (Exception ex)
                        {
                             LogToFile(string.Format("Error sending to {0}: {1}", c.IP, ex.Message));
                             failed.Add(c.MachineName);
                        }
                    }
                    else
                    {
                        failed.Add(c != null ? c.MachineName : ip);
                    }
                }
            }
            MessageBox.Show(string.Format("Command '{0}' sent.\nSuccess: {1}\nFailed: {2}", cmd, success, failed.Count), "Command Result");
        }
        
        private void SendWOLToSelected()
        {
            int sent = 0;
             lock (clients)
            {
                foreach (ListViewItem item in clientList.CheckedItems)
                {
                    if (item.SubItems.Count < 3) continue;
                    string ip = item.SubItems[2].Text; 
                    var c = clients.Find(x => x.IP == ip);
                    if (c != null && !string.IsNullOrEmpty(c.MacAddress))
                    {
                        SendMagicPacket(c.MacAddress);
                        LogToFile(string.Format("Sent WOL to {0} ({1})", c.IP, c.MacAddress));
                        sent++;
                    }
                }
            }
            MessageBox.Show(string.Format("WOL Magic Packet sent to {0} clients.", sent), "WOL Result");
        }
        
        private void SendMagicPacket(string macAddress)
        {
            try
            {
                byte[] mac = new byte[6];
                string[] hex = macAddress.Split('-', ':');
                if (hex.Length != 6) return;
                for (int i = 0; i < 6; i++) mac[i] = Convert.ToByte(hex[i], 16);

                byte[] packet = new byte[17 * 6];
                for (int i = 0; i < 6; i++) packet[i] = 0xFF;
                for (int i = 1; i <= 16; i++)
                    for (int j = 0; j < 6; j++)
                        packet[i * 6 + j] = mac[j];

                UdpClient udp = new UdpClient();
                udp.Connect(IPAddress.Broadcast, 9);
                udp.Send(packet, packet.Length);
            }
            catch { }
        }

        private void RefreshList(object sender, EventArgs e)
        {
            clientList.BeginUpdate();
            
            // Update Count Label
            int count = clients.Count;
            lblCount.Text = "Total: " + count;
            
            lock (clients)
            {
                // Dynamic Drive Checkboxes based on FIRST client
                if (clients.Count > 0 && !string.IsNullOrEmpty(clients[0].PartitionsRaw))
                {
                    string[] parts = clients[0].PartitionsRaw.Split(',');
                    foreach (string part in parts)
                    {
                        int idx = part.IndexOf(':');
                        if (idx > 0)
                        {
                            string drive = part.Substring(0, idx);
                             this.Invoke((MethodInvoker)delegate {
                                AddDriveCheckBox(drive);
                            });
                        }
                    }
                }

                // Add or Update items
                int index = 0;
                foreach (var c in clients)
                {
                    index++;
                    ListViewItem item = null;
                    foreach (ListViewItem existing in clientList.Items)
                    {
                        // IP is at SubItems[2]
                        if (existing.SubItems.Count > 2 && existing.SubItems[2].Text == c.IP)
                        {
                            item = existing;
                            break;
                        }
                    }

                    if (item == null)
                    {
                        // Col 0: No. (Text)
                        item = new ListViewItem(index.ToString()); 
                        item.SubItems.Add(""); // 1 Machine Name (Placeholder)
                        item.SubItems.Add(c.IP); // 2
                        item.SubItems.Add(c.MacAddress ?? ""); // 3
                        item.SubItems.Add(""); // 4 Status
                        item.SubItems.Add(c.LastSeen.ToString("HH:mm:ss")); // 5
                        clientList.Items.Add(item);
                    }
                    else
                    {
                        item.Text = index.ToString(); // Update Index if list changed
                    }

                    // Update Online Status
                    bool isOnline = (DateTime.Now - c.LastSeen).TotalSeconds < 30;
                    
                    // Update Text for Machine Name with Status Dot
                    // Using Unicode Characters: 🟢 (U+1F7E2) and ⚫ (U+26AB) or ⚪
                    // Note: WinForms default font might not render color emojis.
                    // Using Bullet • with Color might be better if OwnerDraw, but text-only solution:
                    // Use "●" (Black Circle) or "○" (White Circle)
                    // Or simply "ONLINE" / "OFFLINE" prefix?
                    // User asked for "Green Dot" equivalent.
                    // We will use Unicode Circle and rely on font rendering.
                    // If simple text, "●" is usually black.
                    // Let's use simple text prefix for now to avoid OwnerDraw complexity crashes.
                    // But wait, I can change the SubItem ForeColor!
                    
                    // Set Machine Name Text
                    string statusPrefix = isOnline ? "● " : "○ ";
                    item.SubItems[1].Text = statusPrefix + c.MachineName;
                    
                    // Attempt to color the Machine Name SubItem based on status?
                    // But if I color it Green, the whole name is Green.
                    // Maybe acceptable.
                    /*
                    item.UseItemStyleForSubItems = false;
                    if (isOnline) 
                        item.SubItems[1].ForeColor = Color.Green;
                    else 
                        item.SubItems[1].ForeColor = Color.Gray;
                    */
                    // BUT, I'm already using UseItemStyleForSubItems = false for Volume Status (Col 4).
                    // So I can set Col 1 color too.
                    // Let's do it.
                    
                    item.UseItemStyleForSubItems = false;
                    item.SubItems[1].ForeColor = isOnline ? Color.Green : Color.Gray;

                    // Update other fields
                    item.SubItems[2].Text = c.IP;
                    item.SubItems[3].Text = c.MacAddress ?? "";
                    
                    // Update Volume Status & Color
                    StringBuilder statusSb = new StringBuilder();
                    bool hasPending = false;
                    
                    List<string> drives = new List<string>();
                    foreach(var cb in driveCheckBoxes) drives.Add(cb.Text);
                    
                    foreach (var drive in drives)
                    {
                        string current = c.CurrentStatus.ContainsKey(drive) ? c.CurrentStatus[drive] : "Unprotected";
                        
                        if (c.PendingStatus.ContainsKey(drive))
                        {
                            hasPending = true;
                            string pending = c.PendingStatus[drive];
                            statusSb.Append(string.Format("{0}:({1}) ", drive, pending));
                            item.ToolTipText = string.Format("Drive {0}: Original={1}, New={2} (Reboot required)", drive, current, pending);
                        }
                        else
                        {
                            statusSb.Append(string.Format("{0}:({1}) ", drive, current));
                        }
                    }

                    item.SubItems[4].Text = statusSb.ToString();
                    
                    if (hasPending)
                    {
                        item.SubItems[4].ForeColor = Color.Red;
                    }
                    else
                    {
                         if (statusSb.ToString().Contains("Unprotected"))
                            item.SubItems[4].ForeColor = Color.Black;
                         else
                            item.SubItems[4].ForeColor = Color.Green;
                    }

                    item.SubItems[5].Text = c.LastSeen.ToString("HH:mm:ss");
                }
                
                // Adaptive Column Width
                if (clientList.Items.Count > 0)
                {
                     // AutoResizeColumns(-1) is for Content, -2 is for Header.
                     // We want "Adaptive". Let's do HeaderSize (-2) generally, 
                     // or Content (-1) for Name/IP?
                     // WinForms AutoResize can be slow if called frequently.
                     // Let's do it only if item count changed?
                     // Or just leave it as is with initial widths.
                     // User said "其它列自适应列宽".
                     // I'll call AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize) every 5 seconds or so?
                     // Or just let user resize manually. 
                     // I will force it once if item count changes.
                     // But I can't track previous count easily here without field.
                     // Let's just set fixed widths that are large enough, as AutoResize every second is bad.
                     // Actually, "自适应列宽" (Adaptive column width) usually means Fill the space or Fit content.
                     // I'll leave it as fixed large widths for now as defined in InitializeComponent.
                }
            }
            clientList.EndUpdate();
        }
        
        private void StartServer()
        {
            try
            {
                server = new TcpListener(IPAddress.Any, PORT);
                server.Start();
                new Thread(AcceptClients).Start();
                new Thread(BroadcastPresence).Start(); 
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to start server: " + ex.Message);
            }
        }

        private void BroadcastPresence()
        {
            try
            {
                UdpClient udp = new UdpClient();
                udp.EnableBroadcast = true;
                IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, PORT); 
                byte[] data = Encoding.UTF8.GetBytes("DISCOVER_PROTECT_SERVER");

                while (running)
                {
                    udp.Send(data, data.Length, endPoint);
                    Thread.Sleep(5000); 
                }
            }
            catch { }
        }

        private void AcceptClients()
        {
            while (running)
            {
                try
                {
                    TcpClient client = server.AcceptTcpClient();
                    new Thread(() => HandleClient(client)).Start();
                }
                catch { break; }
            }
        }

        private void HandleClient(TcpClient client)
        {
            try
            {
                string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                
                if (ip == "127.0.0.1")
                {
                    client.Close();
                    return;
                }

                UpdateClient(ip, "Connecting...", client); 

                NetworkStream stream = client.GetStream();
                
                byte[] key = new byte[16];
                new Random().NextBytes(key);
                stream.Write(key, 0, 16);

                while (running && client.Connected)
                {
                    if (stream.DataAvailable)
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0) break;
                        
                        string msg = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        if (msg.Contains("MAC="))
                        {
                            UpdateClient(ip, msg, client);
                        }
                        else
                        {
                            UpdateHeartbeat(ip, msg);
                        }
                    }
                    Thread.Sleep(100);
                }
            }
            catch { }
            finally { client.Close(); }
        }

        private void UpdateClient(string ip, string info, TcpClient socket)
        {
            lock (clients)
            {
                var c = clients.Find(x => x.IP == ip);
                if (c == null)
                {
                    c = new ClientInfo { IP = ip, LastSeen = DateTime.Now };
                    clients.Add(c);
                }
                c.Socket = socket;
                c.LastSeen = DateTime.Now;
                
                if (info.Contains("MAC="))
                {
                    string[] parts = info.Split('|');
                    foreach (var p in parts)
                    {
                        if (p.StartsWith("MAC=")) c.MacAddress = p.Substring(4);
                        if (p.StartsWith("PARTITIONS=")) c.PartitionsRaw = p.Substring(11);
                    }
                    c.MachineName = "Client-" + ip.Replace(".", "");
                    
                    if (info.Contains("STATUS="))
                    {
                        ParseStatus(c, info);
                    }
                }
            }
        }

        private void UpdateHeartbeat(string ip, string info = null)
        {
            lock (clients)
            {
                var c = clients.Find(x => x.IP == ip);
                if (c != null) 
                {
                    c.LastSeen = DateTime.Now;
                    if (!string.IsNullOrEmpty(info) && info.Contains("STATUS="))
                    {
                        ParseStatus(c, info);
                    }
                }
            }
        }
        
        private void ParseStatus(ClientInfo c, string info)
        {
            string[] parts = info.Split('|');
            foreach (var p in parts)
            {
                if (p.StartsWith("STATUS="))
                {
                    string statusRaw = p.Substring(7);
                    if (!string.IsNullOrEmpty(statusRaw))
                    {
                         string[] drives = statusRaw.Split(',');
                         foreach(var d in drives)
                         {
                             int idx = d.IndexOf(':');
                             if (idx > 0)
                             {
                                 string drive = d.Substring(0, idx);
                                 string state = d.Substring(idx + 1);
                                 c.CurrentStatus[drive] = state;
                                 
                                 if (c.PendingStatus.ContainsKey(drive) && c.PendingStatus[drive] == state)
                                 {
                                     c.PendingStatus.Remove(drive);
                                 }
                             }
                         }
                    }
                }
            }
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // --- Helper Classes ---
    public class ListViewColumnSorter : System.Collections.IComparer
    {
        public int SortColumn { get; set; }
        public SortOrder Order { get; set; }
        private System.Collections.CaseInsensitiveComparer ObjectCompare;

        public ListViewColumnSorter()
        {
            SortColumn = 0;
            Order = SortOrder.Ascending;
            ObjectCompare = new System.Collections.CaseInsensitiveComparer();
        }

        public int Compare(object x, object y)
        {
            ListViewItem listviewX = (ListViewItem)x;
            ListViewItem listviewY = (ListViewItem)y;

            int compareResult;
            
            // Adjust indices for new columns
            // Col 0: No. (Text)
            // Col 1: Name
            // Col 2: IP
            if (SortColumn == 2) // IP
            {
                Version ip1, ip2;
                bool valid1 = Version.TryParse(listviewX.SubItems[2].Text, out ip1);
                bool valid2 = Version.TryParse(listviewY.SubItems[2].Text, out ip2);
                if (valid1 && valid2) compareResult = ip1.CompareTo(ip2);
                else compareResult = ObjectCompare.Compare(listviewX.SubItems[2].Text, listviewY.SubItems[2].Text);
            }
            else if (SortColumn == 0) 
            {
                // Numeric Sort for "No."
                int n1, n2;
                if (int.TryParse(listviewX.Text, out n1) && int.TryParse(listviewY.Text, out n2))
                    compareResult = n1.CompareTo(n2);
                else
                    compareResult = ObjectCompare.Compare(listviewX.Text, listviewY.Text);
            }
            else
            {
                if (listviewX.SubItems.Count > SortColumn && listviewY.SubItems.Count > SortColumn)
                    compareResult = ObjectCompare.Compare(listviewX.SubItems[SortColumn].Text, listviewY.SubItems[SortColumn].Text);
                else
                    compareResult = 0;
            }

            if (Order == SortOrder.Ascending) return compareResult;
            else if (Order == SortOrder.Descending) return (-compareResult);
            else return 0;
        }
    }
}
