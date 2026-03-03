# NetProtect User Manual / 用户手册

## 1. Overview / 简介
**NetProtect** is a comprehensive disk protection and remote management system consisting of a Server application (`ProtectServer.exe`) and a Client service (`protect.exe`). It allows administrators to centrally manage disk protection states (Protect/Unprotect), monitor client status, and perform power management operations (Wake-on-LAN, Restart, Shutdown) across a network.

**NetProtect** 是一个综合性的磁盘保护和远程管理系统，由服务端程序 (`ProtectServer.exe`) 和客户端服务 (`protect.exe`) 组成。它允许管理员集中管理磁盘保护状态（保护/不保护），监控客户端状态，并在网络中执行电源管理操作（局域网唤醒、重启、关机）。

---

## 2. Server Side / 服务端 (ProtectServer.exe)

The server application provides a graphical interface to manage all connected clients. It runs entirely in memory and does not store client information in a database, ensuring a fresh state upon every launch.

服务端程序提供了一个图形界面来管理所有连接的客户端。它完全在内存中运行，不将客户端信息保存到数据库中，确保每次启动都是全新的状态。

### 2.1 Interface Layout / 界面布局

*   **Top Row (Drive Selection) / 第一行（磁盘选择）**:
    *   Displays checkboxes for drive letters (e.g., `C`, `D`) detected from the first connected client.
    *   显示从第一个连接的客户端检测到的盘符钩选框（例如 `C`, `D`）。
    *   **Usage / 用法**: Check the drives you want to apply actions to. / 钩选您希望执行操作的磁盘。

*   **Control Row / 控制行**:
    *   **Select All / 全选**: Selects all clients in the list. / 选中列表中的所有客户端。
    *   **Protect / 保护 (Green Button)**: Enables protection for selected drives on selected clients. / 对选中客户端的选中磁盘启用保护。
    *   **Unprotect / 不保护 (Pink Button)**: Disables protection for selected drives on selected clients. / 对选中客户端的选中磁盘禁用保护。
    *   **Wake Up / 唤醒**: Sends a Wake-on-LAN (WOL) magic packet to selected clients. / 向选中客户端发送局域网唤醒 (WOL) 魔术包。
    *   **Restart / 重启**: Sends a restart command to selected clients. / 向选中客户端发送重启指令。
    *   **Shutdown / 关机**: Sends a shutdown command to selected clients. / 向选中客户端发送关机指令。

### 2.2 Client List Columns / 客户端列表列

1.  **Checkbox / 选框**: Select clients for batch operations. / 选择要进行批量操作的客户端。
2.  **Machine Name / 机器名**: The hostname of the client. / 客户端的主机名。
3.  **IP Address / IP 地址**: The local IP address of the client. / 客户端的本地 IP 地址。
4.  **MAC Address / MAC 地址**: Physical network address (used for WOL). / 物理网络地址（用于 WOL）。
5.  **Volume Status / 卷状态**: Current protection status of drives. / 磁盘当前的保护状态。
    *   **Green Text / 绿色字**: Protected / 已保护
    *   **Black Text / 黑色字**: Unprotected / 未保护
    *   **Red Text / 红色字**: Pending Change (Reboot required) / 等待变更（需重启）
    *   *Hover over red text to see the pending change details. / 鼠标悬停在红色文字上可查看待变更详情。*
6.  **Last Seen / 最后在线**: Timestamp of the last heartbeat. / 最后一次心跳的时间戳。

### 2.3 Status Indicators / 状态指示

*   **Online / 在线**: Green dot next to machine name. / 机器名旁显示绿色圆点。
*   **Offline / 离线**: Gray dot next to machine name. / 机器名旁显示灰色圆点。

---

## 3. Client Side / 客户端 (Protect.exe)

The client runs as a Windows Service (`ProtectSvc`), communicating with the server and controlling the underlying disk filter driver.

客户端作为 Windows 服务 (`ProtectSvc`) 运行，负责与服务器通信并控制底层的磁盘过滤驱动。

### 3.1 Installation / 安装

Run the provided installation script as Administrator:
请以管理员身份运行提供的安装脚本：

```cmd
install.bat
```

This will register `protect.exe` as a system service.
这将把 `protect.exe` 注册为系统服务。

### 3.2 Configuration / 配置

The client configuration is stored in **Sector 62** of PhysicalDrive0 for persistence and tamper resistance.
客户端配置存储在 PhysicalDrive0 的 **第 62 扇区**，以确保持久性和防篡改。

**Command Line Usage / 命令行用法**:

*   **Set Server IP / 设置服务器 IP**:
    ```cmd
    protect.exe /set <ServerIP>:<Port>
    Example: protect.exe /set 192.168.1.100:3000
    ```
    *Note: Default port is 3000 if omitted. / 注意：如果省略端口，默认为 3000。*

*   **Test Connection / 测试连接**:
    ```cmd
    protect.exe /conn
    ```
    Tests connectivity to the configured server. / 测试与配置的服务器的连接性。

*   **Clear Configuration / 清除配置**:
    ```cmd
    protect.exe /clear
    ```
    Wipes the configuration from Sector 62. / 清除第 62 扇区的配置信息。

### 3.3 Driver Interaction / 驱动交互

*   The client service automatically communicates with the kernel driver to enforce protection policies.
*   客户端服务自动与内核驱动通信以执行保护策略。
*   **Reboot Required**: Changing protection status (Protect/Unprotect) requires a system restart to take full effect.
*   **需要重启**：更改保护状态（保护/不保护）需要重启系统才能完全生效。

---

## 4. Operation Workflow / 操作流程

1.  **Start Server**: Run `ProtectServer.exe` on the management machine.
    **启动服务端**：在管理机上运行 `ProtectServer.exe`。
2.  **Configure Clients**: On each client machine, run `protect.exe /set <ServerIP>` once.
    **配置客户端**：在每台客户机上，运行一次 `protect.exe /set <ServerIP>`。
3.  **Start Client Service**: Ensure the `ProtectSvc` service is running (or reboot client).
    **启动客户端服务**：确保 `ProtectSvc` 服务正在运行（或重启客户机）。
4.  **Manage**:
    **管理**：
    *   Clients will automatically appear in the Server list. / 客户端会自动出现在服务端列表中。
    *   Select clients and drives. / 选择客户端和磁盘。
    *   Click "Protect" or "Unprotect". / 点击“保护”或“不保护”。
    *   Review the result popup. / 查看结果弹窗。
    *   Reboot clients to apply changes (or use the "Restart" button). / 重启客户端以应用更改（或使用“重启”按钮）。

## 5. Troubleshooting / 故障排除

*   **Client not showing up / 客户端未显示**:
    *   Check firewall settings on port 3000. / 检查端口 3000 的防火墙设置。
    *   Run `protect.exe /conn` on client to verify connectivity. / 在客户端运行 `protect.exe /conn` 验证连接。
*   **Protection status mismatch / 保护状态不匹配**:
    *   Status changes require a reboot. Check for red text in the "Volume Status" column. / 状态更改需要重启。检查“卷状态”列中是否有红色文字。
*   **WOL not working / WOL 不工作**:
    *   Ensure "Wake on LAN" is enabled in the client BIOS/UEFI and network adapter settings. / 确保客户端 BIOS/UEFI 和网卡设置中已启用“局域网唤醒”。
