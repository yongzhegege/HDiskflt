# Diskflt 驱动系统使用说明书

版本: 1.0

## 1. 产品简介

**Diskflt** 是一款基于 Windows 内核的磁盘过滤驱动程序（Disk Filter Driver），专为系统保护和数据还原场景设计。该驱动工作在 Windows 存储堆栈的磁盘类驱动（Disk Class Driver）之上，能够拦截对物理磁盘的读写请求，实现"影子模式"（Shadow Mode）保护。

开启保护后，用户对受保护磁盘的所有写入操作都将被重定向到内存或临时存储区域，而不会修改物理硬盘上的真实数据。当计算机重启后，所有临时数据将被丢弃，系统瞬间还原到保护前的状态，从而有效防止病毒破坏、误操作或恶意软件篡改系统。

## 2. 功能特点

- **实时还原保护**：支持对选定的磁盘分区进行扇区级写保护，重启即还原。
- **多分区支持**：可灵活配置需要保护的分区（如仅保护 C 盘系统盘，或同时保护 D 盘数据盘）。
- **底层驱动拦截**：基于 WDM/WDF 框架的 Upper Filter 驱动，抗干扰能力强，难以被普通应用层恶意软件绕过。
- **配置持久化**：保护配置信息存储于物理磁盘的隐藏扇区（Sector 62），防止文件系统损坏导致配置丢失。
- **透明运行**：对上层文件系统和应用程序完全透明，不影响系统正常使用习惯。

## 3. 运行环境与支持

### 3.1 硬件要求

- CPU：x86 或 x64 架构处理器
- 内存：建议 4GB 及以上（由于写重定向需要占用一定内存资源）
- 硬盘：支持 HDD、SSD、NVMe 等各类标准磁盘设备

### 3.2 操作系统支持（仅支持 UEFI）

- Windows 10 (x86/x64)
- Windows 11 (x64)

## 4. 安装与卸载

### 4.1 安装步骤

1. 确保已获取完整的安装包（包含 `diskflt.sys`, `diskflt.inf`, `diskflt.cat`, `install.bat` 及 `Protection.exe`）。
2. **以管理员身份运行** `install.bat` 脚本。
3. 脚本会自动执行以下操作：
   - 将驱动文件复制到 `System32\drivers` 目录。
   - 创建 `diskflt` 系统服务（启动类型：Boot Start）。
   - 在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}` 的 `UpperFilters` 项中添加 `diskflt`。
4. 安装完成后，**必须重启计算机**以使驱动加载生效。

### 4.2 卸载步骤

1. 运行卸载脚本（或手动从注册表 `UpperFilters` 中移除 `diskflt` 字符串）。
2. 删除 `diskflt` 服务：`sc delete diskflt`。
3. 重启计算机。
4. 删除 `System32\drivers\diskflt.sys` 文件。

## 5. 原理与流程

### 5.1 驱动架构图

```
[应用程序 (Word, Explorer等)]
⬇️ ⬆️
[文件系统驱动 (NTFS/FAT)]
⬇️ ⬆️
[卷管理驱动 (Volmgr)]
⬇️ ⬆️
[Diskflt 过滤驱动 (本产品)] <--- 拦截/重定向
⬇️ ⬆️
[磁盘类驱动 (Disk.sys)]
⬇️ ⬆️
[物理硬盘]
```

### 5.2 读写处理流程

**写入流程 (Write Request):**

1. 上层发送 `IRP_MJ_WRITE` 请求。
2. Diskflt 拦截该请求，判断目标扇区是否属于受保护卷。
3. **若是受保护卷**：
   - 在内存/临时区中分配空间。
   - 将数据写入临时区。
   - 更新重定向位图（Redirect Bitmap），标记该扇区已被修改。
   - 向系统返回"写入成功"状态（欺骗上层），实际未修改物理硬盘。
4. **若非受保护卷**：
   - 直接将请求下发给底层驱动，写入物理硬盘。

**读取流程 (Read Request):**

1. 上层发送 `IRP_MJ_READ` 请求。
2. Diskflt 拦截请求，查询重定向位图。
3. **若扇区已被修改**（存在于临时区）：
   - 从临时区读取最新数据返回给上层。
4. **若扇区未被修改**：
   - 从物理硬盘读取原始数据返回。

## 6. Protection 软件操作说明

`Protection.exe` 是用户配置保护策略的管理工具（命令行版本）。

### 6.1 运行与权限

- 运行软件需要**管理员权限**（必须以管理员身份运行）。
- 软件无图形界面，通过命令行参数进行交互。
- 可以通过 `Protection.exe /q` 查看当前系统中所有分区的保护状态。

### 6.2 开启/关闭保护

通过命令行工具控制保护状态：

- **开启保护**：`Protection.exe <盘符> /r`
  例如：`Protection.exe C /r`（开启 C 盘保护）
- **关闭保护**：`Protection.exe <盘符> /w`
  例如：`Protection.exe C /w`（关闭 C 盘保护）

**注意**：配置修改后，必须**重启计算机**才能生效。

### 6.3 参数说明

| 参数项 | 说明 |
|--------|------|
| Magic Char | `[dbgger][dbgger]` - 用于校验配置扇区是否有效的特征码。 |
| VolumeInfo | 32字节数组，对应 A-Z 盘符。1 表示保护，0 表示不保护。 |

### 6.4 命令行参数说明

`Protection.exe` 支持命令行操作，方便管理员进行批量部署或脚本控制。

| 命令格式 | 功能描述 | 示例 |
|---------|---------|------|
| `Protection.exe <盘符> /r` | 开启指定分区的保护（还原模式）。 | `Protection.exe C /r` |
| `Protection.exe <盘符> /w` | 关闭指定分区的保护（写入模式）。 | `Protection.exe D /w` |
| `Protection.exe /q` | 查询当前所有分区的保护状态。 | `Protection.exe /q` |
| `Protection.exe /c` | 清除所有保护配置（清空扇区 62）。 | `Protection.exe /c` |
| `Protection.exe /u` | 完全卸载驱动及服务，并清除配置。 | `Protection.exe /u` |
| `Protection.exe /forceupdate <文件>` | 强制更新驱动文件（绕过保护）。 | `Protection.exe /forceupdate diskflt.sys` |

## 7. 常见问题 (FAQ)

### Q1: Protection 软件提示"无法保存配置"？

**原因**：可能是安全软件拦截了对物理磁盘扇区的直接写入操作，或者没有以管理员身份运行。
**解决**：右键选择"以管理员身份运行"。暂时关闭杀毒软件，或在驱动已加载的情况下，软件会尝试通过驱动 IOCTL 接口写入配置（这通常不会被拦截）。

### Q2: 保护模式下，为什么复制进去的文件重启就没了？

**回答**：这是正常的。保护模式下所有写入都是临时的，重启后系统会丢弃所有更改，还原到保护前的状态。如需永久保存文件，请先关闭保护，或保存到未保护的分区（如 D 盘）。

---

## Diskflt Driver System User Manual

Version: 1.0

## 1. Product Introduction

**Diskflt** is a Windows kernel-based disk filter driver designed for system protection and data recovery scenarios. The driver operates above the Windows storage stack's Disk Class Driver, intercepting read/write requests to physical disks and implementing "Shadow Mode" protection.

When protection is enabled, all write operations to protected disks are redirected to memory or temporary storage areas without modifying the real data on the physical hard drive. When the computer restarts, all temporary data is discarded, and the system instantly reverts to its pre-protection state, effectively preventing virus damage, accidental operations, or malicious software tampering.

## 2. Features

- **Real-time Restore Protection**: Supports sector-level write protection for selected disk partitions, with instant restore on reboot.
- **Multi-partition Support**: Flexible configuration of protected partitions (e.g., protect only C: system drive or both C: and D: data drives).
- **Low-level Driver Interception**: Upper Filter driver based on WDM/WDF framework with strong anti-interference capability, difficult to bypass by ordinary application-layer malware.
- **Configuration Persistence**: Protection configuration is stored in hidden disk sectors (Sector 62), preventing configuration loss due to file system corruption.
- **Transparent Operation**: Completely transparent to upper-level file systems and applications, without affecting normal system usage habits.

## 3. System Requirements

### 3.1 Hardware Requirements

- CPU: x86 or x64 architecture processor
- Memory: 4GB or higher recommended (write redirection requires certain memory resources)
- Storage: Supports HDD, SSD, NVMe, and other standard disk devices

### 3.2 Operating System Support (UEFI Only)

- Windows 10 (x86/x64)
- Windows 11 (x64)

## 4. Installation and Uninstallation

### 4.1 Installation Steps

1. Ensure you have the complete installation package (including `diskflt.sys`, `diskflt.inf`, `diskflt.cat`, `install.bat`, and `Protection.exe`).
2. **Run as Administrator** the `install.bat` script.
3. The script will automatically perform the following operations:
   - Copy driver files to `System32\drivers` directory.
   - Create `diskflt` system service (Start Type: Boot Start).
   - Add `diskflt` to the `UpperFilters` registry entry at `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}`.
4. After installation, **you must restart the computer** for the driver to take effect.

### 4.2 Uninstallation Steps

1. Run the uninstall script (or manually remove `diskflt` from the `UpperFilters` registry entry).
2. Delete the `diskflt` service: `sc delete diskflt`.
3. Restart the computer.
4. Delete the `System32\drivers\diskflt.sys` file.

## 5. Principles and Workflow

### 5.1 Driver Architecture Diagram

```
[Applications (Word, Explorer, etc.)]
⬇️ ⬆️
[File System Driver (NTFS/FAT)]
⬇️ ⬆️
[Volume Manager Driver (Volmgr)]
⬇️ ⬆️
[Diskflt Filter Driver (This Product)] <--- Intercept/Redirect
⬇️ ⬆️
[Disk Class Driver (Disk.sys)]
⬇️ ⬆️
[Physical Hard Drive]
```

### 5.2 Read/Write Processing Flow

**Write Process (Write Request):**

1. Upper layer sends `IRP_MJ_WRITE` request.
2. Diskflt intercepts the request and determines if the target sector belongs to a protected volume.
3. **If protected volume**:
   - Allocates space in memory/temporary area.
   - Writes data to temporary area.
   - Updates Redirect Bitmap, marking the sector as modified.
   - Returns "write successful" status to the system (deceiving upper layers), without actually modifying the physical hard drive.
4. **If not protected volume**:
   - Directly passes the request to the lower-level driver to write to physical hard drive.

**Read Process (Read Request):**

1. Upper layer sends `IRP_MJ_READ` request.
2. Diskflt intercepts the request and queries the Redirect Bitmap.
3. **If sector has been modified** (exists in temporary area):
   - Reads latest data from temporary area and returns to upper layer.
4. **If sector has not been modified**:
   - Reads original data from physical hard drive and returns.

## 6. Protection Software Operation Guide

`Protection.exe` is the command-line management tool for configuring protection policies.

### 6.1 Running and Permissions

- The software requires **Administrator privileges** (must run as administrator).
- The software has no GUI and operates through command-line parameters.
- Use `Protection.exe /q` to view the protection status of all partitions.

### 6.2 Enable/Disable Protection

Control protection status through command-line tool:

- **Enable Protection**: `Protection.exe <drive> /r`
  Example: `Protection.exe C /r` (Enable C: drive protection)
- **Disable Protection**: `Protection.exe <drive> /w`
  Example: `Protection.exe C /w` (Disable C: drive protection)

**Note**: After configuration changes, you must **restart the computer** for changes to take effect.

### 6.3 Parameter Description

| Parameter | Description |
|-----------|-------------|
| Magic Char | `[dbgger][dbgger]` - Signature code used to verify if the configuration sector is valid. |
| VolumeInfo | 32-byte array corresponding to A-Z drive letters. 1 means protected, 0 means not protected. |

### 6.4 Command Line Parameters

`Protection.exe` supports command-line operations for administrators to perform batch deployments or script control.

| Command Format | Function Description | Example |
|----------------|---------------------|---------|
| `Protection.exe <drive> /r` | Enable protection for specified partition (restore mode). | `Protection.exe C /r` |
| `Protection.exe <drive> /w` | Disable protection for specified partition (write mode). | `Protection.exe D /w` |
| `Protection.exe /q` | Query protection status of all partitions. | `Protection.exe /q` |
| `Protection.exe /c` | Clear all protection configurations (clear sector 62). | `Protection.exe /c` |
| `Protection.exe /u` | Completely uninstall driver and service, and clear configuration. | `Protection.exe /u` |
| `Protection.exe /forceupdate <file>` | Force update driver file (bypass protection). | `Protection.exe /forceupdate diskflt.sys` |

## 7. Frequently Asked Questions (FAQ)

### Q1: Protection software shows "Unable to save configuration"?

**Cause**: Security software may be blocking direct write operations to physical disk sectors, or the software was not run as administrator.
**Solution**: Right-click and select "Run as administrator". Temporarily disable antivirus software, or if the driver is already loaded, the software will attempt to write configuration through the driver IOCTL interface (which is usually not blocked).

### Q2: Why do files copied in protection mode disappear after restart?

**Answer**: This is normal. In protection mode, all writes are temporary. After restart, the system discards all changes and reverts to the pre-protection state. To permanently save files, please disable protection first, or save to an unprotected partition (such as D: drive).

---

Copyright © 2026 Diskflt Team. All Rights Reserved.