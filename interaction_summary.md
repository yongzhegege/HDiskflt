# Interaction Summary: Disk Filter Driver Development
**Date:** 2026-03-03
**Project:** Disk Filter Driver (diskflt.sys) & Protection Tool

## 1. Project Context
The objective is to develop and debug a disk filter driver (`diskflt.sys`) and a control application (`Protection.exe`) in a Virtual Machine environment. The environment resets on reboot (Shadow Mode), requiring persistent configuration strategies.

## 2. Key Issues & Resolutions

### 2.1 Driver Update Failure
- **Issue:** `Protection.exe /forceupdate` failed with error code 2 (File not found) due to file system redirection or shadowing.
- **Resolution:** 
  - Manually copied `diskflt.sys` to `C:\Windows\System32\drivers\`.
  - Updated `install.bat` to backup the driver to the ESP partition (Z:) to survive reboots.

### 2.2 Configuration Persistence (Registry vs. Disk)
- **Issue:** Driver configuration stored in the Registry was lost after reboot due to Shadow Mode resetting the VM state.
- **Resolution:**
  - **Action:** Disabled `flt_loadConfigFromRegistry` in `diskflt.c`.
  - **Implementation:** Enforced loading configuration exclusively from **Disk 0 Sector 62** (Raw Sector Write). This bypasses filesystem-level resets.
  - **Verification:** Added "V2 DISK ONLY BUILD" logs to confirm the loading path.

### 2.3 Sector 62 Write Permission
- **Issue:** `Protection.exe` failed to write the configuration to Sector 62 because the driver blocked the write operation.
- **Resolution:**
  - Modified `diskflt.c` to explicitly allow writes to Sector 62 (Offset `31744`).
  - Added logging to confirm "ALLOWED Write to Config Sector 62".

### 2.4 Array Out-of-Bounds Crash
- **Issue:** Potential crash in `IOCTL_DISKFLT_TEMP_DISABLE`.
- **Resolution:** Corrected array index from 32 to 26 in `diskflt.c`.

### 2.5 Logging & Debugging
- **Issue:** Inability to see logs after a system reset.
- **Resolution:**
  - **Driver:** Enabled file-based logging (`LogToFile`).
  - **App:** Added `LogToDisk` function in `Protection.cpp` to write debug info to `C:\protection_log.txt`.

### 2.6 Windows 11 BSOD (ntokrnl.exe) Fix
- **Issue:** System crashed with BSOD (likely `IRQL_NOT_LESS_OR_EQUAL`) in `ntokrnl.exe` after enabling protection and rebooting.
- **Diagnosis:** The driver attempted to perform complex redirection logic for **Paging I/O** at `DISPATCH_LEVEL`.
- **Resolution:** Modified I/O path to queue operations safely.

### 2.7 Winlogon Hang (Spinning Circle)
- **Issue:** After fixing the BSOD, the system boots but hangs at the `winlogon` user login screen (spinning circle).
- **Diagnosis:** Deadlock in **Paging I/O** handling. The driver was redirecting Paging I/O (using `handle_disk_request`) which requires acquiring locks that may already be held.
- **Initial Fix (Too Aggressive):** Passthrough ALL Paging I/O.
  - **Result:** System booted, but **Protection Failed** because user data writes (which are often Paging I/O) were written to disk.

### 2.8 Protection Failure (Data Not Reverted)
- **Issue:** User reported protection was lost (data saved to disk).
- **Cause:** The "Passthrough All Paging I/O" fix allowed all file writes (Lazy Writer) to bypass redirection.
- **Final Resolution:**
  - **Strategy:** Revert the "Passthrough All" logic. Instead of passing through, **Queue Paging I/O** to the worker thread.
  - **Why?**
    - Synchronous handling at DISPATCH_LEVEL = BSOD.
    - Passthrough = Protection Loss.
    - Queuing = Safe from BSOD (no wait at DISPATCH), Safe for Protection (redirects write).
    - **Risk:** Potential logical deadlock in Worker Thread, but this is the only viable path for a Shadow Mode driver that requires redirection.
  - **Implementation:** Removed the `if (Irp->Flags & IRP_PAGING_IO) { return FALSE; }` block in `diskflt.c`, allowing Paging I/O to fall through to the `ExInterlockedInsertTailList` logic.

### 2.9 Tool Integration & Network Features (Latest Updates)
- **Integration:** Integrated all functionality from `Protection.exe` (Standalone Tool) into `protect.exe` (Client Service). `protect.exe` now serves as both the background service and the command-line control tool.
- **Auto-Discovery:**
  - **Server (`ProtectServer.exe`)**: Implemented UDP Broadcast (Port 3000) to announce presence every 5 seconds.
  - **Client (`protect.exe`)**: Implemented UDP Listener. Automatically detects server in the same VLAN and connects if no manual IP is configured.
- **Instant Reconnect:**
  - Modified `protect.exe` to support `RELOAD_CONFIG` (Control Code 128).
  - When configuration is updated via CLI (`protect.exe /set <IP>`), the tool signals the running service to immediately reload configuration and reconnect, eliminating the need for a service restart.

## 3. Current Status
- **Resolved:** Boot loop, BSOD, Login Hang, Protection Failure, and Tool Fragmentation.
- **Pending:** Final deployment testing in multi-client environment.

## 4. Modified Files
1.  `c:\Users\Administrator\Documents\pDISK\sys\diskflt.c` (Driver Logic)
2.  `c:\Users\Administrator\Documents\pDISK\App\protect_service.cpp` (Unified Client Service & Tool)
3.  `c:\Users\Administrator\Documents\pDISK\App\ProtectServer.cs` (Server with Discovery)
4.  `c:\Users\Administrator\Documents\pDISK\Netpect\install.bat` (Installation Script)
