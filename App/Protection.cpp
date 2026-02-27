#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <shlwapi.h>
#include <strsafe.h>
#include <winioctl.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

// Protection Info Structure (Must match driver and previous script)
// magicChar[32] + volumeInfo[32] + passWord[16] = 80 bytes
#pragma pack(push, 1)
typedef struct _PROTECT_INFO {
    BYTE magicChar[32];
    BYTE volumeInfo[32];
    BYTE passWord[16];
} PROTECT_INFO, *PPROTECT_INFO;
#pragma pack(pop)

#define REG_PATH L"SYSTEM\\CurrentControlSet\\Services\\DiskFlt"
#define REG_VALUE L"ProtectInfo"
#define MAGIC_STR "[dbgger][dbgger]"

void LogToDisk(const wstring& msg) {
    FILE* fp = _wfopen(L"C:\\protection_log.txt", L"a+");
    if (fp) {
        fwprintf(fp, L"%s\n", msg.c_str());
        fclose(fp);
    }
}

void Log(const wstring& msg) {
    wcout << msg << endl;
    LogToDisk(msg);
}

void LogError(const wstring& msg, DWORD err) {
    wchar_t buf[256];
    StringCbPrintf(buf, sizeof(buf), L"[ERROR] %s Code: %d", msg.c_str(), err);
    wcout << buf << endl;
    LogToDisk(buf);
}

bool IsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdminSID = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID))
    {
        if (!CheckTokenMembership(NULL, pAdminSID, &fIsRunAsAdmin)) {
            fIsRunAsAdmin = FALSE;
        }
        FreeSid(pAdminSID);
    }
    return fIsRunAsAdmin == TRUE;
}

// Forward declaration
bool WriteConfigViaDriver(const void* data, DWORD size);

bool SaveConfigToDisk(const PROTECT_INFO& info) {
    // Prepare 512-byte buffer for Sector 62
    BYTE buffer[512];
    memset(buffer, 0, 512);
    memcpy(buffer, &info, sizeof(PROTECT_INFO));

    // Try Driver IOCTL First (Bypass OS Restrictions)
    if (WriteConfigViaDriver(buffer, 512)) {
        return true;
    }

    // Fallback: Write config to Disk 0 Sector 62 directly
    Log(L"Driver IOCTL failed/not loaded, trying direct disk write...");
    HANDLE hDisk = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        LogError(L"Failed to open PhysicalDrive0.", GetLastError());
        return false;
    }

    // Move pointer to Sector 62 (62 * 512)
    LARGE_INTEGER offset;
    offset.QuadPart = 62 * 512;
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        LogError(L"Failed to seek to Sector 62.", GetLastError());
        CloseHandle(hDisk);
        return false;
    }

    // We must write aligned to sector size (usually 512)
    // BYTE buffer[512]; // Already defined above
    memset(buffer, 0, 512);
    memcpy(buffer, &info, sizeof(PROTECT_INFO));

    DWORD written;
    if (!WriteFile(hDisk, buffer, 512, &written, NULL)) {
        LogError(L"Failed to write to Sector 62.", GetLastError());
        CloseHandle(hDisk);
        return false;
    }

    CloseHandle(hDisk);
    return true;
}

bool GetConfigFromDisk(PROTECT_INFO& info) {
     HANDLE hDisk = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 62 * 512;
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return false;
    }

    BYTE buffer[512];
    DWORD read;
    if (!ReadFile(hDisk, buffer, 512, &read, NULL)) {
        CloseHandle(hDisk);
        return false;
    }
    
    memcpy(&info, buffer, sizeof(PROTECT_INFO));
    CloseHandle(hDisk);
    return true;
}

bool SetProtectInfo(const PROTECT_INFO& info) {
    // Write to Registry (Backup/Legacy)
    HKEY hKey;
    DWORD disposition;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, REG_VALUE, 0, REG_BINARY, (const BYTE*)&info, sizeof(PROTECT_INFO));
        RegCloseKey(hKey);
    }
    
    // Write to Disk (Primary)
    if (!SaveConfigToDisk(info)) {
        Log(L"Failed to save configuration to Disk Sector!");
        return false;
    }

    return true;
}

bool GetProtectInfo(PROTECT_INFO& info) {
    // Try Disk First
    if (GetConfigFromDisk(info)) {
         string magic = MAGIC_STR;
         if (memcmp(info.magicChar, magic.c_str(), magic.length()) == 0) {
             return true;
         }
    }

    // Fallback to Registry
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = REG_BINARY;
    DWORD size = sizeof(PROTECT_INFO);
    if (RegQueryValueEx(hKey, REG_VALUE, NULL, &type, (LPBYTE)&info, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

void InitProtectInfo(PROTECT_INFO& info) {
    memset(&info, 0, sizeof(PROTECT_INFO));
    string magic = MAGIC_STR;
    memcpy(info.magicChar, magic.c_str(), min(magic.length(), sizeof(info.magicChar)));
}

void ShowStatus() {
    PROTECT_INFO info;
    if (!GetProtectInfo(info)) {
        Log(L"No protection configuration found.");
        return;
    }

    Log(L"Current Protection Status:");
    bool anyProtected = false;
    for (int i = 0; i < 26; i++) {
        if (info.volumeInfo[i]) {
            wcout << L"Drive " << (wchar_t)(L'A' + i) << L": Protected" << endl;
            anyProtected = true;
        }
    }
    
    // Check ESP (Index 26)
    if (info.volumeInfo[26]) {
         wcout << L"ESP Partition: Protected" << endl;
         anyProtected = true;
    }

    if (!anyProtected) {
        Log(L"No drives are currently protected.");
    }
}

#define IOCTL_DISKFLT_TEMP_DISABLE      CTL_CODE(0x8000, 0x800+7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISKFLT_WRITE_CONFIG      CTL_CODE(0x8000, 0x800+8, METHOD_BUFFERED, FILE_ANY_ACCESS)

void DisableProtectionTemp() {
    HANDLE hDevice = CreateFile(L"\\\\.\\DiskFlt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        if (DeviceIoControl(hDevice, IOCTL_DISKFLT_TEMP_DISABLE, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
            Log(L"Temporarily disabled protection to update configuration.");
        } else {
             LogError(L"Failed to disable protection (DeviceIoControl).", GetLastError());
        }
        CloseHandle(hDevice);
    } else {
         // If driver is not loaded, we don't need to disable protection.
         // But it might be loaded but handle creation failed for other reasons.
         // LogError(L"Failed to open DiskFlt driver.", GetLastError());
         Log(L"Driver not accessible (not loaded?), skipping temp disable.");
    }
}

// ------------------------------------------------------------------------------------------------
// Driver IOCTL Helper to Bypass OS Write Restrictions
// ------------------------------------------------------------------------------------------------
bool WriteConfigViaDriver(const void* data, DWORD size) {
    HANDLE hDevice = CreateFile(L"\\\\.\\DiskFlt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        Log(L"Driver not loaded. Cannot use Driver Bypass.");
        return false;
    }

    DWORD bytesReturned;
    bool result = DeviceIoControl(hDevice, IOCTL_DISKFLT_WRITE_CONFIG, (LPVOID)data, size, NULL, 0, &bytesReturned, NULL);
    
    if (result) {
        Log(L"Configuration written via Driver IOCTL.");
    } else {
        LogError(L"Driver IOCTL Write Failed.", GetLastError());
    }

    CloseHandle(hDevice);
    return result;
}

// ------------------------------------------------------------------------------------------------
// Force Update Driver Logic (Physical Write Bypass)
// ------------------------------------------------------------------------------------------------

bool GetVolumeDiskExtents(wchar_t volLetter, PVOLUME_DISK_EXTENTS& pExtents) {
    wchar_t volPath[] = L"\\\\.\\X:";
    volPath[4] = volLetter;

    HANDLE hVol = CreateFile(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return false;

    DWORD size = sizeof(VOLUME_DISK_EXTENTS) + 256 * sizeof(DISK_EXTENT);
    pExtents = (PVOLUME_DISK_EXTENTS)malloc(size);
    if (!pExtents) {
        CloseHandle(hVol);
        return false;
    }

    DWORD bytes;
    if (!DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, pExtents, size, &bytes, NULL)) {
        free(pExtents);
        CloseHandle(hVol);
        return false;
    }

    CloseHandle(hVol);
    return true;
}

bool PhysicalWrite(DWORD diskNumber, LARGE_INTEGER offset, BYTE* data, DWORD length) {
    wchar_t path[64];
    StringCbPrintf(path, sizeof(path), L"\\\\.\\PhysicalDrive%d", diskNumber);

    HANDLE hDisk = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return false;

    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return false;
    }

    DWORD written;
    bool res = WriteFile(hDisk, data, length, &written, NULL);
    CloseHandle(hDisk);
    return res && (written == length);
}

bool ForceUpdateDriverFile(const wstring& srcPath, const wstring& dstPath) {
    Log(L"Starting Force Update (Physical Bypass)...");
    
    // 1. Read Source File
    HANDLE hSrc = CreateFile(srcPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        LogError(L"Failed to open source file.", GetLastError());
        return false;
    }
    DWORD srcSize = GetFileSize(hSrc, NULL);
    BYTE* srcData = (BYTE*)malloc(srcSize);
    DWORD read;
    ReadFile(hSrc, srcData, srcSize, &read, NULL);
    CloseHandle(hSrc);

    // 2. Open Target File to get clusters
    HANDLE hDst = CreateFile(dstPath.c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        LogError(L"Failed to open target file.", GetLastError());
        free(srcData);
        return false;
    }

    // 3. Get Disk Extents for C: (Assuming target is on C)
    // Simplified: Assume target is on same volume as path indicates.
    wchar_t volLetter = towupper(dstPath[0]);
    PVOLUME_DISK_EXTENTS pExtents = NULL;
    if (!GetVolumeDiskExtents(volLetter, pExtents)) {
        LogError(L"Failed to get volume extents.", GetLastError());
        CloseHandle(hDst);
        free(srcData);
        return false;
    }
    
    // Assume Volume spans one disk (simple case) or first extent
    DWORD diskNumber = pExtents->Extents[0].DiskNumber;
    LARGE_INTEGER volOffset = pExtents->Extents[0].StartingOffset;

    // 4. Get Retrieval Pointers (Clusters)
    STARTING_VCN_INPUT_BUFFER input = { 0 };
    RETRIEVAL_POINTERS_BUFFER* pRetrieval = (RETRIEVAL_POINTERS_BUFFER*)malloc(4096);
    
    DWORD bytes;
    if (!DeviceIoControl(hDst, FSCTL_GET_RETRIEVAL_POINTERS, &input, sizeof(input), pRetrieval, 4096, &bytes, NULL)) {
         if (GetLastError() != ERROR_MORE_DATA) {
            LogError(L"Failed to get file clusters.", GetLastError());
            CloseHandle(hDst);
            free(srcData);
            free(pExtents);
            free(pRetrieval);
            return false;
         }
    }
    
    // Get Cluster Size
    wchar_t root[] = L"C:\\";
    root[0] = volLetter;
    DWORD sectPerClust, bytesPerSect, freeClust, totalClust;
    GetDiskFreeSpace(root, &sectPerClust, &bytesPerSect, &freeClust, &totalClust);
    DWORD clusterSize = sectPerClust * bytesPerSect;

    // 5. Write Data to Clusters
    DWORD currentOffset = 0;
    LARGE_INTEGER currentLcn = pRetrieval->Extents[0].Lcn;
    
    // Handle only the first run for simplicity (drivers are usually small and contiguous)
    // If complex, need loop.
    if (pRetrieval->ExtentCount > 0) {
        // Calculate Physical Address
        LARGE_INTEGER physAddr;
        physAddr.QuadPart = volOffset.QuadPart + (currentLcn.QuadPart * clusterSize);
        
        Log(L"Writing to Physical Sector...");
        if (PhysicalWrite(diskNumber, physAddr, srcData, srcSize)) {
            Log(L"Physical Write Success!");
        } else {
            Log(L"Physical Write Failed!");
        }
    }

    CloseHandle(hDst);
    free(srcData);
    free(pExtents);
    free(pRetrieval);
    return true;
}

bool SetDriveProtection(wchar_t driveLetter, bool protect) {
    // Disable protection first to ensure registry write goes through
    DisableProtectionTemp();

    PROTECT_INFO info;
    
    // Try to read existing config, or init new if failed
    if (!GetProtectInfo(info)) {
        InitProtectInfo(info);
    } else {
        // Verify magic to ensure structure validity
        string magic = MAGIC_STR;
        if (memcmp(info.magicChar, magic.c_str(), magic.length()) != 0) {
            Log(L"Invalid config detected, resetting...");
            InitProtectInfo(info);
        }
    }

    driveLetter = towupper(driveLetter);
    int index = driveLetter - L'A';
    
    if (index < 0 || index >= 26) {
        Log(L"Invalid drive letter.");
        return false;
    }

    info.volumeInfo[index] = protect ? 1 : 0;
    
    // For ESP (Index 26), we should sync it with C drive status if driveLetter is C
    if (index == ('C' - 'A')) {
        info.volumeInfo[26] = protect ? 1 : 0;
    }
    
    if (SetProtectInfo(info)) {
        wcout << L"Drive " << driveLetter << (protect ? L" is now PROTECTED." : L" is now UNPROTECTED.") << endl;
        Log(L"Please restart the computer for changes to take effect.");
        return true;
    }
    
    return false;
}

void ShowUsage() {
    Log(L"Usage:");
    Log(L"  Protection.exe <DriveLetter> /r   - Enable protection (Restore mode)");
    Log(L"  Protection.exe <DriveLetter> /w   - Disable protection (Write mode)");
    Log(L"  Protection.exe /q                 - Query status");
    Log(L"  Protection.exe /c                 - Clear configuration (Sector 62)");
    Log(L"  Protection.exe /u                 - Uninstall driver and clear config");
    Log(L"  Protection.exe /forceupdate <path> - Force update diskflt.sys (Bypass protection)");
    Log(L"Examples:");
    Log(L"  Protection.exe C /r");
    Log(L"  Protection.exe /c");
    Log(L"  Protection.exe /u");
}

bool ClearConfig() {
    Log(L"Clearing configuration on Sector 62...");
    
    // Prepare Zero Buffer
    BYTE buffer[512];
    memset(buffer, 0, 512);

    // Try Driver IOCTL First
    if (WriteConfigViaDriver(buffer, 512)) {
        Log(L"Sector 62 cleared successfully via Driver.");
        return true;
    }

    Log(L"Driver IOCTL failed/not loaded, trying direct disk write...");
    
    HANDLE hDisk = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        LogError(L"Failed to open PhysicalDrive0.", GetLastError());
        return false;
    }

    // Move pointer to Sector 62 (62 * 512)
    LARGE_INTEGER offset;
    offset.QuadPart = 62 * 512;
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        LogError(L"Failed to seek to Sector 62.", GetLastError());
        CloseHandle(hDisk);
        return false;
    }

    DWORD written;
    if (!WriteFile(hDisk, buffer, 512, &written, NULL)) {
        LogError(L"Failed to clear Sector 62.", GetLastError());
        CloseHandle(hDisk);
        return false;
    }

    CloseHandle(hDisk);
    Log(L"Sector 62 cleared successfully.");
    return true;
}

bool UninstallDriver() {
    Log(L"Starting Uninstallation...");

    // 1. Clear Config
    ClearConfig();

    // 2. Stop Service
    Log(L"Stopping diskflt service...");
    system("sc stop diskflt >nul 2>&1");

    // 3. Delete Service
    Log(L"Deleting diskflt service...");
    system("sc delete diskflt >nul 2>&1");

    // 4. Remove from UpperFilters (via PowerShell)
    Log(L"Removing from UpperFilters...");
    const char* psCmd = "powershell -Command \"$key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}'; $values = (Get-ItemProperty $key).UpperFilters; if ($values -contains 'diskflt') { $values = $values | Where-Object { $_ -ne 'diskflt' }; Set-ItemProperty $key -Name UpperFilters -Value $values; echo 'Removed diskflt from UpperFilters'; }\"";
    system(psCmd);

    // 5. Delete Driver File
    Log(L"Deleting driver file...");
    // We try standard delete. If it fails (in use), we might need to schedule it on reboot, 
    // but typically stopping service releases the handle unless it's a boot driver that can't stop.
    // diskflt is a boot driver, but if we stopped it (if possible) or if we just delete it, it might require reboot.
    // Note: Boot start drivers often can't be stopped. 
    // We will try to delete, and if it fails, we move it to NULL (PendingRenameOperations) or just warn user.
    if (DeleteFile(L"C:\\Windows\\System32\\drivers\\diskflt.sys")) {
        Log(L"Deleted C:\\Windows\\System32\\drivers\\diskflt.sys");
    } else {
        LogError(L"Failed to delete driver file (might be in use). Reboot required.", GetLastError());
        // Try MoveFileEx with DELAY_UNTIL_REBOOT
        MoveFileEx(L"C:\\Windows\\System32\\drivers\\diskflt.sys", NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    // 6. Delete Backup in Z:
    if (GetFileAttributes(L"Z:\\diskflt.sys") != INVALID_FILE_ATTRIBUTES) {
         if (DeleteFile(L"Z:\\diskflt.sys")) {
             Log(L"Deleted Z:\\diskflt.sys");
         }
    }

    Log(L"Uninstallation complete. Please REBOOT to finalize.");
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "");

    if (!IsAdmin()) {
        Log(L"Please run as Administrator.");
        return 1;
    }

    if (argc < 2) {
        ShowUsage();
        return 1;
    }

    wstring cmd = argv[1];
    
    if (cmd == L"/?" || cmd == L"-?" || cmd == L"-help" || cmd == L"--help") {
        ShowUsage();
        return 0;
    }

    if (cmd == L"/c" || cmd == L"-c") {
        ClearConfig();
        return 0;
    }

    if (cmd == L"/u" || cmd == L"-u") {
        UninstallDriver();
        return 0;
    }

    if (cmd == L"/q" || cmd == L"-q") {
        ShowStatus();
        return 0;
    }

    if (cmd == L"/forceupdate") {
         if (argc < 3) {
             Log(L"Usage: Protection.exe /forceupdate <source_sys_path>");
             return 1;
         }
         wstring src = argv[2];
         // Default target is system driver path
         wstring dst = L"C:\\Windows\\System32\\drivers\\diskflt.sys";
         
         if (ForceUpdateDriverFile(src, dst)) {
             Log(L"Driver updated successfully (Physical Write). Please REBOOT.");
         } else {
             Log(L"Driver update failed.");
         }
         return 0;
    }

    // Expecting: Protection.exe <Drive> <Mode>
    if (argc < 3) {
        ShowUsage();
        return 1;
    }

    wchar_t driveLetter = argv[1][0];
    wstring mode = argv[2];

    if (mode == L"/r" || mode == L"-r") {
        SetDriveProtection(driveLetter, true);
    } else if (mode == L"/w" || mode == L"-w") {
        SetDriveProtection(driveLetter, false);
    } else {
        Log(L"Invalid mode. Use /r for protection or /w for writable.");
        ShowUsage();
        return 1;
    }

    return 0;
}
