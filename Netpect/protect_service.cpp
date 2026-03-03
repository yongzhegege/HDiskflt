#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <thread>
#include <atomic>
#include <map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// --- Constants & Structs ---

#define SERVICE_NAME "ProtectSvc"
#define SECTOR_SIZE 512
#define CONFIG_SECTOR 62
#define DEFAULT_PORT 3000
#define MAGIC_STR "[dbgger][dbgger]"
#define LOG_FILE "C:\\protect_service.log"

// Sector 62 Layout (Combined)
#pragma pack(push, 1)
struct CombinedConfig {
    // Legacy Protection Info (80 bytes) - Offset 0
    BYTE magicChar[32];
    BYTE volumeInfo[32];
    BYTE passWord[16];

    // Service Config (66 bytes) - Offset 80
    char ip[64];
    unsigned short port; // Network Byte Order

    // Padding to reach 510 bytes
    unsigned char padding[512 - 80 - 64 - 2 - 2];
    
    // CRC (2 bytes) - Offset 510
    unsigned short crc;
};
#pragma pack(pop)

// Network Protocol (TLV)
struct PacketHeader {
    unsigned int type;
    unsigned int length;
};

// Protection Info for Driver (Legacy support attempt)
struct PROTECT_INFO {
    BYTE magicChar[32];
    BYTE volumeInfo[32];
    BYTE passWord[16];
};
#pragma pack(pop)

// Driver IOCTLs (from diskflt.h)
#define FILE_DEVICE_DISKFLT 0x8000
#define DISKFLT_IOCTL_BASE 0x800
#define CTL_CODE_DISKFLT(lastScan) CTL_CODE(FILE_DEVICE_DISKFLT, DISKFLT_IOCTL_BASE+lastScan, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISKFLT_PROTECTSYS CTL_CODE_DISKFLT(4) 
// Assuming there is a way to send config to driver via IOCTL if not using disk
// If the driver only reads disk, we have a conflict. 
// We will implement a "Best Effort" driver control using available IOCTLs.

// --- Globals ---

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::atomic<bool> g_Running(true);
std::atomic<bool> g_ReloadRequested(false);
SOCKET g_CurrentSocket = INVALID_SOCKET;

char g_ServerIP[64] = "127.0.0.1";
unsigned short g_ServerPort = DEFAULT_PORT;
BYTE g_AESKey[16] = {0}; // Distributed by server
bool g_HasKey = false;

// --- Helper Functions ---

void GetPartitions(char* buffer, int bufLen) {
    char drives[256];
    if (GetLogicalDriveStringsA(sizeof(drives) - 1, drives)) {
        char* p = drives;
        string result = "";
        while (*p) {
            // p is "C:\"
            char rootPath[4] = { p[0], ':', '\\', 0 };
            UINT type = GetDriveTypeA(rootPath);
            if (type == DRIVE_FIXED) {
                char volName[MAX_PATH];
                char fsName[MAX_PATH];
                if (GetVolumeInformationA(rootPath, volName, sizeof(volName), NULL, NULL, NULL, fsName, sizeof(fsName))) {
                    if (result.length() > 0) result += ",";
                    result += string(1, p[0]) + ":" + string(fsName);
                }
            }
            p += strlen(p) + 1;
        }
        strncpy_s(buffer, bufLen, result.c_str(), bufLen - 1);
    } else {
        strncpy_s(buffer, bufLen, "C:NTFS", bufLen - 1);
    }
}

bool GetMacAddress(char* buffer, int bufLen) {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        // Just pick the first one
        sprintf_s(buffer, bufLen, "%02X-%02X-%02X-%02X-%02X-%02X",
            pAdapterInfo->Address[0], pAdapterInfo->Address[1],
            pAdapterInfo->Address[2], pAdapterInfo->Address[3],
            pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
        return true;
    }
    return false;
}

// CRC16-CCITT (Poly 0x1021)
unsigned short CalculateCRC16(const unsigned char* data, int length) {
    unsigned short crc = 0xFFFF;
    for (int i = 0; i < length; ++i) {
        crc ^= (unsigned short)data[i] << 8;
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
            else crc <<= 1;
        }
    }
    return crc;
}

void LogEvent(const char* msg, WORD type = EVENTLOG_INFORMATION_TYPE) {
    HANDLE hEventLog = RegisterEventSourceA(NULL, SERVICE_NAME);
    if (hEventLog) {
        const char* strings[1] = { msg };
        ReportEventA(hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

void LogToFile(const char* msg) {
    FILE* fp = NULL;
    if (fopen_s(&fp, LOG_FILE, "a+") == 0 && fp) {
        // Timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", 
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
        fclose(fp);
    }
}

// Helper to read current protection status for reporting
void GetProtectionStatus(char* buffer, int bufLen) {
    // Default to empty
    buffer[0] = 0;

    // Read Sector 62
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER offset;
    offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return;
    }

    CombinedConfig config;
    DWORD read;
    if (ReadFile(hDisk, &config, sizeof(CombinedConfig), &read, NULL) && read == sizeof(CombinedConfig)) {
        // Verify Magic
        if (strncmp((char*)config.magicChar, MAGIC_STR, strlen(MAGIC_STR)) == 0) {
             string result = "";
             for (int i = 0; i < 26; i++) {
                 if (config.volumeInfo[i] == 1) {
                     char drive = 'A' + i;
                     if (result.length() > 0) result += ",";
                     result += string(1, drive) + ":Protected";
                 }
             }
             if (result.length() > 0) {
                 strncpy_s(buffer, bufLen, result.c_str(), bufLen - 1);
             }
        }
    }
    CloseHandle(hDisk);
}

// --- Sector 62 Operations ---

bool ReadConfigFromSector() {
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        LogEvent("Failed to open PhysicalDrive0 for config read.", EVENTLOG_ERROR_TYPE);
        return false;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return false;
    }

    CombinedConfig config;
    DWORD read;
    if (!ReadFile(hDisk, &config, sizeof(CombinedConfig), &read, NULL) || read != sizeof(CombinedConfig)) {
        CloseHandle(hDisk);
        return false;
    }
    CloseHandle(hDisk);

    // CRC Check on first 510 bytes
    unsigned short calcCRC = CalculateCRC16((unsigned char*)&config, 510);
    if (calcCRC != config.crc) {
        LogEvent("Config Sector CRC mismatch. Using defaults.", EVENTLOG_WARNING_TYPE);
        return false;
    }

    if (config.ip[0] == 0) return false;

    strncpy_s(g_ServerIP, config.ip, 63);
    g_ServerPort = ntohs(config.port);
    
    char logMsg[128];
    sprintf_s(logMsg, "Loaded Config: %s:%d", g_ServerIP, g_ServerPort);
    LogEvent(logMsg);
    LogToFile(logMsg);

    return true;
}

bool WriteConfigToSector(const char* ip, unsigned short port) {
    // 1. Read existing to preserve protection info
    CombinedConfig config = {0};
    
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open PhysicalDrive0 (Admin required?)\n");
        return false;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
    
    if (SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        DWORD read;
        if (ReadFile(hDisk, &config, sizeof(CombinedConfig), &read, NULL) && read == sizeof(CombinedConfig)) {
            // Check magic
            if (strncmp((char*)config.magicChar, MAGIC_STR, strlen(MAGIC_STR)) != 0) {
                // Initialize if invalid
                memset(&config, 0, sizeof(CombinedConfig));
                strncpy_s((char*)config.magicChar, 32, MAGIC_STR, 31);
            }
        } else {
             memset(&config, 0, sizeof(CombinedConfig));
             strncpy_s((char*)config.magicChar, 32, MAGIC_STR, 31);
        }
    }

    // Update IP/Port
    if (ip && ip[0]) {
        strncpy_s(config.ip, ip, 63);
        config.port = htons(port);
    } else if (port == 0) {
        // Clear IP (disable service conn)
        memset(config.ip, 0, 64);
        config.port = 0;
    }

    // Recalculate CRC
    config.crc = CalculateCRC16((unsigned char*)&config, 510);

    // Write Back
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return false;
    }

    DWORD written;
    if (!WriteFile(hDisk, &config, sizeof(CombinedConfig), &written, NULL) || written != sizeof(CombinedConfig)) {
        printf("Error: Failed to write to Sector 62.\n");
        CloseHandle(hDisk);
        return false;
    }

    CloseHandle(hDisk);
    printf("Configuration saved to Sector 62.\n");
    return true;
}

// --- Driver Control ---

#define IOCTL_DISKFLT_TEMP_DISABLE      CTL_CODE(0x8000, 0x800+7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISKFLT_WRITE_CONFIG      CTL_CODE(0x8000, 0x800+8, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool SetDriverProtection(char driveLetter, bool enable) {
    char logMsg[256];
    sprintf_s(logMsg, "Processing Protection Command: Drive %c -> %s", driveLetter, enable ? "PROTECT" : "UNPROTECT");
    LogEvent(logMsg);
    LogToFile(logMsg);

    // 1. Try to use Driver IOCTL to write config (Best, Bypasses Protection)
    HANDLE hDevice = CreateFileA("\\\\.\\DiskFlt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    bool driverLoaded = (hDevice != INVALID_HANDLE_VALUE);
    
    // We need to read current config first to merge changes
    // If driver loaded, maybe we can read from it too? 
    // Usually driver just enforces. We read from disk.
    // BUT if disk is protected, we can't read/write easily unless we use driver bypass or temp disable.
    
    CombinedConfig config = {0};
    bool readSuccess = false;

    // A. Read Config
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER offset;
        offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
        if (SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
            DWORD read;
            if (ReadFile(hDisk, &config, sizeof(CombinedConfig), &read, NULL) && read == sizeof(CombinedConfig)) {
                readSuccess = true;
            } else {
                 LogToFile("Warning: ReadFile failed (might be protected).");
            }
        }
        CloseHandle(hDisk);
    } else {
        LogToFile("Warning: Could not open PhysicalDrive0 for reading.");
    }

    if (!readSuccess) {
        // If we can't read, maybe we can't write either.
        // We should try to initialize default if read failed?
        // Or if read failed due to protection, we MUST disable protection first to read?
        // Let's try to disable protection TEMP if driver is loaded.
        if (driverLoaded) {
             DWORD bytes;
             if (DeviceIoControl(hDevice, IOCTL_DISKFLT_TEMP_DISABLE, NULL, 0, NULL, 0, &bytes, NULL)) {
                 LogToFile("Info: Temporarily disabled protection to read/write.");
                 // Retry Read
                 hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                 if (hDisk != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER offset;
                    offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
                    if (SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
                        DWORD read;
                        if (ReadFile(hDisk, &config, sizeof(CombinedConfig), &read, NULL) && read == sizeof(CombinedConfig)) {
                            readSuccess = true;
                        }
                    }
                    CloseHandle(hDisk);
                 }
             } else {
                 LogToFile("Error: Failed to disable protection via IOCTL.");
             }
        }
    }

    if (!readSuccess) {
        LogToFile("Error: Could not read configuration even after temp disable attempt.");
        // We could init defaults, but risky to overwrite IP.
        // If we have IP in memory (g_ServerIP), we can reconstruct.
        memset(&config, 0, sizeof(CombinedConfig));
        strncpy_s((char*)config.magicChar, 32, MAGIC_STR, 31);
        strncpy_s(config.ip, g_ServerIP, 63);
        config.port = htons(g_ServerPort);
    }

    // Verify Magic
    if (strncmp((char*)config.magicChar, MAGIC_STR, strlen(MAGIC_STR)) != 0) {
        LogToFile("Warning: Magic string invalid, re-initializing.");
        memset(&config, 0, sizeof(CombinedConfig));
        strncpy_s((char*)config.magicChar, 32, MAGIC_STR, 31);
        strncpy_s(config.ip, g_ServerIP, 63);
        config.port = htons(g_ServerPort);
    }

    // Update Protection Info
    int driveIndex = toupper(driveLetter) - 'A';
    if (driveIndex >= 0 && driveIndex < 26) {
        config.volumeInfo[driveIndex] = enable ? 1 : 0;
        // Sync ESP if C
        if (driveIndex == ('C' - 'A')) {
             config.volumeInfo[26] = enable ? 1 : 0;
        }
    } else {
        LogToFile("Error: Invalid drive letter.");
        if (driverLoaded) CloseHandle(hDevice);
        return false;
    }

    // Update CRC
    config.crc = CalculateCRC16((unsigned char*)&config, 510);

    // B. Write Config
    bool writeSuccess = false;
    
    // STRATEGY: Always write to disk to ensure persistence.
    // 1. Disable Protection Temporarily (if driver loaded)
    if (driverLoaded) {
         DWORD bytes;
         if (DeviceIoControl(hDevice, IOCTL_DISKFLT_TEMP_DISABLE, NULL, 0, NULL, 0, &bytes, NULL)) {
             LogToFile("Info: Temporarily disabled protection for write.");
         } else {
             LogToFile("Warning: Failed to disable protection (IOCTL failed). Write might fail.");
         }
    }

    // 2. Direct Disk Write
    hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER offset;
        offset.QuadPart = CONFIG_SECTOR * SECTOR_SIZE;
        if (SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
            DWORD written;
            if (WriteFile(hDisk, &config, sizeof(CombinedConfig), &written, NULL) && written == sizeof(CombinedConfig)) {
                LogToFile("Success: Configuration written to Sector 62 (Direct Write).");
                writeSuccess = true;
            } else {
                LogToFile("Error: WriteFile failed.");
            }
        }
        CloseHandle(hDisk);
    } else {
            LogToFile("Error: CreateFile for Write failed.");
    }
    
    // 3. Notify Driver (to apply changes or re-enable protection)
    if (driverLoaded) {
        DWORD bytesReturned;
        // Even if we wrote to disk, we send the config to driver so it updates its internal state immediately (Hot Patch)
        if (DeviceIoControl(hDevice, IOCTL_DISKFLT_WRITE_CONFIG, &config, sizeof(CombinedConfig), NULL, 0, &bytesReturned, NULL)) {
            LogToFile("Success: Driver notified via IOCTL (Hot Update).");
        } else {
            LogToFile("Warning: Driver IOCTL Notify failed. Reboot required for changes to take effect.");
        }
        CloseHandle(hDevice);
    }

    if (writeSuccess) {
        LogToFile("Protection configuration updated. Reboot required.");
        return true;
    } else {
        LogToFile("Fatal Error: Failed to update protection configuration.");
        return false;
    }
}

// ------------------------------------------------------------------------------------------------
// Force Update Driver Logic (Physical Write Bypass)
// ------------------------------------------------------------------------------------------------

bool GetVolumeDiskExtents(char volLetter, PVOLUME_DISK_EXTENTS& pExtents) {
    char volPath[] = "\\\\.\\X:";
    volPath[4] = volLetter;

    HANDLE hVol = CreateFileA(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
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
    char path[64];
    sprintf_s(path, sizeof(path), "\\\\.\\PhysicalDrive%d", diskNumber);

    HANDLE hDisk = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
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

bool ForceUpdateDriverFile(const char* srcPath, const char* dstPath) {
    printf("Starting Force Update (Physical Bypass)...\n");
    
    // 1. Read Source File
    HANDLE hSrc = CreateFileA(srcPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("Failed to open source file. Error: %d\n", GetLastError());
        return false;
    }
    DWORD srcSize = GetFileSize(hSrc, NULL);
    BYTE* srcData = (BYTE*)malloc(srcSize);
    DWORD read;
    ReadFile(hSrc, srcData, srcSize, &read, NULL);
    CloseHandle(hSrc);

    // 2. Open Target File to get clusters
    HANDLE hDst = CreateFileA(dstPath, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        printf("Failed to open target file. Error: %d\n", GetLastError());
        free(srcData);
        return false;
    }

    // 3. Get Disk Extents for C: (Assuming target is on C)
    char volLetter = toupper(dstPath[0]);
    PVOLUME_DISK_EXTENTS pExtents = NULL;
    if (!GetVolumeDiskExtents(volLetter, pExtents)) {
        printf("Failed to get volume extents. Error: %d\n", GetLastError());
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
            printf("Failed to get file clusters. Error: %d\n", GetLastError());
            CloseHandle(hDst);
            free(srcData);
            free(pExtents);
            free(pRetrieval);
            return false;
         }
    }
    
    // Get Cluster Size
    char root[] = "C:\\";
    root[0] = volLetter;
    DWORD sectPerClust, bytesPerSect, freeClust, totalClust;
    GetDiskFreeSpaceA(root, &sectPerClust, &bytesPerSect, &freeClust, &totalClust);
    DWORD clusterSize = sectPerClust * bytesPerSect;

    // 5. Write Data to Clusters
    LARGE_INTEGER currentLcn = pRetrieval->Extents[0].Lcn;
    
    if (pRetrieval->ExtentCount > 0) {
        LARGE_INTEGER physAddr;
        physAddr.QuadPart = volOffset.QuadPart + (currentLcn.QuadPart * clusterSize);
        
        printf("Writing to Physical Sector...\n");
        if (PhysicalWrite(diskNumber, physAddr, srcData, srcSize)) {
            printf("Physical Write Success!\n");
        } else {
            printf("Physical Write Failed!\n");
        }
    }

    CloseHandle(hDst);
    free(srcData);
    free(pExtents);
    free(pRetrieval);
    return true;
}

// --- Networking ---

SOCKET ConnectToServer() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_ServerPort);
    inet_pton(AF_INET, g_ServerIP, &addr.sin_addr);

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

void WorkerThread(void* param) {
    int backoff = 1;
    while (g_Running) {
        SOCKET s = ConnectToServer();
        if (s != INVALID_SOCKET) {
            g_CurrentSocket = s;
            LogEvent("Connected to server.");
            backoff = 1;

            // 1. Handshake (Recv Key)
            int len = recv(s, (char*)g_AESKey, 16, 0);
            if (len == 16) {
                g_HasKey = true;
                // 2. Send Info
                char mac[32] = "00-00-00-00-00-00";
                GetMacAddress(mac, sizeof(mac));
                
                char partitions[256] = {0};
                GetPartitions(partitions, sizeof(partitions));
                
                char status[256] = {0};
                GetProtectionStatus(status, sizeof(status));

                char infoBuf[1024];
                sprintf_s(infoBuf, "MAC=%s|PARTITIONS=%s|STATUS=%s", mac, partitions, status);
                send(s, infoBuf, strlen(infoBuf), 0);
            }

            // 3. Heartbeat Loop
            while (g_Running) {
                // Wait for commands or send heartbeat
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(s, &readfds);
                timeval tv = { 5, 0 }; // 5s timeout
                
                int ret = select(0, &readfds, NULL, NULL, &tv);
                if (ret == 0) {
                    // Timeout -> Send Heartbeat with Status
                    char status[256] = {0};
                    GetProtectionStatus(status, sizeof(status));
                    char hbBuf[512];
                    sprintf_s(hbBuf, "HB|STATUS=%s", status);
                    if (send(s, hbBuf, strlen(hbBuf), 0) == SOCKET_ERROR) {
                        break; // Disconnected
                    }
                } else if (ret > 0) {
                    char buf[1024] = {0};
                    int n = recv(s, buf, sizeof(buf) - 1, 0);
                    if (n <= 0) break; // Disconnect
                    buf[n] = 0; // Ensure null-termination
                    
                    LogToFile(buf); // Log received command

                    // Handle Command (e.g., "PROTECT C", "UNPROTECT D")
                    if (strncmp(buf, "PROTECT ", 8) == 0) {
                        char drive = buf[8];
                        if (SetDriverProtection(drive, true)) {
                            char status[256] = {0};
                            GetProtectionStatus(status, sizeof(status));
                            char reply[512];
                            sprintf_s(reply, "OK|STATUS=%s", status);
                            send(s, reply, strlen(reply), 0);
                        } else {
                            send(s, "ERR", 3, 0);
                        }
                    } else if (strncmp(buf, "UNPROTECT ", 10) == 0) {
                        char drive = buf[10];
                        if (SetDriverProtection(drive, false)) {
                            char status[256] = {0};
                            GetProtectionStatus(status, sizeof(status));
                            char reply[512];
                            sprintf_s(reply, "OK|STATUS=%s", status);
                            send(s, reply, strlen(reply), 0);
                        } else {
                            send(s, "ERR", 3, 0);
                        }
                    } else if (strncmp(buf, "RESTART", 7) == 0) {
                        LogEvent("Received RESTART command.");
                        LogToFile("Received RESTART command.");
                        system("shutdown /r /t 0");
                    } else if (strncmp(buf, "SHUTDOWN", 8) == 0) {
                        LogEvent("Received SHUTDOWN command.");
                        LogToFile("Received SHUTDOWN command.");
                        system("shutdown /s /t 0");
                    }
                } else {
                    break; // Error
                }
            }
            closesocket(s);
            if (g_CurrentSocket == s) g_CurrentSocket = INVALID_SOCKET;
            LogEvent("Disconnected from server.");
        } else {
            // LogEvent("Connection failed. Retrying...");
        }

        // Backoff
        if (!g_Running) break;
        Sleep(backoff * 1000);
        if (backoff < 300) backoff *= 2;
    }
}

// --- Service Infrastructure ---

void WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;
        g_Running = false;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
        if (g_CurrentSocket != INVALID_SOCKET) {
             closesocket(g_CurrentSocket);
             g_CurrentSocket = INVALID_SOCKET;
        }
        break;
    case 128: // Custom Control Code for RELOAD_CONFIG
        LogEvent("Received RELOAD_CONFIG signal.");
        if (ReadConfigFromSector()) {
             // Force disconnect current socket to trigger reconnect loop
             if (g_CurrentSocket != INVALID_SOCKET) {
                 closesocket(g_CurrentSocket);
                 g_CurrentSocket = INVALID_SOCKET;
             }
        }
        break;
    default:
        break;
    }
}

// --- Discovery (UDP Listener) ---

void DiscoveryThread(void* param) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;

    // Allow Broadcast
    BOOL broadcast = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
    
    // Reuse Addr
    BOOL reuse = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT); // Same port as TCP (3000) for simplicity or +1
    // Actually, TCP Listen on 3000. UDP Listen on 3000 might conflict if SO_REUSEADDR not fully supported on some OS/Interfaces?
    // But usually fine. Let's use 3000.
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        // LogEvent("Discovery Bind Failed. Port 3000 busy?");
        closesocket(sock);
        return;
    }

    char buf[256];
    sockaddr_in senderAddr;
    int senderLen = sizeof(senderAddr);

    while (g_Running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval tv = { 1, 0 };

        int ret = select(0, &readfds, NULL, NULL, &tv);
        if (ret > 0) {
            int n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&senderAddr, &senderLen);
            if (n > 0) {
                buf[n] = 0;
                if (strncmp(buf, "DISCOVER_PROTECT_SERVER", 23) == 0) {
                    char serverIP[64];
                    inet_ntop(AF_INET, &senderAddr.sin_addr, serverIP, sizeof(serverIP));
                    
                    // Auto-Configure if not set or local
                    if (strcmp(g_ServerIP, "127.0.0.1") == 0 || strlen(g_ServerIP) == 0) {
                        strncpy_s(g_ServerIP, serverIP, 63);
                        // LogEvent("Auto-Discovery: Found Server.");
                        // Force reconnect if idle
                        if (g_CurrentSocket == INVALID_SOCKET) {
                             // Will connect in next Worker loop
                        }
                    }
                }
            }
        }
    }
    closesocket(sock);
}

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // Load Config
    if (!ReadConfigFromSector()) {
        // Defaults already set
    }

    // Init Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Start Worker
    std::thread worker(WorkerThread, nullptr);
    worker.detach();

    // Start Discovery Listener
    std::thread discovery(DiscoveryThread, nullptr);
    discovery.detach();

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    WSACleanup();
}

// --- Main Entry ---

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "/set") == 0) {
            if (argc < 3) {
                printf("Usage: protect.exe /set <IP>[:Port]\n");
                return 1;
            }
            
            char ip[64] = {0};
            unsigned short port = DEFAULT_PORT;
            
            char* p = strchr(argv[2], ':');
            if (p) {
                *p = 0;
                strncpy_s(ip, argv[2], 63);
                port = (unsigned short)atoi(p + 1);
            } else {
                strncpy_s(ip, argv[2], 63);
            }

            if (WriteConfigToSector(ip, port)) {
                // Send signal to service to reload config and reconnect
                SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                if (hSCM) {
                    SC_HANDLE hService = OpenServiceA(hSCM, SERVICE_NAME, SERVICE_USER_DEFINED_CONTROL);
                    if (hService) {
                        SERVICE_STATUS status;
                        if (ControlService(hService, 128, &status)) { // 128 is RELOAD_CONFIG
                            printf("Configuration updated. Service signalled to reconnect.\n");
                        } else {
                            printf("Configuration updated. Failed to signal service (Is it running?).\n");
                        }
                        CloseServiceHandle(hService);
                    } else {
                        printf("Configuration updated. Service not found or access denied.\n");
                    }
                    CloseServiceHandle(hSCM);
                }
                return 0;
            } else {
                return 1;
            }
        } else if (strcmp(argv[1], "/conn") == 0) {
            // Test Connection
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);

            if (!ReadConfigFromSector()) {
                printf("Error: No configuration found in Sector 62.\n");
                WSACleanup();
                return 1;
            }

            printf("Testing connection to %s:%d...\n", g_ServerIP, g_ServerPort);
            SOCKET s = ConnectToServer();
            if (s != INVALID_SOCKET) {
                printf("Success: Connected to server!\n");
                
                // Receive Key to complete handshake gracefully
                char key[16];
                int len = recv(s, key, 16, 0);
                if (len == 16) {
                    printf("Handshake successful (Key received).\n");
                } else {
                    printf("Warning: Handshake incomplete.\n");
                }

                closesocket(s);
            } else {
                printf("Error: Failed to connect to server.\n");
            }
            WSACleanup();
            return 0;
        } else if (strcmp(argv[1], "/clear") == 0) {
            // Clear Sector 62
            char emptyIP[64] = {0};
            if (WriteConfigToSector(emptyIP, 0)) {
                printf("Sector 62 cleared.\n");
                return 0;
            } else {
                return 1;
            }
        } else if (strcmp(argv[1], "/forceupdate") == 0) {
             if (argc < 3) {
                 printf("Usage: protect.exe /forceupdate <source_sys_path>\n");
                 return 1;
             }
             
             // Use default destination if not provided or hardcoded
             const char* src = argv[2];
             const char* dst = "C:\\Windows\\System32\\drivers\\diskflt.sys";
             
             if (ForceUpdateDriverFile(src, dst)) {
                 printf("Driver updated successfully. Reboot required.\n");
                 return 0;
             } else {
                 printf("Driver update failed.\n");
                 return 1;
             }
        } else if (strcmp(argv[1], "/u") == 0) {
             // Uninstall logic
             // 1. Clear Config
             char emptyIP[64] = {0};
             WriteConfigToSector(emptyIP, 0);
             
             // 2. Stop Service (Self?)
             // 3. Delete Service
             // 4. Remove UpperFilters
             // 5. Delete Driver File
             
             // PowerShell Command for UpperFilters
             const char* psCmd = "powershell -Command \"$key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}'; $values = (Get-ItemProperty $key).UpperFilters; if ($values -contains 'diskflt') { $values = $values | Where-Object { $_ -ne 'diskflt' }; Set-ItemProperty $key -Name UpperFilters -Value $values; echo 'Removed diskflt from UpperFilters'; }\"";
             system(psCmd);
             
             printf("Uninstall steps triggered. Please reboot.\n");
             return 0;
        } else if (strcmp(argv[1], "/q") == 0) {
             char status[256] = {0};
             GetProtectionStatus(status, sizeof(status));
             if (strlen(status) > 0)
                 printf("Current Protection: %s\n", status);
             else
                 printf("No drives protected.\n");
             return 0;
        } else if (argc >= 3 && (strcmp(argv[2], "/r") == 0 || strcmp(argv[2], "/w") == 0)) {
             // Protect/Unprotect specific drive: protect.exe C /r
             char drive = argv[1][0];
             bool protect = (strcmp(argv[2], "/r") == 0);
             
             if (SetDriverProtection(drive, protect)) {
                 printf("Drive %c %s. Reboot required.\n", drive, protect ? "Protected" : "Unprotected");
                 return 0;
             } else {
                 printf("Failed to set protection.\n");
                 return 1;
             }
        }
    }

    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(ServiceTable)) {
        // If run as console app (not service manager), show help
        printf("Protect Service & Tool\n");
        printf("Usage:\n");
        printf("  protect.exe /set <IP>[:Port]  - Configure Server\n");
        printf("  protect.exe /clear            - Clear Configuration\n");
        printf("  protect.exe /conn             - Test Connection\n");
        printf("  protect.exe <Drive> /r        - Protect Drive (e.g., C)\n");
        printf("  protect.exe <Drive> /w        - Unprotect Drive\n");
        printf("  protect.exe /q                - Query Status\n");
        printf("  protect.exe /u                - Uninstall Driver\n");
        printf("  (Run as Service)              - Start Protection Service\n");
    }

    return 0;
}
