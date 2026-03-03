
#define FILE_DEVICE_DISKFLT			0x8000
#define DISKFLT_IOCTL_BASE			0x800

#define CTL_CODE_DISKFLT(lastScan)	\
	CTL_CODE(FILE_DEVICE_DISKFLT, DISKFLT_IOCTL_BASE+lastScan, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DISKFLT_LOCK				CTL_CODE_DISKFLT(0)
#define IOCTL_DISKFLT_UNLOCK			CTL_CODE_DISKFLT(1)
#define IOCTL_DISKFLT_GETINFO			CTL_CODE_DISKFLT(2)
#define IOCTL_DISKFLT_LOGIN				CTL_CODE_DISKFLT(3)

#define IOCTL_DISKFLT_PROTECTSYS		CTL_CODE_DISKFLT(4)	// 保护系统盘
#define IOCTL_DISKFLT_NOPROTECTSYS		CTL_CODE_DISKFLT(5)	// 不保护

#define IOCTL_DISKFLT_PROTECTSYS_STATE	CTL_CODE_DISKFLT(6)	// 是否保护
#define IOCTL_DISKFLT_TEMP_DISABLE      CTL_CODE_DISKFLT(7) // Temporarily disable protection for config update
#define IOCTL_DISKFLT_WRITE_CONFIG      CTL_CODE_DISKFLT(8) // Write config to Sector 62 (Bypass OS restriction)写入配置

#define DISKFILTER_WIN32_DEVICE_NAME_A	"\\\\.\\DiskFlt"
#define DISKFILTER_WIN32_DEVICE_NAME_W	L"\\\\.\\DiskFlt"

#define DISKFILTER_DOS_DEVICE_NAME_W	L"\\DosDevices\\DiskFlt"

#define DISKFILTER_DEVICE_NAME_W		L"\\Device\\DiskFlt"

#ifdef _UNICODE
#define DISKFILTER_WIN32_DEVICE_NAME	DISKFILTER_WIN32_DEVICE_NAME_W
#else
#define DISKFILTER_WIN32_DEVICE_NAME	DISKFILTER_WIN32_DEVICE_NAME_A
#endif

#define MAGIC_CHAR	"[dbgger][dbgger]"


#define MAX_DOS_DRIVES 32

#pragma pack(push, 1)

typedef struct _FAT_BPB {
    USHORT  wBytsPerSec;    // Bytes per sector
    UCHAR   bySecPerClus;   // Sectors per cluster
    USHORT  wRsvdSecCnt;    // Reserved sector count
    UCHAR   byNumFATs;      // Number of FATs
    USHORT  wRootEntCnt;    // Root directory entries
    USHORT  wTotSec16;      // Total sectors (if zero, use wTotSec32)
    UCHAR   byMedia;        // Media descriptor
    USHORT  wFATSz16;       // Sectors per FAT (FAT12/FAT16)
    USHORT  wSecPerTrk;     // Sectors per track
    USHORT  wNumHeads;      // Number of heads
    ULONG   dwHiddSec;      // Hidden sectors
    ULONG   dwTotSec32;     // Total sectors (if wTotSec16 == 0)
} FAT_BPB, *PFAT_BPB;

typedef struct _FAT32_EBPB {
    ULONG   dwFATSz32;      // Sectors per FAT (FAT32)
    USHORT  wExtFlags;      // Extended flags
    USHORT  wFSVer;         // File system version
    ULONG   dwRootClus;     // Root directory cluster
    USHORT  wFSInfo;        // FSInfo sector
    USHORT  wBkBootSec;     // Backup boot sector
    UCHAR   byReserved[12]; // Reserved
    UCHAR   byDrvNum;       // Drive number
    UCHAR   byReserved1;    // Reserved
    UCHAR   byBootSig;      // Boot signature (0x29)
    ULONG   dwVolID;        // Volume ID
    UCHAR   byVolLab[11];   // Volume label
    UCHAR   byFilSysType[8];// File system type
} FAT32_EBPB, *PFAT32_EBPB;

typedef struct _FAT_LBR {
    UCHAR       pbyJmpBoot[3];  // Jump instruction to boot code
    UCHAR       byOemName[8];   // OEM name
    FAT_BPB     bpb;            // BIOS Parameter Block
    union {
        FAT32_EBPB ebpb32;      // Extended BPB for FAT32
        struct {
            UCHAR   byDrvNum;
            UCHAR   byReserved1;
            UCHAR   byBootSig;
            ULONG   dwVolID;
            UCHAR   byVolLab[11];
            UCHAR   byFilSysType[8];
        } ebpb16;
    };
    UCHAR       byBootCode[420]; // Boot code (adjust size for padding)
    USHORT      wTrailSig;       // 0xAA55
} FAT_LBR, *PFAT_LBR;

#pragma pack(pop)

typedef struct _PROTECT_INFO
{
	BYTE	magicChar[32];
	BYTE	volumeInfo[MAX_DOS_DRIVES];	// 卷保护信息，1表示保护
	BYTE	passWord[16];				// MD5密码
} PROTECT_INFO, *PPROTECT_INFO;