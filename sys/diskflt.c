
#include <ntifs.h>
#include <ntdddisk.h>
#include <windef.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntddvol.h>
//#include <ntifs.h>
//#include "GenericTable.h"



#include "diskfltlib.h"

//#include "ntimage.h"
//#include <ntimage.h>
#include "mempool/mempool.h"
#include "diskflt.h"
#include "md5.h"
#include "notify.h"

typedef struct _SYSTEM_HANDLE_INFORMATION { // Actually SYSTEM_HANDLE_TABLE_ENTRY_INFO
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT Handle;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define ObjectNameInfo ObjectNameInformation

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef ObjectNameInformation
#define ObjectNameInformation 1
#endif

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG Length,
    OUT PULONG ReturnLength OPTIONAL
);


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

#define RTL_CONSTANT_STRING(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), s}
#define	__free_Safe(_buffer)	{if (_buffer)__free(_buffer);}

#define dprintf	if (DBG) DbgPrint

VOID DiskFltLog(const char* format, ...);
VOID LogToFile(CHAR* format, ...);



ULONG g_ProtectLogCount = 0;
BOOLEAN g_IsShutdown = FALSE;

/*
typedef struct {
	
    LARGE_INTEGER StartingLcn;
    LARGE_INTEGER BitmapSize;
    BYTE  Buffer[1];
	
} VOLUME_BITMAP_BUFFER, *PVOLUME_BITMAP_BUFFER;

typedef struct {
	
    LARGE_INTEGER StartingLcn;
	
} STARTING_LCN_INPUT_BUFFER, *PSTARTING_LCN_INPUT_BUFFER;
*/

#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

typedef struct _PAIR
{
	ULONGLONG	orgIndex;	// 原始扇区地址
	ULONGLONG	mapIndex;		// 重定向后的地址
} PAIR, *PPAIR;


typedef struct _FILTER_DEVICE_EXTENSION
{
	// 是否在保护状态
	BOOL					Protect;
	//此卷对应的保护系统使用的读写队列
	LIST_ENTRY				list_head;
	//此卷对应的保护系统使用的队列锁
	KSPIN_LOCK				list_lock;
	//此卷对应的保护系统使用的队列同步事件
	KEVENT					ReqEvent;
	//此卷对应的保护系统使用的读写线程之线程ID
	PVOID					thread_read_write;
	CLIENT_ID				thread_read_write_id;

	// 回收线程
//	PVOID					thread_reclaim;	
//	CLIENT_ID				thread_reclaim_id;
	//保护系统使用的读写线程之终止标志
	BOOLEAN					terminate_thread;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


typedef struct _DP_BITMAP_
{
	ULONG		bitMapSize;
	// 每个区域有多少位
    ULONG		regionSize;
	// 每个区域占多少byte
	ULONG		regionBytes;
	// 整个bitmap总共有多少个区域
    ULONG		regionNumber;
	// 指向bitmap存储空间的指针
    UCHAR **	buffer; 
} DP_BITMAP, * PDP_BITMAP;


typedef struct _VOLUME_INFO
{
	BOOLEAN		isValid;			// 是否有效
	BOOLEAN		isProtect;			// 是否保护此卷
//	BOOLEAN		isDiskFull;			// 磁盘是否已满

	WCHAR		volume;				// 卷标

	ULONG		diskNumber;			// 此卷所在磁盘号

	DWORD		partitionNumber;	// 分区号
	BYTE		partitionType;		// 的
	BOOLEAN		bootIndicator;		// 是否启动分区

	LONGLONG	physicalStartingOffset;		// 分区在磁盘上的偏移，也就是起始地址

	LONGLONG	bytesTotal;			// 分区总大小，以byte为单位
	ULONG		bytesPerSector;		// 每个扇区的大小
	ULONG		bytesPerCluster;	// 每簇大小
	ULONGLONG	firstDataSector;	// 第一个数据区的开始地址，即位图上第一个扇区的开始地址，NTFS固定为0，FAT专用

	
	//此卷设备对应的过滤设备之下部设备对象
	PDEVICE_OBJECT	LowerDevObj;

	// 此卷逻辑上有多少个扇区
	ULONGLONG		sectorCount;
	
	// 标记空闲写 空闲写bit为0, 初始化时同bitMap_OR
	PDP_BITMAP		bitMap_Free;
	// 标记此扇区是否已重定向
	PDP_BITMAP		bitMap_Redirect;
	// 直接放过写的扇区(force write)如pagefile.sys hiberfil.sys, 位图比实际逻辑位图小一点即可
	PDP_BITMAP		bitMap_Protect;
	
	// 上次扫描的目标写扇区位置
	ULONGLONG		last_scan_index;
	
	// 重定向映射
// 定
	RTL_GENERIC_TABLE	redirectMap;
	
	// Lock for redirectMap and bitmaps
	ERESOURCE			lock;

} VOLUME_INFO, *PVOLUME_INFO;


PROTECT_INFO	_protectInfo = {MAGIC_CHAR, 0, 0, 0};
// 卷保护全局信息
VOLUME_INFO		_volumeList[MAX_DOS_DRIVES];

// 硬盘下部设备对象信息
PDEVICE_OBJECT	_lowerDeviceObject[MAX_DOS_DRIVES];

PFILTER_DEVICE_EXTENSION	_deviceExtension = NULL;

ULONG	_processNameOfffset = 0;
ULONG	_systemProcessId = 0;

// 拒绝系统补丁
BOOL	_sysPatchEnable = FALSE;


// 锁定进程ID可以穿透diskflt.sys修改数据
ULONG	_lockProcessId = -1;

// 位图一个区域大小2M
#define SLOT_SIZE	(1024 * 1024 * 2)

void DPBitMap_Free(DP_BITMAP * bitmap)
{
	//释放bitmap
	DWORD i = 0;
	
	if (NULL != bitmap)
	{
		if (NULL != bitmap->buffer)
		{
			for (i = 0; i < bitmap->regionNumber; i++)
			{
				if (NULL != bitmap->buffer[i])
				{
					//从最底层的块开始释放，所有块都要查询一次				
					__free(bitmap->buffer[i]);
				}
			}
			//释放空间指针
			__free(bitmap->buffer);
		}	
		//释放bitmap结构
		__free(bitmap);
	}
}

NTSTATUS
DPBitMap_Create(
	DP_BITMAP ** bitmap,	// 位图输出指针
	ULONGLONG bitMapSize,	// 位图中有多少个位
	ULONGLONG regionBytes	// 位图长度，分成N块，一块占多少byte
	)	
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	int		i = 0;
	DP_BITMAP *	myBitmap = NULL;

	//调用者负责使用此传入的参数，如下调用者等待此函数
	if (NULL == bitmap || 0 == regionBytes  || 0 == bitMapSize)
	{
		return status;
	}
	__try
	{
		*bitmap = NULL;
		//分配一个bitmap结构，分配成功意味着要占用内存，此结构相当于一个bitmap的handle	
		if (NULL == (myBitmap = (DP_BITMAP *)__malloc(sizeof(DP_BITMAP))))
		{
			__leave;
		}
		
		//清零结构
		memset(myBitmap, 0, sizeof(DP_BITMAP));

		myBitmap->regionSize = regionBytes * 8;
		if (myBitmap->regionSize > bitMapSize)
		{
			myBitmap->regionSize = bitMapSize / 2;
		}
		//根据参数对结构中的成员进行赋值
		myBitmap->bitMapSize = bitMapSize;
		myBitmap->regionBytes = (myBitmap->regionSize / 8) + sizeof(int);

		myBitmap->regionNumber = bitMapSize / myBitmap->regionSize;
		if (bitMapSize % myBitmap->regionSize)
		{
			myBitmap->regionNumber++;
		}

		//分配regionNumber个指向region的指针，这是一个指针数组
		if (NULL == (myBitmap->buffer = (UCHAR **)__malloc(sizeof(UCHAR *) * myBitmap->regionNumber)))
		{
			__leave;
		}
		//清零指针数组
		memset(myBitmap->buffer, 0, sizeof(UCHAR *) * myBitmap->regionNumber);
		*bitmap = myBitmap;
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))
	{
		if (NULL != myBitmap)
		{
			DPBitMap_Free(myBitmap);
		}
		*bitmap = NULL;
	}
	return status;
}


ULONGLONG
DPBitMap_FindNext(DP_BITMAP * bitMap, ULONGLONG startIndex, BOOL set)
{
	LONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;
	
	// 计算slot
	for (slot = startIndex / bitMap->regionSize; slot < bitMap->regionNumber; slot++)
	{
		ULONGLONG	max = 0;
		
		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				startIndex = (slot + 1) * bitMap->regionSize;
				continue;
			}
			else
			{
				return startIndex;
			}
		}
		
		for (max = min((slot + 1) * bitMap->regionSize, bitMap->bitMapSize); 
		startIndex < max; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 判断是否一个双字全为1或全为0

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 整块跳过
				startIndex += 32 - (sIndex % 32);
				continue;
			}
			
			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}	
			startIndex++;
		}
	}
	
	return -1;
}

NTSTATUS
DPBitMap_Set(DP_BITMAP * bitMap, ULONGLONG index, BOOL set)
{
	ULONG	slot = index / bitMap->regionSize;
	if (slot > (bitMap->regionNumber-1))
	{
		dprintf("DPBitMap_Set out of range slot %d\n", slot);
		return STATUS_UNSUCCESSFUL;
	}

	if (!bitMap->buffer[slot])
	{
		if (!set)
		{
			return STATUS_SUCCESS;
		}
		bitMap->buffer[slot] = (UCHAR *)__malloc(bitMap->regionBytes);
		if (!bitMap->buffer[slot])
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		memset(bitMap->buffer[slot], 0, bitMap->regionBytes);
	}
	
	index %= bitMap->regionSize;
	
    if (set)
        ((ULONG *)bitMap->buffer[slot])[index / 32] |= (1 << (index % 32));
    else
        ((ULONG *)bitMap->buffer[slot])[index / 32] &= ~(1 << (index % 32));

	return STATUS_SUCCESS;
}

BOOL
DPBitMap_Test(DP_BITMAP * bitMap, ULONGLONG index)
{
	ULONG	slot = index / bitMap->regionSize;
	if (slot > (bitMap->regionNumber-1))
	{
		dprintf("DPBitMap_Test out of range slot %d\n", slot);
		return FALSE;
	}
	// 还没有分配
	if (!bitMap->buffer[slot])
	{
		return FALSE;
	}

	index %= bitMap->regionSize;	

	return (((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32)) ? TRUE : FALSE);
}

NTSTATUS
ksleep(ULONG microSecond)
{
	LARGE_INTEGER	timeout = RtlConvertLongToLargeInteger(-10000 * microSecond);
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	return STATUS_SUCCESS;
}

/*
void cls()
{
	UCHAR SpareColor = 4;   // blue
	UCHAR BackColor = 3;    // green
	UCHAR TextColor = 15;   // white

	if (InbvIsBootDriverInstalled())
	{
		InbvAcquireDisplayOwnership();

		InbvResetDisplay();

		// c:\boot.ini 如果在启动菜单加了 /noguiboot, 就就不显示load的
		// 打印时也显示windows时logo效果

		//InbvSolidColorFill(0, 0, 639, 479, SpareColor);         // blue, 640x480

		InbvSetTextColor(TextColor);

	//	InbvInstallDisplayStringFilter(NULL);
		InbvEnableDisplayString(TRUE);
	}
}

ULONG
kprintf(const char *fmt, ...) 
{
	va_list args;
	int ret;
	char buff[1024];

	va_start(args, fmt);
	ret = _vsnprintf(buff, sizeof(buff), fmt, args);
	va_end(args);

	InbvDisplayString(buff);

	return ret;
}

*/
PVOID getFileClusterList(HANDLE hFile)
{
	
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER StartVcn;
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs;
	ULONG ulOutPutSize = 0;
	ULONG uCounts = 200;
	
	StartVcn.QuadPart=0;
	ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts* sizeof(pVcnPairs->Extents)+sizeof(LARGE_INTEGER);
	pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
	if(pVcnPairs == NULL)
	{
		return NULL;
	}
	
	while( (status = ZwFsControlFile( hFile,NULL, NULL, 0, &iosb,
		FSCTL_GET_RETRIEVAL_POINTERS,
		&StartVcn, sizeof(LARGE_INTEGER),
		pVcnPairs, ulOutPutSize ) ) == STATUS_BUFFER_OVERFLOW)
	{
		uCounts+=200;
		ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts* sizeof(pVcnPairs->Extents)+sizeof(LARGE_INTEGER);
		__free(pVcnPairs);
		
		pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
		if(pVcnPairs == NULL)
		{
			dprintf("__malloc %d bytes faild", ulOutPutSize);
			return FALSE;
		}
	}
	
	if(!NT_SUCCESS(status))
	{
		dprintf(" --ZwFsControlFile --->> FSCTL_GET_RETRIEVAL_POINTERS  failed");
		dprintf(" --status %x",status);
		__free(pVcnPairs);
		return NULL;
	}
	
	return pVcnPairs;
}



//--------------------------------------------------------------------------------------
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{    
    NTSTATUS ns;
    ULONG RetSize, Size = 0x1000;
    PVOID Info;
	
    while (1) 
    {    
        if ((Info = __malloc(Size)) == NULL) 
        {
            dprintf("__malloc() fails\n");
            return NULL;
        }
		
        ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            __free(Info);
            Size = RetSize + 0x100;
        }
        else
		{
            break;    
		}
    }
	
    if (!NT_SUCCESS(ns))
    {
        dprintf("ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);
		
        if (Info)
		{
            __free(Info);
		}
		
        return NULL;
    }
	
    return Info;
}

// Fixed SYSTEM_HANDLE_INFORMATION definition for x64/x86 compatibility
#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_FIXED {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_FIXED, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_FIXED;

typedef struct _SYSTEM_HANDLE_INFORMATION_FIXED {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_FIXED Handles[1];
} SYSTEM_HANDLE_INFORMATION_FIXED, *PSYSTEM_HANDLE_INFORMATION_FIXED;

HANDLE searchFileHandle(PUNICODE_STRING fileName)
{
	NTSTATUS status;
	ULONG_PTR i;
	PVOID sysBuffer = NULL;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo;
	POBJECT_NAME_INFORMATION ObjectName;
	
	char ObjectNameBuf[1024];
	ULONG ReturnLen;
	HANDLE hPageFile ;
	
	ObjectName = (POBJECT_NAME_INFORMATION)ObjectNameBuf;
	ObjectName->Name.MaximumLength = 510;
	
	sysBuffer = GetSysInf((SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation);

	if(sysBuffer == NULL)
	{
		dprintf("DiskGetHandleList error\n");
		return (HANDLE)-1;
	}

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)sysBuffer;
	
	for (i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
		if(pHandleInfo->Handles[i].UniqueProcessId == (ULONG_PTR)_systemProcessId)
		{
			status = ZwQueryObject((HANDLE)pHandleInfo->Handles[i].HandleValue, ObjectNameInfo, 
				ObjectName, sizeof(ObjectNameBuf), &ReturnLen);

			if(status == 0 && (RtlEqualUnicodeString(&ObjectName->Name, fileName, TRUE) == TRUE))
			{
				hPageFile = (HANDLE)pHandleInfo->Handles[i].HandleValue;
				__free(sysBuffer);
				return hPageFile;
			}
		}
	}
	
	__free(sysBuffer);

    return (HANDLE)-1;
}
//--------------------------------------------------------------------------------------
NTSTATUS
RtlAllocateUnicodeString(PUNICODE_STRING us, ULONG maxLength)
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	
    ULONG ulMaximumLength = maxLength;
	
    if (maxLength > 0)
    {
        if ((us->Buffer = (PWSTR)__malloc(ulMaximumLength)) != NULL)
		{
			RtlZeroMemory(us->Buffer, ulMaximumLength);
			
			us->Length = 0;
			us->MaximumLength = (USHORT)maxLength;
			
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_NO_MEMORY;
		}
    }
	
    return status;
}


NTSTATUS
flt_getFileHandleReadOnly(PHANDLE fileHandle, PUNICODE_STRING fileName)
{
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
		
	InitializeObjectAttributes(&oa,
		fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	return ZwCreateFile(fileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
}

NTSTATUS
flt_getFatFirstSectorOffset(HANDLE fileHandle, PULONGLONG firstDataSector)
{
	NTSTATUS	status;
	IO_STATUS_BLOCK	IoStatusBlock;
	FAT_LBR		fatLBR = { 0 };

	LARGE_INTEGER	pos;
	pos.QuadPart = 0;

	if (!firstDataSector)
	{
		return STATUS_NOT_FOUND;
	}

	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &IoStatusBlock, &fatLBR, sizeof(fatLBR), &pos, NULL);
	
	if (NT_SUCCESS(status) && sizeof(FAT_LBR) == IoStatusBlock.Information)
	{
		DWORD dwRootDirSectors	= 0;
		DWORD dwFATSz			= 0;
	
		// Validate jump instruction to boot code. This field has two
		// allowed forms: 
		// jmpBoot[0] = 0xEB, jmpBoot[1] = 0x??, jmpBoot[2] = 0x90 
		// and
		// jmpBoot[0] = 0xE9, jmpBoot[1] = 0x??, jmpBoot[2] = 0x??
		// 0x?? indicates that any 8-bit value is allowed in that byte.
		// JmpBoot[0] = 0xEB is the more frequently used format.
		
		if(( fatLBR.wTrailSig       != 0xAA55 ) ||
			( ( fatLBR.pbyJmpBoot[ 0 ] != 0xEB || 
			fatLBR.pbyJmpBoot[ 2 ] != 0x90 ) &&
			( fatLBR.pbyJmpBoot[ 0 ] != 0xE9 ) ) )
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}
		
		// Compute first sector offset for the FAT volumes:		


		// First, we determine the count of sectors occupied by the
		// root directory. Note that on a FAT32 volume the BPB_RootEntCnt
		// value is always 0, so on a FAT32 volume dwRootDirSectors is
		// always 0. The 32 in the above is the size of one FAT directory
		// entry in bytes. Note also that this computation rounds up.
		
		dwRootDirSectors = 
			( ( ( fatLBR.bpb.wRootEntCnt * 32 ) + 
			( fatLBR.bpb.wBytsPerSec - 1  ) ) / 
			fatLBR.bpb.wBytsPerSec );
		
		// The start of the data region, the first sector of cluster 2,
		// is computed as follows:
		
		dwFATSz = fatLBR.bpb.wFATSz16;		
		if( !dwFATSz )
			dwFATSz = fatLBR.ebpb32.dwFATSz32;
		

		if( !dwFATSz )
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}
		

		// 得到第一数据区的第一扇区位置
		*firstDataSector = 
			( fatLBR.bpb.wRsvdSecCnt + 
			( fatLBR.bpb.byNumFATs * dwFATSz ) + 
			dwRootDirSectors );		
		}

	status = STATUS_SUCCESS;
__faild:

	return status;
}

/*
	获取卷信息
	diskNumber
	LowerDevObj

	partitionNumber
	partitionType
	physicalStartingOffset
	bootIndicator
	firstSectorOffset
	bytesPerSector
	bytesPerCluster
	bytesTotal
*/
NTSTATUS
flt_getVolumeInfo(WCHAR volume, PVOLUME_INFO info)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	
	WCHAR	volumeDosName[50];

	swprintf(volumeDosName, L"\\??\\%c:", volume);
	
	RtlInitUnicodeString(&fileName, volumeDosName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("open %wZ ret 0x%x\n", &fileName, status);

	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK				ioBlock;
		// PARTITION_INFORMATION		partitionInfo; // Removed for GPT
		FILE_FS_SIZE_INFORMATION	sizeoInfo;

		ULONG	buff[256];
		PVOLUME_DISK_EXTENTS		diskExtents;

		diskExtents = (PVOLUME_DISK_EXTENTS)buff;

		// 得到此卷所在磁盘号，可能是软盘卷
		status = ZwDeviceIoControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 
			NULL, 
			0, 
			diskExtents, 
			sizeof(buff)
			);

		if (NT_SUCCESS(status))
		{
			info->diskNumber = diskExtents->Extents[0].DiskNumber;
			// 得到下部设备
			info->LowerDevObj = _lowerDeviceObject[info->diskNumber];
		}

		// 得到此卷第一个分区，即所在硬盘上的分区偏移信息

		// GPT/Windows 10/11 Support
		PARTITION_INFORMATION_EX partitionInfoEx;

		status = ZwDeviceIoControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			IOCTL_DISK_GET_PARTITION_INFO_EX, 
			NULL, 
			0, 
			&partitionInfoEx, 
			sizeof(partitionInfoEx)
			);


		if (NT_SUCCESS(status))
		{
			if (partitionInfoEx.PartitionStyle != PARTITION_STYLE_GPT)
			{
				DiskFltLog("GetPartitionInfoEx: Not GPT! Style=%d\n", partitionInfoEx.PartitionStyle);
				ZwClose(fileHandle);
				return STATUS_NOT_SUPPORTED;
			}

			info->partitionNumber = partitionInfoEx.PartitionNumber;
			// info->partitionType = 0; 
			info->physicalStartingOffset = partitionInfoEx.StartingOffset.QuadPart;
			info->bootIndicator = FALSE;
			info->firstDataSector = 0;

			DiskFltLog("GPT Success: Offset=0x%I64x, Len=0x%I64x\n", info->physicalStartingOffset, partitionInfoEx.PartitionLength.QuadPart);
			
			// FAT分区需要读取LBR, 得到第一扇区偏移
 			// FAT check
			// if (0)
			{
				status = flt_getFatFirstSectorOffset(fileHandle, &info->firstDataSector);
			}
		}

		// 得到簇，即每簇大小
		status = ZwQueryVolumeInformationFile(fileHandle,
			&IoStatusBlock,
			&sizeoInfo,
			sizeof(sizeoInfo),
			FileFsSizeInformation);

		if (NT_SUCCESS(status))
		{
			info->bytesPerSector = sizeoInfo.BytesPerSector;
			info->bytesPerCluster = sizeoInfo.BytesPerSector * sizeoInfo.SectorsPerAllocationUnit;

			// 如果得到的磁盘大小为0，则使用LBR中的信息
			// GPT Length
			info->bytesTotal = partitionInfoEx.PartitionLength.QuadPart;
		}
		
		ZwClose(fileHandle);
	}

	return status;
}

/*
	获取位图信息
	diskNumber
	LowerDevObj

	partitionNumber
	partitionType
	physicalStartingOffset
	bootIndicator
	firstSectorOffset
	bytesPerSector
	bytesPerCluster
	bytesTotal
*/
NTSTATUS
flt_getVolumeBitmapInfo(WCHAR volume, PVOLUME_BITMAP_BUFFER * bitMap)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	
	WCHAR	volumeDosName[10];
	
	if (NULL == bitMap)
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	swprintf(volumeDosName, L"\\??\\%c:", volume);
	
	RtlInitUnicodeString(&fileName, volumeDosName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("Open %wZ ret 0x%x\n", &fileName, status);
	
	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER	info;
		STARTING_LCN_INPUT_BUFFER StartingLCN;

		ULONG	BitmapSize = 0;
		
		StartingLCN.StartingLcn.QuadPart = 0;
		
		
		/*
		// 此卷, 在得到位图前
		status = ZwFsControlFile( fileHandle, 
					NULL, 
					NULL, 
					NULL, 
					&ioBlock, 
					FSCTL_LOCK_VOLUME, 
					NULL, 0, NULL, 0
					);
		
		dprintf("FSCTL_LOCK_VOLUME = 0x%x\n", status);
		
		*/

		do 
		{
			BitmapSize += 10240;
			
			info = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			// 内存不足
			if (!info)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			
			status = ZwFsControlFile( fileHandle, 
				NULL, 
				NULL, 
				NULL, 
				&ioBlock, 
				FSCTL_GET_VOLUME_BITMAP, 
				&StartingLCN,
				sizeof (StartingLCN),
				info, 
				BitmapSize
				);

			if (STATUS_BUFFER_OVERFLOW == status)
			{
				__free(info);
			}
			
		} while(STATUS_BUFFER_OVERFLOW == status);
		
		dprintf("FSCTL_GET_VOLUME_BITMAP ret 0x%x\n", status);

		if (!NT_SUCCESS(status))
		{
			if (info)
			{
				__free(info);
			}
			*bitMap = NULL;
		}
		else
		{
			dprintf("%c: bitMapinfo (%d / %d) cluster = %I64d\n", volume, ioBlock.Information, BitmapSize, info->BitmapSize.QuadPart);

			*bitMap = info;
		}

		
		/*
		status = ZwFsControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			FSCTL_UNLOCK_VOLUME, 
			NULL, 0, NULL, 0
				);

		dprintf("FSCTL_UNLOCK_VOLUME ret 0x%x\n", status);
		*/
		

		ZwClose(fileHandle);
	}
	
	return status;
}

NTSTATUS
flt_SendToNextDriver(
				   IN	PDEVICE_OBJECT	TgtDevObj,
				   IN	PIRP			Irp
				   )
{	
	//获取当前irp stack
	IoSkipCurrentIrpStackLocation(Irp);
	//获取目标设备对象并复制irp
	return IoCallDriver(TgtDevObj, Irp);
}

NTSTATUS
flt_CompleteRequest(
				  IN	PIRP			Irp,
				  IN	NTSTATUS		Status,
				  IN	CCHAR			Priority
				  )
{	
	//将IRP的io状态设置为传入的参数
	Irp->IoStatus.Status = Status;
	//调用IoCompleteRequest来完成Irp
	IoCompleteRequest(Irp, Priority);
	return STATUS_SUCCESS;
}


RTL_GENERIC_COMPARE_RESULTS
NTAPI CompareRoutine(
					 struct _RTL_GENERIC_TABLE *Table,
					 PVOID FirstStruct,
					 PVOID SecondStruct
					 )
{
	PPAIR first = (PPAIR) FirstStruct;
	PPAIR second = (PPAIR) SecondStruct;
	
	UNREFERENCED_PARAMETER(Table);

	if (first->orgIndex < second->orgIndex)
		return GenericLessThan;
	else if (first->orgIndex > second->orgIndex)
		return GenericGreaterThan;
	else
		return GenericEqual;
}

PVOID NTAPI AllocateRoutine (
							 struct _RTL_GENERIC_TABLE *Table,
							 LONG ByteSize
							 )
{
	UNREFERENCED_PARAMETER(Table);

	return __malloc(ByteSize);
}

VOID
NTAPI FreeRoutine (
				   struct _RTL_GENERIC_TABLE *Table,
				   PVOID Buffer
				   )
{
	
	UNREFERENCED_PARAMETER(Table);
	
	__free(Buffer);
}

BOOL bitmap_test (ULONG * bitMap, ULONGLONG index)
{
	//	return ((BYTE *)BitmapDetail)[Cluster / 8] & (1 << (Cluster % 8));
	return ((bitMap[index / 32] & (1 << (index % 32))) ? TRUE : FALSE);   
}

void bitmap_set (ULONG * bitMap, ULONGLONG index, BOOL Used)
{
    if (Used)
        bitMap[index / 32] |= (1 << (index % 32));
    else
        bitMap[index / 32] &= ~(1 << (index % 32));
}


// 位图中为1的扇区直接读写文件的扇区
NTSTATUS
setBitmapDirectRWFile(WCHAR volume, WCHAR * path, PDP_BITMAP bitmap)
{
	NTSTATUS	status;
	HANDLE	linkHandle = NULL;
	HANDLE	linkHandle1 = NULL;
	OBJECT_ATTRIBUTES	oa;
	ULONG	ret;
	BOOLEAN	needClose = FALSE;
	BOOLEAN	needFree = FALSE;
	UNICODE_STRING	symbol;
	UNICODE_STRING	target;
	WCHAR	tempBuffer[256];
	
	PVOID lpFileObject = NULL;
	HANDLE fileHandle = (HANDLE)-1;
	
	ULONG   Cls, r;
	LARGE_INTEGER PrevVCN, Lcn;	
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs = NULL;

	PEPROCESS	eProcess = NULL;
	if (!NT_SUCCESS( PsLookupProcessByProcessId((PVOID)_systemProcessId, &eProcess)))
	{
		goto __faild;
	}

	// ObDereferenceObject(eProcess); // Moved to end of function
	// Attach to system process
	KeAttachProcess(eProcess);

	swprintf(tempBuffer, L"\\??\\%c:%ls", volume, path);

	RtlInitUnicodeString(&target, tempBuffer);

	// 直接读失败，可以尝试从卷中读取

	status = flt_getFileHandleReadOnly(&fileHandle, &target);
	if (NT_SUCCESS(status))
	{
		needClose = TRUE;
	}
	// 如果拒绝访问，尝试从HANDLE中获取
	else if (STATUS_SHARING_VIOLATION == status)
	{
		dprintf("Try to open %wZ from handle list\n", &target);

		swprintf(tempBuffer, L"\\??\\%c:", volume);
		
		RtlInitUnicodeString(&symbol, tempBuffer);
		
		RtlAllocateUnicodeString(&target, 1024);

		needFree = TRUE;
		

		InitializeObjectAttributes(&oa,
			&symbol,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);
		
		// 将 \??\C: 映射为真实路径 \Device\HarddiskVolume1 之类的路径
		
		status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);
		
		if (!NT_SUCCESS(status))
		{
			dprintf("ZwOpenSymbolicLinkObject %wZ fail 0x%x\n", &symbol, status);
			goto __faild;
		}
		
		status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);
		
		if (!NT_SUCCESS(status))
		{
			dprintf("ZwQuerySymbolicLinkObject %wZ fail 0x%x\n", &symbol, status);
			goto __faild;
		}

		while (1)
		{
			// 判断是否查询到卷路径指向的卷 symbolicLink
			InitializeObjectAttributes(&oa,
				&target,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);
			
			// 将 \??\C: 映射为真实路径 \Device\HarddiskVolume1 之类的路径
			
			status = ZwOpenSymbolicLinkObject(&linkHandle1, GENERIC_READ, &oa);
			
			// 如果是硬盘卷，有指定的symbollink
			if (NT_SUCCESS(status))
			{
				dprintf("SymbolicLink > SymbolicLink\n");
				ZwClose(linkHandle);
				linkHandle = linkHandle1;
				status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);
				if (!NT_SUCCESS(status))
				{
					goto __faild;
				}			
			}
			else
			{
				break;
			}
		}
		
		// 合并路径
		
		RtlAppendUnicodeToString(&target, path);
	
		fileHandle = searchFileHandle(&target);

		needClose = FALSE;
	}
	
	if((HANDLE)-1 == fileHandle)
	{
		dprintf("getFileHandle %wZ fail\n", &target);
		goto __faild;
	}
	
	pVcnPairs = getFileClusterList(fileHandle);
	
	if(NULL == pVcnPairs)
	{
		dprintf("getFileClusterList fail\n");
		goto __faild;
	}
	
	PrevVCN = pVcnPairs->StartingVcn;
	for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONG	CnCount;
		Lcn = pVcnPairs->Extents[r].Lcn;
		
		for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
		CnCount; CnCount--, Cls++, Lcn.QuadPart++) 
		{
			// 分配位图
			DPBitMap_Set(bitmap, Lcn.QuadPart, TRUE);
		}
		
		PrevVCN = pVcnPairs->Extents[r].NextVcn;
	}

	dprintf("set %wZ force RW bit map success\n", &target);
	DiskFltLog("setBitmapDirectRWFile: %wZ success. Last LCN=%I64d\n", &target, Lcn.QuadPart);
	
	__free_Safe(pVcnPairs);
	
__faild:
	
	if (eProcess)
	{
		KeDetachProcess();
		ObDereferenceObject(eProcess);
		eProcess = NULL;
	}
	
	if (linkHandle)
		ZwClose(linkHandle);

	if (needClose && ((HANDLE)-1 != fileHandle))
		ZwClose(fileHandle);

	if (needFree)
		__free_Safe(target.Buffer);
	
	return status;
}


// from wdk wdm.h
#define SL_KEY_SPECIFIED                0x01
#define SL_OVERRIDE_VERIFY_VOLUME       0x02
#define SL_WRITE_THROUGH                0x04
#define SL_FT_SEQUENTIAL_WRITE          0x08
#define SL_FORCE_DIRECT_WRITE           0x10


NTSTATUS 
FltReadWriteSectorsCompletion( 
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP Irp, 
	IN PVOID Context 
	) 
	/*++ 
	Routine Description: 
	A completion routine for use when calling the lower device objects to 
	which our filter deviceobject is attached. 

	Arguments: 

	DeviceObject - Pointer to deviceobject 
	Irp        - Pointer to a PnP Irp. 
	Context    - NULL or PKEVENT 
	Return Value: 

	NT Status is returned. 

	--*/ 
{ 
    PMDL    mdl; 
	
    UNREFERENCED_PARAMETER(DeviceObject); 
	
    // 
    // Free resources 
    // 
	
	/*
    if (Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_DEALLOCATE_BUFFER)) { 
        __free(Irp->AssociatedIrp.SystemBuffer); 
    } 
	*/
	
	if (Irp->IoStatus.Status)
	{
		DbgPrint("!!!!!!!!!!Read Or Write HD Error Code====0x%x\n", Irp->IoStatus.Status);
	}
	/*
	如果为的 IRP 的处理层不知道怎么处理 IRP
	怎么究竟需要 CompleteRoutine 使用时 IoFreeIrp()释放的 IRP
	STATUS_MORE_PROCESSING_REQUIRED的数据需要注意，
	CompleteRoutine返回的 IRP 已经被头部
	的任何关于 IRP 的部的处理重的 BSOD 的
	*/
    while (Irp->MdlAddress) { 
        mdl = Irp->MdlAddress; 
        Irp->MdlAddress = mdl->Next; 
        MmUnlockPages(mdl); 
        IoFreeMdl(mdl); 
    } 
	
    if (Irp->PendingReturned && (Context != NULL)) { 
        *Irp->UserIosb = Irp->IoStatus; 
        KeSetEvent((PKEVENT) Context, IO_DISK_INCREMENT, FALSE); 
    } 
	
    IoFreeIrp(Irp); 
	
    // 
    // Don't touch irp any more 
    // 
    return STATUS_MORE_PROCESSING_REQUIRED; 
} 


NTSTATUS 
fastFsdRequest( 
	IN PDEVICE_OBJECT DeviceObject, 
	ULONG majorFunction,
	IN LONGLONG ByteOffset,
	OUT PVOID Buffer, 
	IN ULONG Length, 			    
	IN BOOLEAN Wait,
    IN ULONG IrpFlags
	)
{ 
    PIRP                irp; 
    IO_STATUS_BLOCK        iosb; 
    KEVENT                event; 
    NTSTATUS            status; 
	
	//
    irp = IoBuildAsynchronousFsdRequest(majorFunction, DeviceObject, 
        Buffer, Length, (PLARGE_INTEGER) &ByteOffset, &iosb); 
    if (!irp) { 
        return STATUS_INSUFFICIENT_RESOURCES; 
    } 

	// vista 下直接穿过写，绕过了保护, 需要检查IRP的FLAGS是否有SL_FORCE_DIRECT_WRITE标志
	/*
	If the SL_FORCE_DIRECT_WRITE flag is set, kernel-mode drivers can write to volume areas that they 
	normally cannot write to because of direct write blocking. Direct write blocking was implemented for 
	security reasons in Windows Vista and later operating systems. This flag is checked both at the file 
	system layer and storage stack layer. For more 
	information about direct write blocking, see Blocking Direct Write Operations to Volumes and Disks. 
	The SL_FORCE_DIRECT_WRITE flag is available in Windows Vista and later versions of Windows. 
	http://msdn.microsoft.com/en-us/library/ms795960.aspx
	*/
	if (IRP_MJ_WRITE == majorFunction)
	{
		IoGetNextIrpStackLocation(irp)->Flags |= SL_FORCE_DIRECT_WRITE;
	}

    // Propagate Paging I/O flags to avoid deadlocks
    if (IrpFlags & IRP_PAGING_IO)
    {
        irp->Flags |= IRP_PAGING_IO;
    }
    if (IrpFlags & IRP_SYNCHRONOUS_PAGING_IO)
    {
        irp->Flags |= IRP_SYNCHRONOUS_PAGING_IO;
    }
	
    if (Wait) { 
        KeInitializeEvent(&event, NotificationEvent, FALSE); 
        IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion, 
            &event, TRUE, TRUE, TRUE); 
	
        status = IoCallDriver(DeviceObject, irp); 
        if (STATUS_PENDING == status) { 
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL); 
            status = iosb.Status; 
        } 
    } else { 
        IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion, 
            NULL, TRUE, TRUE, TRUE); 
        irp->UserIosb = NULL; 
        status = IoCallDriver(DeviceObject, irp); 
    } 
	
	if (!NT_SUCCESS(status))
	{
		dprintf("IoCallDriver 0x%x fail 0x%x\n", majorFunction, status);
	}
    return status; 
} 

__inline
BOOL isSectorProtect (PVOLUME_INFO volumeInfo, ULONGLONG index)
{
	ULONGLONG startSector = volumeInfo->physicalStartingOffset / volumeInfo->bytesPerSector;
	ULONGLONG relIndex;

	if (index < startSector)
	{
		return FALSE;
	}

	relIndex = index - startSector;

	if (DPBitMap_Test(volumeInfo->bitMap_Protect,
		(relIndex / (volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector))))
	{
		return TRUE;
	}
	
	return FALSE;
}

// 获取真实要写入的扇区
ULONGLONG
getRealSectorForRead(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = orgIndex;
	ULONGLONG	startSector = volumeInfo->physicalStartingOffset / volumeInfo->bytesPerSector;
	ULONGLONG	relIndex;

	if (orgIndex < startSector)
	{
		return orgIndex;
	}

	relIndex = orgIndex - startSector;

	// 此扇区是否可以被直接操作
// 是否直接写
	if (isSectorProtect(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否已经重定向
	if (DPBitMap_Test(volumeInfo->bitMap_Redirect, relIndex))
	{
		// 找到重定向的扇区，返回它
		PAIR *	result;
		PAIR	pair;
		pair.orgIndex = orgIndex;

		ExAcquireResourceSharedLite(&volumeInfo->lock, TRUE);
		result = (PAIR *)RtlLookupElementGenericTable(&volumeInfo->redirectMap, &pair);

		if (result)
		{
			mapIndex = result->mapIndex;
		}
		ExReleaseResourceLite(&volumeInfo->lock);
	}
	
	return mapIndex;
}


// 获取真实要写入的扇区
ULONGLONG
getRealSectorForWrite(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = -1;
	ULONGLONG	startSector = volumeInfo->physicalStartingOffset / volumeInfo->bytesPerSector;
	ULONGLONG	relIndex;
	ULONGLONG	bitMapIndex;

	if (orgIndex < startSector)
	{
		return orgIndex;
	}

	relIndex = orgIndex - startSector;

	// 此扇区是否可以直接写
	if (isSectorProtect(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否已经重定向
	if (DPBitMap_Test(volumeInfo->bitMap_Redirect, relIndex))
	{
		// 找到重定向的扇区，返回它
		PAIR *	result;
		PAIR	pair;
		pair.orgIndex = orgIndex;
		
		ExAcquireResourceSharedLite(&volumeInfo->lock, TRUE);
		result = (PAIR *)RtlLookupElementGenericTable(&volumeInfo->redirectMap, &pair);
		
		if (result)
		{
			mapIndex = result->mapIndex;
		}
		ExReleaseResourceLite(&volumeInfo->lock);
	}
	else
	{
		// 查找下一个空闲的可用扇区
		bitMapIndex = DPBitMap_FindNext(volumeInfo->bitMap_Free, volumeInfo->last_scan_index, FALSE);

		if (bitMapIndex != -1)
		{
			// lastScan = 当前得到的扇区 + 1
			volumeInfo->last_scan_index = bitMapIndex + 1;

			// 标记为空闲写
			DPBitMap_Set(volumeInfo->bitMap_Free, bitMapIndex, TRUE);
			
			// 标记此扇区已被重定向(orgIndex)
			DPBitMap_Set(volumeInfo->bitMap_Redirect, relIndex, TRUE);
			
			// 加入重定向列表
			{
				PAIR	pair;
				pair.orgIndex = orgIndex;
				pair.mapIndex = bitMapIndex + startSector;				
				ExAcquireResourceExclusiveLite(&volumeInfo->lock, TRUE);
				RtlInsertElementGenericTable(&volumeInfo->redirectMap, &pair, sizeof(PAIR), NULL);
				ExReleaseResourceLite(&volumeInfo->lock);
				
				mapIndex = pair.mapIndex;
			}
		}
	}

	return mapIndex;
}

// ģ的
NTSTATUS
handle_disk_request(
	PVOLUME_INFO volumeInfo,
	ULONG majorFunction,
	ULONGLONG logicOffset,  
	void * buff,
	ULONG length,
    ULONG IrpFlags)
{
	NTSTATUS	status;
	
	// 当前的偏移
	ULONGLONG	physicalOffset = 0;
	ULONGLONG	sectorIndex;
	ULONGLONG	realIndex;
	ULONG		bytesPerSector = volumeInfo->bytesPerSector;
	
	// 记录时为启动的扇区重定向
	BOOLEAN		isFirstBlock = TRUE;
	ULONGLONG	prevIndex = -1;
	ULONGLONG	prevOffset = -1;
	PVOID		prevBuffer = NULL;
	ULONG		totalProcessBytes = 0;

	// 卸载时要重的要的扇是否启动分区的一个区简单的, 接口速度
	while (length)
	{
		sectorIndex = logicOffset / bytesPerSector;	
		
		if (IRP_MJ_READ == majorFunction)
		{
			realIndex = getRealSectorForRead(volumeInfo, sectorIndex);
		}
		else
		{
			// 写时卸载是否的原时
			realIndex = getRealSectorForWrite(volumeInfo, sectorIndex);
		}
		
		// 盘不是时太的小时, 的硬的
		if (-1 == realIndex)
		{
			dprintf("no enough disk space\n");
			return STATUS_DISK_FULL;
		}
		
		physicalOffset = realIndex * bytesPerSector;

__reInit:		
		// 开始prevIndex
		if (isFirstBlock)
		{
			prevIndex = realIndex;
			prevOffset = physicalOffset;
			prevBuffer = buff;
			totalProcessBytes = bytesPerSector;
			
			isFirstBlock = FALSE;
			
			goto __next;
		}
		
		// 如果连续的，则合并
		if (prevIndex == (realIndex - 1))
		{
			prevIndex = realIndex;
			totalProcessBytes += bytesPerSector;
			goto __next;
		}
		// 的上次时要的扇, 的isFirstBlock
		else
		{
			isFirstBlock = TRUE;
			status = fastFsdRequest(volumeInfo->LowerDevObj, majorFunction, prevOffset, 
				prevBuffer, totalProcessBytes, TRUE, IrpFlags);

			// 初始的初始时
			goto __reInit;
		}
__next:		
		// 的下一页的也的已经
		if (bytesPerSector >= length)
		{
			status = fastFsdRequest(volumeInfo->LowerDevObj, majorFunction, prevOffset, 
				prevBuffer, totalProcessBytes, TRUE, IrpFlags);

			// 卸载顺序
			break;
		}
		
		// 时一时, 的剩时
		logicOffset += (ULONGLONG)bytesPerSector;
		buff = (char *)buff + bytesPerSector;
		length -= bytesPerSector;
	}
	
	return status;
}
  
//
// For backward compatibility with Windows NT 4.0 by Bruce Engle.
//
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY) MmGetSystemAddressForMdlPrettySafe(MDL)

PVOID
MmGetSystemAddressForMdlPrettySafe (
    PMDL Mdl
    )
{
    CSHORT  MdlMappingCanFail;
    PVOID   MappedSystemVa;

    MdlMappingCanFail = Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL;

    Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

    MappedSystemVa = MmGetSystemAddressForMdl(Mdl);

    if (MdlMappingCanFail == 0)
    {
        Mdl->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return MappedSystemVa;
}
#endif

/*
// 回收线程
VOID
flt_thread_reclaim (
	IN PVOID Context
	)
{
	ULONG	i = 0;
	ULONG	timeout = getTickCount();
	PFILTER_DEVICE_EXTENSION	device_extension = (PFILTER_DEVICE_EXTENSION)Context;

	while (!device_extension->terminate_thread)
	{
		if ((getTickCount() - timeout) > (1000 * 60))
		{
			for (i = 0; i < _countof(_volumeList); i++)
			{
				if (_volumeList[i].isProtect && _volumeList[i].isProtect && _volumeList[i].isDiskFull)
				{
					// 的
					reclaimDiskSpace(&_volumeList[i]);
				}
				
			}
			
			timeout = getTickCount();
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}
*/
VOID
flt_thread_read_write (
					   IN PVOID Context
					   )
{
	//NTSTATUS的返回值
	NTSTATUS					status = STATUS_SUCCESS;
	//清零指针数组设备的设备可扩展指南
	PFILTER_DEVICE_EXTENSION	device_extension = (PFILTER_DEVICE_EXTENSION)Context;
	//队列的
	PLIST_ENTRY			ReqEntry = NULL;
	//irp指针
	PIRP				Irp = NULL;
	//irp stack指南
	PIO_STACK_LOCATION	io_stack = NULL;
	//irp�а的ݵ�ַ
	PVOID				buffer = NULL;
	//irp�е的ݳ的
	ULONG				length = 0;
	//irp要时ƫ的
	LARGE_INTEGER		offset = { 0 };

	//irp要时ƫ的
	LARGE_INTEGER		cacheOffset = { 0 };

	

	//的̵߳的ȼ�
	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
	//时̵߳�ʵ分割�֣的ѭ时˳�
	for (;;)
	{	
		//�ȵȴ的ͬ记录的�抽象化�irp需要的�ǵ时߳̾͵ȴ时�ó�cpuʱ的߳�
		KeWaitForSingleObject(
			&device_extension->ReqEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
			);
		//的߳̽的�־的ô回收线程�ڲ时Լ时Լ�
		if (device_extension->terminate_thread)
		{
			//的�̵߳�Ψһ�˳�扇区
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		//从队列中取出一个请求，避免死锁冲突
		while (ReqEntry = ExInterlockedRemoveHeadList(
			&device_extension->list_head,
			&device_extension->list_lock
			))
		{
			PVOLUME_INFO	volumeInfo;

			void * newbuff = NULL;

			//�Ӷ时е时找到ʵ�ʵ�irp�ĵ�ַ
			Irp = CONTAINING_RECORD(ReqEntry, IRP, Tail.Overlay.ListEntry);

			//取消irp stack
			io_stack = IoGetCurrentIrpStackLocation(Irp);

			// 选择信息
			volumeInfo = &_volumeList[(ULONG)Irp->IoStatus.Pointer];

			if (IRP_MJ_READ == io_stack->MajorFunction)
			{
				//读取irp的时irp stack对应的参数为offset和length
				offset = io_stack->Parameters.Read.ByteOffset;
				length = io_stack->Parameters.Read.Length;
			}
			else if (IRP_MJ_WRITE == io_stack->MajorFunction)
			{
				//写入irp的时irp stack对应的参数为offset和length
				offset = io_stack->Parameters.Write.ByteOffset;
				length = io_stack->Parameters.Write.Length;				
			}
			else
			{
				//的֮�⣬offset时length的0
				cacheOffset.QuadPart = 0;
				offset.QuadPart = 0;
				length = 0;
			}	

			// 得到时ھ时е�偏移 的偏移-的߼�偏移
			cacheOffset.QuadPart = offset.QuadPart - volumeInfo->physicalStartingOffset;

// 			DbgPrint("0x%x UserBuffer = 0x%x MdlAddress = 0x%x SystemBuffer = 0x%x\n", io_stack->MajorFunction,
// 				Irp->UserBuffer, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

			if (Irp->MdlAddress)
			{
				buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			}
			else if (Irp->AssociatedIrp.SystemBuffer)
			{
				buffer = Irp->AssociatedIrp.SystemBuffer;
			}
			else
			{
				buffer = NULL;
			}
	
			if (!buffer || !length)
			{
				goto __faild;
			}

			if (0 != (length % volumeInfo->bytesPerSector))
			{
				DbgPrint("fuck read %d\n", length);
			}
			
			// 如果上次未的buffer时不同的，则
			// 的 PFN_LIST_CORRUPT (0x99, ...) A PTE or PFN is corrupt 的
			// 跨越内存也的前跨抽象化时
			newbuff = __malloc(length);

			if (newbuff)
			{
				if (IRP_MJ_READ == io_stack->MajorFunction)
				{
					status = handle_disk_request(volumeInfo, io_stack->MajorFunction, offset.QuadPart,
					 newbuff, length, Irp->Flags);
					RtlCopyMemory(buffer, newbuff, length);
				}
				else
				{
					RtlCopyMemory(newbuff, buffer, length);
					status = handle_disk_request(volumeInfo, io_stack->MajorFunction, offset.QuadPart,
					 newbuff, length, Irp->Flags);
				}
				__free(newbuff);
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}

			// 特征Information
			if (NT_SUCCESS(status))
			{
				Irp->IoStatus.Information = length;
			}
			else
			{
				Irp->IoStatus.Information = 0;
			}

			flt_CompleteRequest(
				Irp,
				status,
				IO_NO_INCREMENT
				);
			continue;
__faild:

			flt_SendToNextDriver(volumeInfo->LowerDevObj, Irp);
			continue;			
		}
	}
}

// 的一致性
void protect_Volume(WCHAR volume, BOOLEAN protect)
{
	_volumeList[volume - L'A'].isProtect = protect;
}

NTSTATUS
flt_initVolumeLogicBitMap(PVOLUME_INFO volumeInfo)
{
	NTSTATUS	status;
	PVOLUME_BITMAP_BUFFER	bitMap = NULL;	

	// �߼�位图大小
	ULONGLONG	logicBitMapMaxSize = 0;
	
	ULONG		sectorsPerCluster = 0;

	ULONGLONG	index = 0;
	ULONGLONG	i = 0;

	status = flt_getVolumeBitmapInfo(volumeInfo->volume, &bitMap);
	
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	sectorsPerCluster = volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector;

	// 计算此卷的扇区数，bytesTotal的值更准确，的计算的
	volumeInfo->sectorCount = volumeInfo->bytesTotal / volumeInfo->bytesPerSector;
	
	// 得到逻辑位图的扇小bytes
	logicBitMapMaxSize = (volumeInfo->sectorCount / 8) + 1;

	// 上次扫描的目标写扇区位置
	volumeInfo->last_scan_index = 0;

	
	dprintf("------------------------\n");
	dprintf("extend cluster = %08I64d physicalStartingOffset = 0x%08I64x bitMapSize = 0x%I64x\n"
		"bytesPerSector = %d bytesPerCluster = %d sectorsPerCluster = %d\n", 
		volumeInfo->firstDataSector, volumeInfo->physicalStartingOffset, logicBitMapMaxSize,
		volumeInfo->bytesPerSector, volumeInfo->bytesPerCluster, sectorsPerCluster);
	
	// 时为时位置位图
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Redirect, volumeInfo->sectorCount, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}
	
	// �Դ�为时位置位图
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Protect, volumeInfo->sectorCount / sectorsPerCluster, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}

	// 时为时位置位图, 的һ时内存时󣬻�ʧ�ܣ的dpbitmap的벻时内存
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Free, volumeInfo->sectorCount, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}

	// 时ʽ�ؿ�始前�Ĵ定的为使用时
	for (i = 0; i < volumeInfo->firstDataSector; i++)
	{
		DPBitMap_Set(volumeInfo->bitMap_Free, i, TRUE);
	}


	for (i = 0; i < bitMap->BitmapSize.QuadPart; i++)
	{		
		if (bitmap_test((PULONG)&bitMap->Buffer, i))
		{
			ULONGLONG	j = 0;
			ULONGLONG	base = volumeInfo->firstDataSector + (i * sectorsPerCluster);
			for (j = 0; j < sectorsPerCluster; j++)
			{
				if (!NT_SUCCESS(DPBitMap_Set(volumeInfo->bitMap_Free, base + j, TRUE)))
				{
					status = STATUS_UNSUCCESSFUL;
					goto __faild;
				}
			}
		}
	}

	// 允许时，这些文件时直接读写
	// bootstat.dat时写入的显示的

	setBitmapDirectRWFile(volumeInfo->volume, L"\\Windows\\bootstat.dat", volumeInfo->bitMap_Protect);
	// SAM的时
// 	setBitmapDirectRWFile(volumeInfo->volume, L"\\Windows\\system32\\config\\sam", volumeInfo->bitMap_Protect);

	// 页面文件
	setBitmapDirectRWFile(volumeInfo->volume, L"\\pagefile.sys", volumeInfo->bitMap_Protect);

	// 的文件
	setBitmapDirectRWFile(volumeInfo->volume, L"\\hiberfil.sys", volumeInfo->bitMap_Protect);	
	
	// 始clusterMap
	RtlInitializeGenericTable(&volumeInfo->redirectMap, CompareRoutine, AllocateRoutine, FreeRoutine, NULL);
	
	// Initialize lock
	ExInitializeResourceLite(&volumeInfo->lock);

	status = STATUS_SUCCESS;

__faild:

	if (!NT_SUCCESS(status))
	{
		if (volumeInfo->bitMap_Redirect)
		{
			DPBitMap_Free(volumeInfo->bitMap_Redirect);
			volumeInfo->bitMap_Redirect = NULL;
		}
		if (volumeInfo->bitMap_Protect)
		{
			DPBitMap_Free(volumeInfo->bitMap_Protect);
			volumeInfo->bitMap_Protect = NULL;
		}
		if (volumeInfo->bitMap_Free)
		{
			DPBitMap_Free(volumeInfo->bitMap_Free);
			volumeInfo->bitMap_Free = NULL;
		}
		// If lock was initialized (status success but failed later? No, status is failure here)
		// But wait, if RtlInitializeGenericTable succeeded, we might have initialized lock.
		// Actually lock init is last step. If we fail before, lock is not init.
		// If we fail after? There is no failure after lock init.
	}

	__free_Safe(bitMap);


	return STATUS_SUCCESS;
}

BOOLEAN	_signal = FALSE;

// �ı䱻的�ķ的�图时
VOID
changeDriveIcon(WCHAR volume)
{
	HANDLE	keyHandle;
	UNICODE_STRING	keyPath;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;
	
	RtlInitUnicodeString( &keyPath, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons");   
	
    //初始化objectAttributes 
    InitializeObjectAttributes(&objectAttributes,   
		&keyPath,   
		OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//�Դ�小д的     
		NULL,
		NULL);
	
	status = ZwCreateKey( &keyHandle,   
		KEY_ALL_ACCESS,   
		&objectAttributes,   
		0,   
		NULL,   
		REG_OPTION_VOLATILE,   // 的Ч
		&ulResult);
	
	if (NT_SUCCESS(status))
	{
		WCHAR	volumeName[10];
		HANDLE	subKey;
		swprintf(volumeName, L"%c", volume);
		
		RtlInitUnicodeString( &keyPath, volumeName);
		
		InitializeObjectAttributes(&objectAttributes,   
			&keyPath,   
			OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//�Դ�小д的     
			keyHandle,
			NULL);
		
		status = ZwCreateKey( &subKey,   
			KEY_ALL_ACCESS,   
			&objectAttributes,   
			0,   
			NULL,   
			REG_OPTION_VOLATILE,   // 的Ч
			&ulResult);
		
		if (NT_SUCCESS(status))
		{
			HANDLE	subsubKey;
			RtlInitUnicodeString( &keyPath, L"DefaultIcon");
			
			InitializeObjectAttributes(&objectAttributes,   
				&keyPath,   
				OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//�Դ�小д的     
				subKey,
				NULL);
			
			status = ZwCreateKey( &subsubKey,   
				KEY_ALL_ACCESS,   
				&objectAttributes,   
				0,   
				NULL,   
				REG_OPTION_VOLATILE,   // 的Ч
				&ulResult);
			
			if (NT_SUCCESS(status))
			{
				UNICODE_STRING	keyName;
				WCHAR iconPath[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,0";
				WCHAR iconPathWin7[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,1";

				RtlInitUnicodeString(&keyName, L"");
				status = ZwSetValueKey(subsubKey, &keyName, 0,REG_SZ, iconPathWin7, sizeof(iconPathWin7));				
				
				ZwClose(subsubKey);
			}
			
			ZwClose(subKey);
		}	
		
		ZwClose(keyHandle);
	}
}




ULONG GetProcessNameOffset(void)
{
    PEPROCESS Process = PsGetCurrentProcess();
	
    __try
    {
		ULONG i = 0;
        for (i = 0; i < PAGE_SIZE * 3; i++)
        {
            if (!strncmp("System", (char *)Process + i, 6))
            {
                return i;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        
    }
	
    return 0;
}

wchar_t * wcsstr_n(const wchar_t *string, size_t count, const wchar_t *strCharSet)
{
	wchar_t   *cp=(wchar_t *)string;   
	wchar_t   *s1, *s2;   
    
	if(!*strCharSet)   
		return ((wchar_t *)string);   
    
	while(count && *cp  )   
	{   
		s1   =   cp;
		s2   =   (wchar_t*)strCharSet;   
		
		while(*s1 && *s2 && !(toupper(*s1)-toupper(*s2)))   
			s1++,   s2++;   
		
		if(!*s2)   
			return(cp);   
		cp++;
		count--;
	}   
    
	return(NULL);   	
}


// 的ԡ时
NTSTATUS
testPartition(WCHAR * partitionName)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	PVOLUME_BITMAP_BUFFER	bitMap = NULL;

	
	RtlInitUnicodeString(&fileName, partitionName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("Open %wZ ret 0x%x\n", &fileName, status);
	
	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER	info;
		STARTING_LCN_INPUT_BUFFER StartingLCN;

		ULONG	BitmapSize = 0;
		
		StartingLCN.StartingLcn.QuadPart = 0;
		
		
		// 的�˾�, �在得到的位图前
		status = ZwFsControlFile( fileHandle, 
					NULL, 
					NULL, 
					NULL, 
					&ioBlock, 
					FSCTL_LOCK_VOLUME, 
					NULL, 0, NULL, 0
					);
		
		dprintf("FSCTL_LOCK_VOLUME = 0x%x\n", status);
		

		do 
		{
			BitmapSize += 10240;
			
			info = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			
			status = ZwFsControlFile( fileHandle, 
				NULL, 
				NULL, 
				NULL, 
				&ioBlock, 
				FSCTL_GET_VOLUME_BITMAP, 
				&StartingLCN,
				sizeof (StartingLCN),
				info, 
				BitmapSize
				);

			if (STATUS_BUFFER_OVERFLOW == status)
			{
				__free(info);
			}
			
		} while(STATUS_BUFFER_OVERFLOW == status);
		
		dprintf("FSCTL_GET_VOLUME_BITMAP ret 0x%x\n", status);

		if (!NT_SUCCESS(status))
		{
			__free(info);
		}
		else
		{
			dprintf("bitMapinfo (%d / %d) cluster = %I64d\n", ioBlock.Information, BitmapSize, info->BitmapSize.QuadPart);

			bitMap = info;
		}

		
		status = ZwFsControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			FSCTL_UNLOCK_VOLUME, 
			NULL, 0, NULL, 0
				);

		dprintf("FSCTL_UNLOCK_VOLUME ret 0x%x\n", status);
		

		ZwClose(fileHandle);
	}

	if (bitMap)
	{
		__free(bitMap);
	}
	
	return status;
}


VOID flt_checkAndProtectESP(ULONG diskNumber)
{
	WCHAR pathBuffer[64];
	UNICODE_STRING path;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	PARTITION_INFORMATION_EX partInfo;
	int i;
	int idx = 26; // Index for ESP

	// ESP GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
	GUID espGuid = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};

		// Check if it's already protected
		if (_volumeList[idx].isValid) 
		{
			// Already protected, just log and return
			DiskFltLog("ESP (Index %d) already protected. Skipping scan.\n", idx);
			return;
		}

		// Initialize ESP volume entry
		RtlZeroMemory(&_volumeList[idx], sizeof(VOLUME_INFO));
		_volumeList[idx].diskNumber = diskNumber;
		_volumeList[idx].volume = 0; // No drive letter

		for (i = 1; i <= 20; i++) 
	{
		swprintf(pathBuffer, L"\\Device\\Harddisk%u\\Partition%u", diskNumber, i);
		RtlInitUnicodeString(&path, pathBuffer);
		InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwCreateFile(&fileHandle, GENERIC_READ | SYNCHRONIZE, &oa, &ioStatus, NULL, 0, 
			FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		
		if (NT_SUCCESS(status)) 
		{
			status = ZwDeviceIoControlFile(fileHandle, NULL, NULL, NULL, &ioStatus, 
				IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partInfo, sizeof(partInfo));
			
			if (NT_SUCCESS(status)) 
			{
				if (partInfo.PartitionStyle == PARTITION_STYLE_GPT) 
				{
					if (RtlEqualMemory(&partInfo.Gpt.PartitionType, &espGuid, sizeof(GUID))) 
					{
						FILE_FS_SIZE_INFORMATION sizeInfo;
						
						_volumeList[idx].volume = 0; 
						_volumeList[idx].diskNumber = diskNumber;
						_volumeList[idx].partitionNumber = partInfo.PartitionNumber;
						_volumeList[idx].physicalStartingOffset = partInfo.StartingOffset.QuadPart;
						_volumeList[idx].bytesTotal = partInfo.PartitionLength.QuadPart;
						_volumeList[idx].bootIndicator = FALSE;
						_volumeList[idx].firstDataSector = 0;

						
						
						// Get Volume Info for ESP (Sector/Cluster size)
						ZwQueryVolumeInformationFile(fileHandle, &ioStatus, &sizeInfo, sizeof(sizeInfo), FileFsSizeInformation);
						
						// Default to standard values if query fails (ESP is typically FAT32)
						if (sizeInfo.BytesPerSector == 0) sizeInfo.BytesPerSector = 512;
						if (sizeInfo.SectorsPerAllocationUnit == 0) sizeInfo.SectorsPerAllocationUnit = 8; // 4KB cluster

						_volumeList[idx].bytesPerSector = sizeInfo.BytesPerSector;
						_volumeList[idx].bytesPerCluster = sizeInfo.BytesPerSector * sizeInfo.SectorsPerAllocationUnit;
						
						// Initialize Bitmap for ESP
						// Important: ESP is small, so we can use a small bitmap or share memory logic
						status = flt_initVolumeLogicBitMap(&_volumeList[idx]);
						if (NT_SUCCESS(status))
						{
							_volumeList[idx].isValid = TRUE;
							_volumeList[idx].isProtect = TRUE;
							DiskFltLog("Protected ESP at index %d (Disk %d Part %d)\n", idx, diskNumber, partInfo.PartitionNumber);
						}
					}
				}
			}
			ZwClose(fileHandle);
			if (_volumeList[idx].isValid) break;
		}
	}
}

VOID flt_initializeVolume()
{
	NTSTATUS	status;
	ULONG		i;
    
    LogToFile("flt_initializeVolume: Start scanning volumes...\n");

	for (i = 0; i < 26; i++)
	{
		_volumeList[i].volume = (WCHAR)i + L'A';
		
		// 时ѯ要的信息
// ѯ要Ϣ
		// Check both config AND current validity. 
		// If config says 0 (unprotect) but isValid is TRUE, we should unprotect it?
		// Currently flt_initializeVolume only handles enabling protection.
		// Disabling protection usually requires a reboot anyway because we don't dynamically detach/clear bitmap easily.
		// However, if the user ran Protection.exe /w and rebooted, _protectInfo.volumeInfo[i] will be 0.
		// In that case, this block is skipped, and isValid remains FALSE (from global init).
		// So logic seems correct for REBOOT case.
		
		if (_protectInfo.volumeInfo[i] && (_volumeList[i].volume > L'B')
			&& (!_volumeList[i].isValid))
		{
            LogToFile("flt_initializeVolume: Found Config for Volume %c (Index %d). Initializing...\n", _volumeList[i].volume, i);
			status = flt_getVolumeInfo(_volumeList[i].volume, &_volumeList[i]);
			
			// 的±的状态
			if (NT_SUCCESS(status))
			{
				status = flt_initVolumeLogicBitMap(&_volumeList[i]);
				
				_signal = TRUE;
				
				if (!NT_SUCCESS(status))
				{
					dprintf("flt_initVolumeLogicBitMap error 0x%x .\n", status);
                    LogToFile("flt_initializeVolume: Init Bitmap Error 0x%x\n", status);
					_protectInfo.volumeInfo[i] = 0;
					continue;
				}
				
				_volumeList[i].isValid = TRUE;
				_volumeList[i].isProtect = TRUE;
                LogToFile("flt_initializeVolume: Volume %c IS NOW PROTECTED.\n", _volumeList[i].volume);
				
				flt_checkAndProtectESP(_volumeList[i].diskNumber);

				DiskFltLog("disk %c diskNumber = %d PartitionNumber: %d protect : %d\n"
					"offset = 0x%08I64x len = 0x%08I64x dataStart = 0x%08I64x\n", 
					_volumeList[i].volume, _volumeList[i].diskNumber, _volumeList[i].partitionNumber, _volumeList[i].isProtect,
					_volumeList[i].physicalStartingOffset, _volumeList[i].bytesTotal,
					_volumeList[i].firstDataSector);
				
				dprintf("disk %c diskNumber = %d PartitionNumber: %d protect : %d\n"
					"offset = 0x%08I64x len = 0x%08I64x dataStart = 0x%08I64x\n\n", 
					_volumeList[i].volume, _volumeList[i].diskNumber, _volumeList[i].partitionNumber, _volumeList[i].isProtect,
					_volumeList[i].physicalStartingOffset, _volumeList[i].bytesTotal,
					_volumeList[i].firstDataSector);
				
			}
            else
            {
                LogToFile("flt_initializeVolume: flt_getVolumeInfo failed 0x%x\n", status);
            }
		}
	}
    LogToFile("flt_initializeVolume: Done.\n");
}

ULONG
getTickCount() 
{ 
	LARGE_INTEGER count, freq;
	count = KeQueryPerformanceCounter(&freq);
	if (freq.QuadPart == 0) return 0;
	return (ULONG)((count.QuadPart * 1000) / freq.QuadPart);
} 

void
getRandomString(PWCHAR random)
{
	ULONG	tick = getTickCount();
	int		mask[9] = {12, 25, 36, 44, 54, 61, 78, 33, 65};
	int		i = 0;
	
	for (i = 0; i < 9; i++)
	{
		if (tick / mask[i] % 2)
			random[i] = (tick / mask[i] % 26) + 'A';
		else
			random[i] = (tick / mask[i] % 26) + 'a';
	}
	
	random[9] = '\0';
}


#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) \
    ((_ucStr)->Buffer = (_buf), \
	(_ucStr)->Length = 0, \
     (_ucStr)->MaximumLength = (USHORT)(_bufSize))

VOID
ImageNotifyRoutine(
				   IN PUNICODE_STRING  FullImageName,
				   IN HANDLE  ProcessId, // where image is mapped
				   IN PIMAGE_INFO  ImageInfo
				   )
{
	static BOOL	isSetIcon = FALSE;

	NTSTATUS	status;

	if ((!isSetIcon) && FullImageName && wcsstr_n(FullImageName->Buffer, FullImageName->Length / sizeof(WCHAR), L"winlogon.exe"))
	{
		ULONG	protectNumber = 0;
		ULONG	i = 0;
		// �ٳ�始时һ�Σ的ֹһЩ�ܱ的ľ用户б的始, �及时性�始比较�ȶ�
		flt_initializeVolume();
        LogToFile("ImageNotifyRoutine: Re-initializing volume logic. Winlogon detected.\n");
		for (i = 0; i < _countof(_volumeList); i++) {
			if (_volumeList[i].isValid && _volumeList[i].isProtect)
			{
                LogToFile("ImageNotifyRoutine: Volume %c IS PROTECTED. Setting Icon.\n", _volumeList[i].volume);
				// ıܱľĬ图
				changeDriveIcon(_volumeList[i].volume);
				protectNumber++;
			}
		}
		isSetIcon = TRUE;
		// 如果要的
		if (protectNumber)
		{
			// 默认的
			_sysPatchEnable = TRUE;	
		}
	}

	if(	(!_sysPatchEnable)
		|| (!ImageInfo->SystemModeImage)
		|| (FullImageName == NULL) 
		|| (FullImageName->Length == 0)
		|| (FullImageName->Buffer == NULL)
		)
	{
		return;
	}

	status = IsFileCreditable(FullImageName);

	if (!NT_SUCCESS(status)) 
	{
		ULONG	start;
		WCHAR	buf[512];
		WCHAR	random[50];
		UNICODE_STRING	msg;
		UNICODE_STRING	caption;

		// 时为时
		getRandomString(random);
		RtlInitUnicodeString(&caption, random);

		RtlInitEmptyUnicodeString(&msg, buf, sizeof(buf));
		RtlAppendUnicodeToString(&msg, L"Load [");
		RtlAppendUnicodeStringToString(&msg, FullImageName);
		RtlAppendUnicodeToString(&msg, L"] ?");

		start = getTickCount();

		if (ResponseYes == kMessageBox(&msg, &caption, OptionYesNo, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_DEFBUTTON2))
		{
			status = STATUS_SUCCESS;
		}

		// �˲的ܵ的ô�죬�ܾ的�
		if ((getTickCount() - start) < 500)
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}

	// 的�ŵ的�全选XX时
	if (!NT_SUCCESS(status))
	{
		/**
		* 00410070 >    B8 220000C0   mov     eax, C0000022 // STATUS_ACCESS_DENIED
		* 00410075      C2 0800       retn    8
		*/
		return; // Disabled for Win10/11
/*
		BYTE	patchCode[] = {0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC2, 0x08, 0x00};
		// PATCH的
		PIMAGE_DOS_HEADER	imageDosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

		if (IMAGE_DOS_SIGNATURE == imageDosHeader->e_magic)
		{
			PIMAGE_NT_HEADERS	imageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageInfo->ImageBase + imageDosHeader->e_lfanew);
			if (IMAGE_NT_SIGNATURE == imageNtHeaders->Signature)
			{
				WriteReadOnlyMemory((LPBYTE)ImageInfo->ImageBase + imageNtHeaders->OptionalHeader.AddressOfEntryPoint, patchCode, sizeof(patchCode));
			}
		}
*/
	}
}

VOID DiskFltLog(const char* format, ...)
{
	CHAR buffer[1024];
	ANSI_STRING ansiString;
	UNICODE_STRING unicodeString;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStatus;
	HANDLE fileHandle;
	NTSTATUS status;
	va_list args;
	UNICODE_STRING fileName;

	va_start(args, format);
	_vsnprintf(buffer, sizeof(buffer) - 1, format, args);
	va_end(args);
	
	RtlInitAnsiString(&ansiString, buffer);
	
	// Convert to Unicode (optional, but good for file content if we write Unicode, 
	// here we just write ANSI bytes for simplicity)
	
	RtlInitUnicodeString(&fileName, L"\\DosDevices\\C:\\log.txt");
	
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&fileHandle, 
						  FILE_APPEND_DATA | SYNCHRONIZE, 
						  &oa, 
						  &ioStatus, 
						  NULL, 
						  FILE_ATTRIBUTE_NORMAL, 
						  FILE_SHARE_READ | FILE_SHARE_WRITE, 
						  FILE_OPEN_IF, 
						  FILE_SYNCHRONOUS_IO_NONALERT, 
						  NULL, 
						  0);
						  
	if (NT_SUCCESS(status))
	{
		ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, buffer, ansiString.Length, NULL, NULL);
		ZwClose(fileHandle);
	}
}

extern UNICODE_STRING DiskPerfRegistryPath;

VOID LogToFile(CHAR* format, ...)
{
    // Simple File Logger to C:\log.txt
    // Uses direct ZwWriteFile.
    
    HANDLE hFile;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING fileName;
    NTSTATUS status;
    char buffer[1024];
    va_list args;
    LARGE_INTEGER offset;
    
    // Construct the log message
    va_start(args, format);
    _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);
    buffer[sizeof(buffer)-1] = 0;
    
    // Open file
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\log.txt");
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &ioStatus, NULL, 
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        
    if (NT_SUCCESS(status))
    {
        offset.QuadPart = 0; // Append
        ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, buffer, strlen(buffer), NULL, NULL);
        ZwClose(hFile);
    }
}

VOID flt_loadConfigFromDisk()
{
    // Load config from Sector 62 (Absolute sector) of Disk 0
    // In GPT, LBA 34-2047 are usually reserved/unused. LBA 62 is safe.
    
    NTSTATUS status;
    HANDLE fileHandle;
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER offset;
    PVOID buffer = NULL;
    
    LogToFile("flt_loadConfigFromDisk: Starting...\n");
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\Harddisk0\\DR0");
    InitializeObjectAttributes(&oa, &deviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwCreateFile(&fileHandle, GENERIC_READ, &oa, &ioStatus, NULL, 
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        
    if (NT_SUCCESS(status))
    {
        buffer = __malloc(512);
        if (buffer)
        {
            offset.QuadPart = 62 * 512; // LBA 62
            
            status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, buffer, 512, &offset, NULL);
            
            if (NT_SUCCESS(status))
            {
                PPROTECT_INFO pInfo = (PPROTECT_INFO)buffer;
                LogToFile("flt_loadConfigFromDisk: Read Sector 62 Success. Magic: %.16s\n", pInfo->magicChar);
                LogToFile("flt_loadConfigFromDisk: Volume C (index 2) Flag: %d\n", pInfo->volumeInfo[2]);
                
                if (strncmp((char*)pInfo->magicChar, MAGIC_CHAR, strlen(MAGIC_CHAR)) == 0)
                {
                    RtlCopyMemory(&_protectInfo, pInfo, sizeof(PROTECT_INFO));
                    DiskFltLog("Config loaded from Disk 0 Sector 62.\n");
                    LogToFile("flt_loadConfigFromDisk: Config LOADED from Sector 62.\n");
                }
                else
                {
                    DiskFltLog("No valid config found at Disk 0 Sector 62.\n");
                    LogToFile("flt_loadConfigFromDisk: Invalid Magic. Ignoring config.\n");
                }
            }
            else
            {
                LogToFile("flt_loadConfigFromDisk: ZwReadFile Failed: 0x%x\n", status);
            }
            __free(buffer);
        }
        else
        {
            LogToFile("flt_loadConfigFromDisk: Malloc Failed.\n");
        }
        ZwClose(fileHandle);
    }
    else
    {
        DiskFltLog("Failed to open Disk 0 for config load: 0x%x\n", status);
        LogToFile("flt_loadConfigFromDisk: Failed to open \\Device\\Harddisk0\\DR0: 0x%x\n", status);
    }
}

VOID flt_loadConfigFromRegistry()
{
    // DISABLED: Registry config loading is disabled to prevent shadow copy reversion issues.
    // Config is now loaded exclusively from Disk 0 Sector 62.
    DiskFltLog("flt_loadConfigFromRegistry: DISABLED in this build.\n");
    return;
}

VOID
flt_reinitializationRoutine( 
	IN	PDRIVER_OBJECT	DriverObject, 
	IN	PVOID			Context, 
	IN	ULONG			Count 
	)
{
	NTSTATUS	status;
	
	//的设备�Ĵ的̵߳时߳̾时
	HANDLE		ThreadHandle = NULL;

	DiskFltLog("\n-------start--------\n");
	DiskFltLog("flt_reinitializationRoutine called - V2 DISK ONLY\n");
    LogToFile("DRIVER LOAD: V2 DISK ONLY BUILD\n");

    // FORCE DISK LOAD ONLY - REGISTRY LOAD DISABLED
	// flt_loadConfigFromRegistry(); 
    flt_loadConfigFromDisk();     
	flt_initializeVolume();
	
	//开始的队列
	InitializeListHead(&_deviceExtension->list_head);
	//开始的队列锁
	KeInitializeSpinLock(&_deviceExtension->list_lock);
	//开始的队列同步事件
	KeInitializeEvent(
		&_deviceExtension->ReqEvent,
		SynchronizationEvent,
		FALSE
		);
	
	//初始化禁止的线程标志
	_deviceExtension->terminate_thread = FALSE;
	//创建的读写线程，线程函数的参数是设备扩展
	status = PsCreateSystemThread(
		&ThreadHandle,
		(ACCESS_MASK)0L,
		NULL,
		NULL,
		&_deviceExtension->thread_read_write_id,			
		flt_thread_read_write,
		_deviceExtension
		);
	
	if (!NT_SUCCESS(status))
		goto __faild;
	
	
	//选择的�̵߳Ķ的
	status = ObReferenceObjectByHandle(
		ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&_deviceExtension->thread_read_write,
		NULL
		);

	if (NULL != ThreadHandle)
		ZwClose(ThreadHandle);

	if (!NT_SUCCESS(status))
	{
		_deviceExtension->terminate_thread = TRUE;
		KeSetEvent(
			&_deviceExtension->ReqEvent,
			(KPRIORITY)0,
			FALSE
			);
		goto __faild;
	}

	


	_deviceExtension->Protect = TRUE;
	_signal = FALSE;

__faild:
	//关闭线程句柄，如果失败时不使用卸载线程的枚举通用的线程的
	if (NULL != ThreadHandle)
		ZwClose(ThreadHandle);
}


NTSTATUS
WriteReadOnlyMemory(
	LPBYTE	dest,
	LPBYTE	src,
	ULONG	count
	)
	/**
	* 检查内存是否可以写入只读的内存页，如果要写入只读内存页，
	* 使用一致性写入，使用相同的内存页
	*/
{
	// Win10/11: Modifying executable code sections is prohibited by PatchGuard.
	// This function is disabled to prevent BSOD.
	return STATUS_NOT_SUPPORTED;
}

// 启动文件是否的，也的启动文件是否的原始没有的
// 只要的卸载的时抽象化时定时

NTSTATUS
IsFileCreditable(PUNICODE_STRING filePath)
{
	NTSTATUS	status;
	HANDLE		fileHandle = (HANDLE)-1;
	PFILE_OBJECT	fileObject = NULL;	
	PRETRIEVAL_POINTERS_BUFFER	pVcnPairs = NULL;
	PVOLUME_INFO	volumeInfo = NULL;
	ULONG	sectorsPerCluster;

	PVOID	RestartKey = 0;
	PVOID	Element;

	BOOLEAN	IsCreditable = FALSE;

	status = flt_getFileHandleReadOnly(&fileHandle, filePath);

	if (!NT_SUCCESS(status))
	{
		dprintf("Open %wZ ret 0x%x\n", filePath, status);
		goto __faild;
	}

	status = ObReferenceObjectByHandle(fileHandle, 0, NULL, KernelMode, (PVOID *)&fileObject, NULL);
	
	if (!NT_SUCCESS(status))
	{
		goto __faild;
	}

	if (FILE_DEVICE_NETWORK_FILE_SYSTEM != fileObject->DeviceObject->DeviceType)
	{
		UNICODE_STRING	uniDosName;
		// 得到的�C:时̷的为�˻�ȡVolumeInfo
		status = RtlVolumeDeviceToDosName(fileObject->DeviceObject, &uniDosName); 
		
		if (NT_SUCCESS(status))
		{
			volumeInfo = &_volumeList[toupper(*(WCHAR *)uniDosName.Buffer) - L'A'];
			ExFreePool(uniDosName.Buffer);

			if ((!volumeInfo->isValid) || (!volumeInfo->isProtect))
			{
				goto __faild;
			}
		}
	}

	if (!volumeInfo)
	{
		goto __faild;
	}

	sectorsPerCluster = volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector;

	pVcnPairs = getFileClusterList(fileHandle);
	
	if(NULL == pVcnPairs)
	{
		dprintf("getFileClusterList fail\n");
		goto __faild;
	}
	
    RestartKey = NULL;
    for (Element = RtlEnumerateGenericTableWithoutSplaying(&volumeInfo->redirectMap, &RestartKey);
         Element != NULL;
         Element = RtlEnumerateGenericTableWithoutSplaying(&volumeInfo->redirectMap, &RestartKey)) 
	{
		ULONG	Cls, r;
		LARGE_INTEGER	PrevVCN = pVcnPairs->StartingVcn;
		for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
		{
			ULONG	CnCount;
			LARGE_INTEGER Lcn = pVcnPairs->Extents[r].Lcn;

			for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
			CnCount; CnCount--, Cls++, Lcn.QuadPart++) 
			{
				ULONGLONG	i = 0;
				ULONGLONG	base = volumeInfo->firstDataSector + (Lcn.QuadPart * sectorsPerCluster);
				for (i = 0; i < sectorsPerCluster; i++)
				{
					// 的�定的, 时文件, 禁止时֤
					if (((PPAIR)Element)->orgIndex == (base + i))
					{
						// ............
						goto __exit;
					}
				}  
			}
			PrevVCN = pVcnPairs->Extents[r].NextVcn;
		}
	}

	// 的
	IsCreditable = TRUE;

__exit:
	
	__free_Safe(pVcnPairs);
	
__faild:

	if (fileObject)
		ObDereferenceObject(fileObject);

	if (((HANDLE)-1 != fileHandle))
		ZwClose(fileHandle);

	return IsCreditable ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

//////////////////////////////////////////////////////////////////////////
PDEVICE_OBJECT on_diskperf_driver_entry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING reg)
{
	NTSTATUS			status; 
	PDEVICE_OBJECT		deviceObject = NULL;
	BOOLEAN				symbolicLink = FALSE;
	UNICODE_STRING		ntDeviceName;
	PFILTER_DEVICE_EXTENSION	deviceExtension;
	UNICODE_STRING		dosDeviceName;

	RtlInitUnicodeString(&ntDeviceName, DISKFILTER_DEVICE_NAME_W);	
	
    status = IoCreateDevice(
		DriverObject,
		sizeof(FILTER_DEVICE_EXTENSION),		// DeviceExtensionSize
		&ntDeviceName,					// DeviceName
		FILE_DEVICE_DISKFLT,			// DeviceType
		0,								// DeviceCharacteristics
		TRUE,							// Exclusive 时要为FALSE,需要ȻCreateFileֻ�ܴ�һ时, 使用得到ùرյ�
		&deviceObject					// [OUT]
		);
	
	if (!NT_SUCCESS(status))
	{
		dprintf("IoCreateDevice failed(0x%x).\n", status);
		goto failed;
	}

//	deviceObject->Flags |= DO_BUFFERED_IO; 

	deviceExtension = (PFILTER_DEVICE_EXTENSION)deviceObject->DeviceExtension;

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);
	if (!NT_SUCCESS(status))
    {
        dprintf("IoCreateSymbolicLink failed(0x%x).\n", status);
		goto failed;
    }

	// 初始化内存�
	mempool_init();

	// 开始时
	memset(&_volumeList, 0, sizeof(_volumeList));
	memset(&_lowerDeviceObject, 0, sizeof(_lowerDeviceObject));

	_sysPatchEnable = FALSE;

	// 初始化为�Ǳ的状态
	deviceExtension->Protect = FALSE;
	
	// 特征ȫ�ֱ的
	_deviceExtension = deviceExtension;

	_systemProcessId = (ULONG)PsGetCurrentProcessId();
	_processNameOfffset = GetProcessNameOffset();

	
	//注册一个boot的扇区的的boot的去执行
  	IoRegisterBootDriverReinitialization(
  		DriverObject,
 		flt_reinitializationRoutine,
  		NULL
  		);	

    if (NT_SUCCESS(status))
	    return deviceObject;

failed:
	
	if (symbolicLink)
		IoDeleteSymbolicLink(&dosDeviceName);
	
	if (deviceObject)
		IoDeleteDevice(deviceObject);

	return deviceObject;
}


VOID on_diskperf_driver_unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosDeviceName;

	ULONG	i = 0;
	
	//
    // Free any resources
    //

	//时需要һЩ的
	if (_deviceExtension->terminate_thread != TRUE && NULL != _deviceExtension->thread_read_write)
	{
		_deviceExtension->Protect = FALSE;
		//的̻߳时еĻ的要停止的ͨ时回收线程停止的еı�־的ҷ的¼的Ϣ回收线程�Լ的ֹ的
		_deviceExtension->terminate_thread = TRUE;
		KeSetEvent(
			&_deviceExtension->ReqEvent,
			(KPRIORITY) 0,
			FALSE
			);
		//�ȴ时߳̽的
		KeWaitForSingleObject(
			_deviceExtension->thread_read_write,
			Executive,
			KernelMode,
			FALSE,
			NULL
			);

		//的̶߳的
		ObDereferenceObject(_deviceExtension->thread_read_write);

		
		for (i = 0; i < _countof(_volumeList); i++)
		{
			// �ͷ的Դ
			DPBitMap_Free(_volumeList[i].bitMap_Redirect);
			DPBitMap_Free(_volumeList[i].bitMap_Protect);
			DPBitMap_Free(_volumeList[i].bitMap_Free);
			
			if (_volumeList[i].isValid)
			{
				ExDeleteResourceLite(&_volumeList[i].lock);
			}
		
			{
				PVOID	RestartKey = 0;
				PVOID	Element;
				
				RestartKey = 0;  // Always get the first element
				while ((Element = RtlEnumerateGenericTableWithoutSplaying(&_volumeList[i].redirectMap, (PVOID *)&RestartKey)) != NULL) 
				{
					RtlDeleteElementGenericTable(&_volumeList[i].redirectMap, Element);		   
					RestartKey = 0;
				}
			}
		}
	}

	// 释放内存�
	mempool_fini();

    //
    // Delete the symbolic link
    //
	
    RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);
	
    IoDeleteSymbolicLink(&dosDeviceName);
	
    //
    // Delete the device object
    //
	
    IoDeleteDevice(DriverObject->DeviceObject);
	
    dprintf("[disk Filter] unloaded\n");
}

// 时أ的�TRUE status为状态时
BOOLEAN on_diskperf_dispatch(
	PDEVICE_OBJECT dev,
    PIRP irp,
	NTSTATUS *status)
{
	ULONG				ioControlCode;
	PIO_STACK_LOCATION	irpSp;
	PVOID				ioBuffer;
    ULONG				inputBufferLength, outputBufferLength;
	irpSp = IoGetCurrentIrpStackLocation(irp);

	ioControlCode		= irpSp->Parameters.DeviceIoControl.IoControlCode;
	ioBuffer			= irp->AssociatedIrp.SystemBuffer;
    inputBufferLength	= irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength	= irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode		= irpSp->Parameters.DeviceIoControl.IoControlCode;

	irp->IoStatus.Information = 0;

	switch (ioControlCode)
    {
	case IOCTL_DISKFLT_LOCK:
		{
			BYTE	md5[16];
			CalcMD5(ioBuffer, inputBufferLength, &md5);
			if (sizeof(md5) == RtlCompareMemory(md5, _protectInfo.passWord, sizeof(md5)))
			{
				InterlockedExchange(&_lockProcessId, (ULONG)PsGetCurrentProcessId());
 				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_ACCESS_DENIED;
			}

		}
		break;
	case IOCTL_DISKFLT_UNLOCK:
		{
			InterlockedExchange(&_lockProcessId, -1);
			irp->IoStatus.Information = 0;
			*status = STATUS_SUCCESS;
		}
		break;
		
	case IOCTL_DISKFLT_GETINFO:
		{
			if (outputBufferLength >= sizeof(PROTECT_INFO))
			{
				irp->IoStatus.Information = sizeof(PROTECT_INFO);
				memcpy(ioBuffer, &_protectInfo, sizeof(PROTECT_INFO));
				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
		break;
	case IOCTL_DISKFLT_PROTECTSYS_STATE:
		{
			*status = _sysPatchEnable ? STATUS_SUCCESS : STATUS_NOT_IMPLEMENTED;
		}
		break;
	case IOCTL_DISKFLT_TEMP_DISABLE:
		{
			// Temporarily disable protection for all volumes
			// This allows config tools to update the registry or files
			int i;
			for (i = 0; i < 26; i++) // Fixed: Array size is 26, not 32
			{
				if (_volumeList[i].isValid)
				{
					_volumeList[i].isProtect = FALSE;
					DiskFltLog("Volume %d (%c) protection temporarily disabled.\n", i, _volumeList[i].volume ? _volumeList[i].volume : '?');
				}
			}
			*status = STATUS_SUCCESS;
		}
		break;
	case IOCTL_DISKFLT_WRITE_CONFIG:
		{
			// Write 512 bytes to Sector 62 (Offset 31744)
			// Input Buffer: 512 bytes
			if (inputBufferLength >= 512)
			{
				LARGE_INTEGER offset;
				offset.QuadPart = 31744; // 62 * 512

				// We need to write to Disk 0. 
				// We can use ZwWriteFile if we open the disk handle, 
				// OR we can construct an IRP and send it down to the lower device object of Disk 0.
				// Since we are in the filter, we have access to lower device objects via _lowerDeviceObject[0].
				
				if (_lowerDeviceObject[0])
				{
					// Use internal helper to write synchronously to lower device
					// We need a helper function to build and send IRP_MJ_WRITE
					// But wait, we are in the dispatch routine of the FILTER device (DiskFlt), 
					// NOT the disk stack filter. This device object is a control device.
					// The lower device objects are stored in _lowerDeviceObject[disk_number] during on_diskperf_new_disk.
					
					// Let's implement a simple synchronous write using IoBuildSynchronousFsdRequest
					
					PDEVICE_OBJECT TargetDevice = _lowerDeviceObject[0];
					KEVENT event;
					PIRP irp;
					IO_STATUS_BLOCK ioStatus;
					
					KeInitializeEvent(&event, NotificationEvent, FALSE);
					
					// Allocate a buffer in non-paged pool to ensure safety (though ioBuffer is usually safe if buffered I/O)
					// But IoBuildSynchronousFsdRequest expects a buffer.
					
					irp = IoBuildSynchronousFsdRequest(
						IRP_MJ_WRITE,
						TargetDevice,
						ioBuffer,
						512,
						&offset,
						&event,
						&ioStatus
					);
					
					if (irp)
					{
						// Set SL_FORCE_DIRECT_WRITE to bypass blocking
						IoGetNextIrpStackLocation(irp)->Flags |= SL_FORCE_DIRECT_WRITE;

						NTSTATUS callStatus = IoCallDriver(TargetDevice, irp);
						if (callStatus == STATUS_PENDING)
						{
							KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
							callStatus = ioStatus.Status;
						}
						
						*status = callStatus;
						if (NT_SUCCESS(*status))
						{
							DiskFltLog("IOCTL_DISKFLT_WRITE_CONFIG: Success.\n");
						}
						else
						{
							DiskFltLog("IOCTL_DISKFLT_WRITE_CONFIG: Failed 0x%x\n", *status);
						}
					}
					else
					{
						*status = STATUS_INSUFFICIENT_RESOURCES;
					}
				}
				else
				{
					DiskFltLog("IOCTL_DISKFLT_WRITE_CONFIG: Disk 0 Device Object not found.\n");
					*status = STATUS_DEVICE_NOT_READY;
				}
			}
			else
			{
				*status = STATUS_BUFFER_TOO_SMALL;
			}
		}
		break;
	case IOCTL_DISKFLT_LOGIN:
	case IOCTL_DISKFLT_PROTECTSYS:
	case IOCTL_DISKFLT_NOPROTECTSYS:
		{
			BYTE	md5[16];
			CalcMD5(ioBuffer, inputBufferLength, &md5);
			if (sizeof(md5) == RtlCompareMemory(md5, _protectInfo.passWord, sizeof(md5)))
			{
				if (IOCTL_DISKFLT_PROTECTSYS == ioControlCode)
				{
					InterlockedExchange(&_sysPatchEnable, TRUE);
				}
				else if (IOCTL_DISKFLT_NOPROTECTSYS == ioControlCode)
				{
					InterlockedExchange(&_sysPatchEnable, FALSE);
				}
				
				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_ACCESS_DENIED;
			}
		}
		break;

	default:
		irp->IoStatus.Information = 0;
		*status = STATUS_SUCCESS;
		break;
	}

 	flt_CompleteRequest(
		irp,
		*status,
		IO_NO_INCREMENT
 		);

	return TRUE;
}

// 时أ的�TRUE status为状态时
BOOLEAN on_diskperf_read_write(
					 IN PUNICODE_STRING physics_device_name,
					 IN ULONG	device_type,
					 IN ULONG device_number,
					 IN ULONG partition_number,
					 IN PDEVICE_OBJECT device_object,
					 IN PIRP Irp,
					 IN NTSTATUS *status)
{
	
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( Irp );
	ULONG	i = 0;

	//irp�е的ݳ的
	ULONG				length = 0;
	//irp要时ƫ的
	LARGE_INTEGER		offset = { 0 };

    if (IRP_MJ_WRITE == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Write.ByteOffset;
        // EXPLICITLY ALLOW WRITE TO CONFIG SECTOR (62)
        // 62 * 512 = 31744
        if (offset.QuadPart == 31744) 
        {
            // DiskFltLog("ALLOWED Write to Config Sector 62.\n");
            return FALSE;
        }
    }

	if (!_deviceExtension->Protect)
	{
		if (_signal && IRP_MJ_WRITE == irpStack->MajorFunction)
		{
			//�к时ٻ时ᴥ的�
			dprintf(">> 选择位图时初始化的м时写入\n");
		}
		return FALSE;
	}

	// �Ź�ָ的�̵Ķ�д
// Allow all IO if shutdown is in progress
    if (g_IsShutdown)
    {
        return FALSE;
    }

	// 
	if (PsGetCurrentProcessId() == _lockProcessId)
	{
		return FALSE;
	}

	if (PsGetCurrentThreadId() == _deviceExtension->thread_read_write_id.UniqueThread)
	{
		return FALSE;
	}

	if (IRP_MJ_WRITE == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Write.ByteOffset;
		length = irpStack->Parameters.Write.Length;

	
	}
	else if (IRP_MJ_READ == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Read.ByteOffset;
		length = irpStack->Parameters.Read.Length;
	}
	else
	{
		// 的֮�⣬offset时length的0
		offset.QuadPart = 0;
		length = 0;
	}

	for (i = 0; i < _countof(_volumeList); i++)
	{
		// 时是否有效
		if ((!_volumeList[i].isValid) || (!_volumeList[i].isProtect))
			continue;

		// 的Ƿ的ܱ的�Ӳ的
		if (_volumeList[i].diskNumber != device_number)
			continue;

		if ((offset.QuadPart >= _volumeList[i].physicalStartingOffset) &&
			((offset.QuadPart - _volumeList[i].physicalStartingOffset) <= _volumeList[i].bytesTotal)
			)
		{
			// Check if this area is configured for Direct RW (e.g. pagefile.sys, hiberfil.sys)
			// Passthrough immediately to avoid Deadlock on Paging I/O
			if (isSectorProtect(&_volumeList[i], offset.QuadPart / _volumeList[i].bytesPerSector))
			{
				return FALSE;
			}

			// Paging I/O MUST be handled synchronously to avoid deadlock in worker thread
			// HOWEVER, we cannot handle it synchronously at DISPATCH_LEVEL (BSOD).
			// And we cannot Passthrough it (Protection Failure).
			// So we MUST Queue it and hope the Worker Thread does not Deadlock.
			// (The previous "return FALSE" here caused the protection failure).
			/*
			if (Irp->Flags & IRP_PAGING_IO)
			{
				return FALSE;
			}
			*/
			//时ڱ的状态时
			//时Ȱ的irp时为pending状态
			IoMarkIrpPending(Irp);

			// 如果IRP中的IoStatus.Pointer的数据时，的
			Irp->IoStatus.Pointer = (PVOID)i;

			// Log the write attempt
			if (IRP_MJ_WRITE == irpStack->MajorFunction)
			{
				// Filter out paging I/O if necessary, or system critical writes during boot
				// But we want to protect everything. 
				// However, if we block something critical for boot progress (like pagefile or logs) it might hang.
				// For ESP, writes are rare. For C:, writes are frequent.
				
				// Debug log: print only first few writes to avoid flooding during boot loop
				// DiskFltLog("Write Protected: Offset=0x%I64x, Length=%d, Vol=%c\n", offset.QuadPart, length, _volumeList[i].volume);
			}

			//然后irp进入队列的
			ExInterlockedInsertTailList(
				&_deviceExtension->list_head,
				&Irp->Tail.Overlay.ListEntry,
				&_deviceExtension->list_lock
				);
			//的枚举等待事件时通知的irp的写入
			KeSetEvent(
				&_deviceExtension->ReqEvent, 
				(KPRIORITY)0, 
				FALSE);
			//的pending状态的�irp的㴦时
			*status = STATUS_PENDING;

			// TRUE开始IPR时
			return TRUE;
		}
	}


//	dprintf("offset %I64d not protected (%d)\n", offset.QuadPart, irpStack->MajorFunction);
	// //的ڱ的状态时ֱ�ӽ的²�设备的写入�
	return FALSE;
}

VOID on_diskperf_new_disk(
			IN PDEVICE_OBJECT device_object,
			IN PUNICODE_STRING physics_device_name,
			IN ULONG device_type,			
			IN ULONG disk_number,
			IN ULONG partition_number)
{
	// 的设备
	if (disk_number < _countof(_lowerDeviceObject))
	{
		_lowerDeviceObject[disk_number] = device_object;
	}
	// 时Ӳ�̹ҽ�
	dprintf("new disk %wZ %d %d %d\n", physics_device_name, device_type, disk_number, partition_number);
}

VOID
on_diskperf_remove_disk(
	IN PDEVICE_OBJECT device_object,
	IN PUNICODE_STRING physics_device_name
	)
{
	
}