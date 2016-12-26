#include <ntddk.h>
#include <Ntstrsafe.h>
#include "main.h"

#define DRIVER_NAME                       L"\\Device\\helper"
#define DEVICE_NAME                       L"\\DosDevices\\helper"
#define IMAGE_SIZEOF_SHORT_NAME           8
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16
#define IMAGE_NT_SIGNATURE                0x00004550  // PE00
#define IMAGE_DOS_SIGNATURE               0x5A4D      // MZ

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONG BaseOfData;
	ULONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Reserved1;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONG SizeOfStackReserve;
	ULONG SizeOfStackCommit;
	ULONG SizeOfHeapReserve;
	ULONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;


typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	}Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG Characteristics;
	ULONG TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	PULONG *AddressOfFunctions;
	PULONG *AddressOfNames;
	PUSHORT *AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DOS_HEADER { // DOS .EXE header
	USHORT e_magic;                 // Magic number
	USHORT e_cblp;                  // Bytes on last page of file
	USHORT e_cp;                    // Pages in file
	USHORT e_crlc;                  // Relocations
	USHORT e_cparhdr;               // Size of header in paragraphs
	USHORT e_minalloc;              // Minimum extra paragraphs needed
	USHORT e_maxalloc;              // Maximum extra paragraphs needed
	USHORT e_ss;                    // Initial (relative) SS value
	USHORT e_sp;                    // Initial SP value
	USHORT e_csum;                  // Checksum
	USHORT e_ip;                    // Initial IP value
	USHORT e_cs;                    // Initial (relative) CS value
	USHORT e_lfarlc;                // File address of relocation table
	USHORT e_ovno;                  // Overlay number
	USHORT e_res[4];                // Reserved words
	USHORT e_oemid;                 // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;               // OEM information; e_oemid specific
	USHORT e_res2[10];              // Reserved words
	ULONG e_lfanew;                 // File address of new exe header
}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY LoadOrder;
	LIST_ENTRY MemoryOrder;
	LIST_ENTRY InitializationOrder;
	PVOID ModuleBaseAddress;
	PVOID EntryPoint;
	ULONG ModuleSize;
	UNICODE_STRING FullModuleName;
	UNICODE_STRING ModuleName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY Hash;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG TimeStamp;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

ULONG ListKernelModule(PDRIVER_OBJECT pDrvObj, PWCHAR pBuf, ULONG ulLen)
{
	ULONG len = 0;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry0;
	PLIST_ENTRY Next;

	KdPrint(("Input: 0x%X, %d\n", pBuf, ulLen));
	LdrDataTableEntry0 = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;
	Next = LdrDataTableEntry0->LoadOrder.Blink;
	while (TRUE) {
		LdrDataTableEntry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, LoadOrder);
		Next = Next->Blink;
		if (!LdrDataTableEntry->ModuleName.Buffer) {
			break;
		}

		if (LdrDataTableEntry->EntryPoint) {
			if ((pBuf != NULL) && (ulLen > 0)) {
				RtlStringCbCatW(pBuf, ulLen, LdrDataTableEntry->ModuleName.Buffer);
				RtlStringCbCatW(pBuf, ulLen, L",");
			}
			len += wcslen(LdrDataTableEntry->ModuleName.Buffer) + 1;

			KdPrint(("Module Name: %ws\n", LdrDataTableEntry->ModuleName.Buffer));
			KdPrint(("Full Name: %ws\n", LdrDataTableEntry->FullModuleName.Buffer));
			KdPrint(("Base Address: 0x%X\n", LdrDataTableEntry->ModuleBaseAddress));
			KdPrint(("Entry Address: 0x%X\n\n", LdrDataTableEntry->EntryPoint));
		}
		if (LdrDataTableEntry == LdrDataTableEntry0) {
			break;
		}
	}
	return len * 2;
}

BOOLEAN KernelGetModuleBase3(PDRIVER_OBJECT pDrvObj, PWCHAR pModuleName, PULONG pBaseAddr, PULONG pEntryAddr)
{
	BOOLEAN bFound = FALSE;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry0;
	PLIST_ENTRY Next;
	UNICODE_STRING usModuleName;

	RtlInitUnicodeString(&usModuleName, pModuleName);
	LdrDataTableEntry0 = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;
	Next = LdrDataTableEntry0->LoadOrder.Blink;
	while (TRUE) {
		LdrDataTableEntry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, LoadOrder);
		Next = Next->Blink;
		if (!LdrDataTableEntry->ModuleName.Buffer) {
			break;
		}

		if (RtlCompareUnicodeString(&LdrDataTableEntry->ModuleName, &usModuleName, TRUE) == 0) {
			bFound = TRUE;
			*pBaseAddr = (ULONG)(LdrDataTableEntry->ModuleBaseAddress);
			*pEntryAddr = (ULONG)(LdrDataTableEntry->EntryPoint);
			KdPrint(("Module Name: %ws\n", LdrDataTableEntry->ModuleName.Buffer));
			KdPrint(("Full Name: %ws\n", LdrDataTableEntry->FullModuleName.Buffer));
			KdPrint(("Base Address: 0x%X\n", LdrDataTableEntry->ModuleBaseAddress));
			KdPrint(("Entry Address: 0x%X\n\n", LdrDataTableEntry->EntryPoint));
			break;
		}

		if (LdrDataTableEntry == LdrDataTableEntry0) {
			break;
		}
	}
	return bFound;
}

void Unload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	DbgPrint("helper driver unloaded !\n");
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS WriteMemory(ULONG ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		DbgPrint("IoAllocateMdl failed\n");
		return status;
	}
	else {
		__try {
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				DbgPrint("MmMapLockedPagesSpecifyCache failed\n");
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					DbgPrint("MmProtectMdlSystemAddress successed\n");
					RtlCopyMemory(ptrBuffer, pData, ulLen);
					DbgPrint("Write data complete\n");
				}
				else {
					DbgPrint("MmProtectMdlSystemAddress failed 0x%X\n", status);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS ReadMemory(ULONG ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		DbgPrint("IoAllocateMdl failed\n");
		return status;
	}
	else {
		__try {
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				DbgPrint("MmMapLockedPagesSpecifyCache failed\n");
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					DbgPrint("MmProtectMdlSystemAddress successed\n");
					RtlCopyMemory(pData, ptrBuffer, ulLen);
					DbgPrint("Read data complete\n");
				}
				else {
					DbgPrint("MmProtectMdlSystemAddress failed 0x%X\n", status);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	ULONG i = 0;
	ULONG code = 0, len = 0, ptrBaseAddr = 0, ptrEntryAddr = 0, ptrSectionAddr = 0, ulSize = 0;
	BOOLEAN bRet = FALSE;
	PIO_STACK_LOCATION stack = NULL;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (code) {
	case IOCTL_HELPER_GET_MODULE_LIST:
		DbgPrint("List kernel module\n");
		len = ListKernelModule(pDevObj->DriverObject, (PWCHAR)pIrp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
		KdPrint(("Returned len: %d\n", len));
		break;
	case IOCTL_HELPER_GET_BASE_ADDRESS:
		DbgPrint("Get base address: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer);
		bRet = KernelGetModuleBase3(pDevObj->DriverObject, (PWCHAR)pIrp->AssociatedIrp.SystemBuffer, &ptrBaseAddr, &ptrEntryAddr);
		DbgPrint("Base Address: 0x%X\n", ptrBaseAddr);
		DbgPrint("Entry Address: 0x%X\n", ptrEntryAddr);
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrBaseAddr;
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_GET_ENTRY_ADDRESS:
		DbgPrint("Get entry address: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer);
		bRet = KernelGetModuleBase3(pDevObj->DriverObject, (PWCHAR)pIrp->AssociatedIrp.SystemBuffer, &ptrBaseAddr, &ptrEntryAddr);
		DbgPrint("Base Address: 0x%X\n", ptrBaseAddr);
		DbgPrint("Entry Address: 0x%X\n", ptrEntryAddr);
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrEntryAddr;
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_GET_SECTION_COUNT:
		DbgPrint("Get section count: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer);
		bRet = KernelGetModuleBase3(pDevObj->DriverObject, (PWCHAR)pIrp->AssociatedIrp.SystemBuffer, &ptrBaseAddr, &ptrEntryAddr);
		if ((((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
			IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
			IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
			IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
			IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
			*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = pFileheader->NumberOfSections;
			DbgPrint("Section count: %d\n", pFileheader->NumberOfSections);
		}
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_GET_SECTION_ADDRESS:
		DbgPrint("Get section address: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer);
		bRet = KernelGetModuleBase3(pDevObj->DriverObject, (PWCHAR)pIrp->AssociatedIrp.SystemBuffer, &ptrBaseAddr, &ptrEntryAddr);
		if ((((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
			IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
			IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
			IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
			IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
			ptrSectionAddr = (ULONG)sectionHeader;
			for (i = 0; i<pFileheader->NumberOfSections; i++) {
				DbgPrint("------------------------------------------------------------------\n");
				DbgPrint("Section Name = %s\n", sectionHeader->Name);
				DbgPrint("Virtual Offset = %X\n", sectionHeader->VirtualAddress);
				DbgPrint("Virtual Size = %X\n", sectionHeader->Misc.VirtualSize);
				DbgPrint("Raw Offset = %X\n", sectionHeader->PointerToRawData);
				DbgPrint("Raw Size = %X\n", sectionHeader->SizeOfRawData);
				DbgPrint("Characteristics = %X\n", sectionHeader->Characteristics);
				DbgPrint("------------------------------------------------------------------\n");
				sectionHeader++;
			}
		}
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrSectionAddr;
		DbgPrint("Section Address: 0x%X\n", ptrSectionAddr);
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_READ_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		DbgPrint("Read memory: addr 0x%X, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength);
#if 0
		ReadMemory(ptrBaseAddr, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
#else
		RtlCopyMemory((UCHAR*)pIrp->AssociatedIrp.SystemBuffer, (UCHAR*)ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength);
#endif
		len = stack->Parameters.DeviceIoControl.InputBufferLength;
		break;
	case IOCTL_HELPER_WRITE_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		DbgPrint("Write memory: addr 0x%X, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength);
		WriteMemory(ptrBaseAddr, (UCHAR*)pIrp->UserBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
		len = stack->Parameters.DeviceIoControl.InputBufferLength;
		break;
	case IOCTL_HELPER_NEW_MEMORY:
		ulSize = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("New memory: size %d\n", ulSize);
		ptrEntryAddr = (ULONG)ExAllocatePool(NonPagedPool, ulSize);
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrEntryAddr;
		DbgPrint("New memory address 0x%X\n", ptrEntryAddr);
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_FREE_MEMORY:
		ptrEntryAddr = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Free memory: addr 0x%X\n", ptrEntryAddr);
		ExFreePool((PVOID)ptrEntryAddr);
		break;
	default:
		DbgPrint("Invalid IOCTL code: 0x%X\n", code);
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;

	DbgPrint("helper driver loaded\n");
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
