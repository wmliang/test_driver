#ifndef __HELPER_DRIVER_H__
#define __HELPER_DRIVER_H__

#include <windows.h>
#include <Winbase.h>
#include <winioctl.h>
#include <tchar.h>
#include "helper/main.h"
#define DRIVER_NAME _T("\\\\.\\helper")

DWORD HELPER_NewMemory(DWORD dwSize);
VOID HELPER_FreeMemory(DWORD dwAddr);
DWORD HELPER_GetModuleBaseAddress(TCHAR *pBuffer);
DWORD HELPER_GetModuleEntryAddress(TCHAR *pBuffer);
DWORD HELPER_GetModuleSectionAddress(TCHAR *pBuffer);
DWORD HELPER_GetModuleSectionCount(TCHAR *pBuffer);
BOOLEAN HELPER_GetModuleList(TCHAR *pBuffer, DWORD dwLen);
DWORD HELPER_ReadMemory(DWORD dwAddr, BYTE *pRetBuffer, DWORD dwLen);
DWORD HELPER_WriteMemory(DWORD dwAddr, BYTE *pRetBuffer, DWORD dwLen);

#endif
