#include "test_driver.h"

BOOLEAN HELPER_GetModuleList(TCHAR *pBuffer, DWORD dwLen)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	memset(pBuffer, 0, dwLen);
	DeviceIoControl(hFile, IOCTL_HELPER_GET_MODULE_LIST, pBuffer, dwLen, pBuffer, dwLen, &dwRet, NULL);
	CloseHandle(hFile);
	return TRUE;
}

DWORD HELPER_GetModuleBaseAddress(TCHAR *pBuffer)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0, dwData = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(DWORD);
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_GET_BASE_ADDRESS, pBuffer, dwInLen, &dwData, dwOutLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwData;
}

DWORD HELPER_GetModuleEntryAddress(TCHAR *pBuffer)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0, dwData = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(DWORD);
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_GET_ENTRY_ADDRESS, pBuffer, dwInLen, &dwData, dwOutLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwData;
}

DWORD HELPER_GetModuleSectionAddress(TCHAR *pBuffer)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0, dwData = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(DWORD);
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_GET_SECTION_ADDRESS, pBuffer, dwInLen, &dwData, dwOutLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwData;
}

DWORD HELPER_GetModuleSectionCount(TCHAR *pBuffer)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0, dwData = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(DWORD);
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_GET_SECTION_COUNT, pBuffer, dwInLen, &dwData, dwOutLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwData;
}

DWORD HELPER_ReadMemory(DWORD dwAddr, BYTE *pRetBuffer, DWORD dwLen)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_READ_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwRet;
}

DWORD HELPER_WriteMemory(DWORD dwAddr, BYTE *pRetBuffer, DWORD dwLen)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_WRITE_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	CloseHandle(hFile);
	return dwRet;
}

DWORD HELPER_NewMemory(DWORD dwLen)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0, dwData;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	bRet = DeviceIoControl(hFile, IOCTL_HELPER_NEW_MEMORY, &dwLen, sizeof(DWORD), &dwData, sizeof(DWORD), &dwRet, NULL);
	CloseHandle(hFile);
	return dwData;
}

VOID HELPER_FreeMemory(DWORD dwAddr)
{
	HANDLE hFile = NULL;
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	hFile = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		bRet = DeviceIoControl(hFile, IOCTL_HELPER_FREE_MEMORY, &dwAddr, sizeof(DWORD), NULL, 0, &dwRet, NULL);
		CloseHandle(hFile);
	}
}
