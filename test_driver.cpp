#include "test_driver.h"
#include <stdio.h>

void LOG(TCHAR *fmt, ...)
{
	TCHAR szBuf[MAX_PATH] = { 0 };

	va_list ap;
	va_start(ap, fmt);
	_vstprintf_s(szBuf, fmt, ap);
	va_end(ap);
	OutputDebugString(szBuf);
}

BOOLEAN Run(void)
{

	TCHAR *MODULE_NAME = _T("Ntfs.sys");
	DWORD i = 0, dwRet = 0;
	DWORD dwBaseAddr = 0, dwEntryAddr = 0, dwSectionAddr = 0, dwSectionCnt = 0, dwTextAddr = 0, dwTextSize = 0;
	IMAGE_SECTION_HEADER sectionHeader[10] = { 0 };
	BYTE buf[4] = { 0 };

	dwBaseAddr = HELPER_GetModuleBaseAddress(MODULE_NAME);
	dwEntryAddr = HELPER_GetModuleEntryAddress(MODULE_NAME);
	dwSectionAddr = HELPER_GetModuleSectionAddress(MODULE_NAME);
	dwSectionCnt = HELPER_GetModuleSectionCount(MODULE_NAME);
	LOG(_T("Base address: 0x%X\n"), dwBaseAddr);
	LOG(_T("Entry address: 0x%X\n"), dwEntryAddr);
	LOG(_T("Section address: 0x%X\n"), dwSectionAddr);
	LOG(_T("Section count: %d\n"), dwSectionCnt);

	if (dwEntryAddr == EOF) {
		LOG(_T("Can't get entry address \n"));
		return FALSE;
	}
	// parse section header
	if (HELPER_ReadMemory(dwSectionAddr, (BYTE*)sectionHeader, sizeof(IMAGE_SECTION_HEADER) * dwSectionCnt) == EOF) {
		LOG(_T("Can't read memory\n"));
		return FALSE;
	}

	for (i = 0; i<dwSectionCnt; i++) {
		if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
			dwTextAddr = sectionHeader[i].VirtualAddress;
			dwTextSize = sectionHeader[i].Misc.VirtualSize;

			// read data of ".text" section
			if (HELPER_ReadMemory(dwBaseAddr + dwTextAddr, (BYTE*)buf, sizeof(buf)) == EOF) {
				LOG(_T("Can't read memory\n"));
				return FALSE;
			}

			for (i = 0; i<sizeof(buf); i++) {
				LOG(_T(".text Data-%d: 0x%X\n"), i, buf[i]);
			}
			break;
		}
	}

	// allocate kernel memory
	if ((dwBaseAddr = HELPER_NewMemory(4)) == EOF) {
		LOG(_T("Can't new memory\n"));
		return FALSE;
	}
	LOG(_T("New memory address: 0x%X\n"), dwBaseAddr);

	// write memory
	buf[0] = 0x55;
	buf[1] = 0x66;
	buf[2] = 0x77;
	buf[3] = 0x88;
	if (HELPER_WriteMemory(dwBaseAddr, (BYTE*)buf, sizeof(buf)) == EOF) {
		LOG(_T("Can't write memory\n"));
		return FALSE;
	}

	// read modified memory
	memset(buf, 0, sizeof(buf));
	if (HELPER_ReadMemory(dwBaseAddr, (BYTE*)buf, sizeof(buf)) == EOF) {
		LOG(_T("Can't read memory\n"));
		return FALSE;
	}
	for (i = 0; i<sizeof(buf); i++) {
		LOG(_T("Modified Memory-%d: 0x%X\n"), i, buf[i]);
	}
	HELPER_FreeMemory(dwBaseAddr);

	LOG(_T("Run complete\n"));
	return TRUE;
}

BOOLEAN ListModule(void)
{
	int i = 0;
	TCHAR *ptr = NULL;
	TCHAR pBuffer[4096] = { 0 };

	if (HELPER_GetModuleList(pBuffer, sizeof(pBuffer)) == FALSE) {
		LOG(_T("Can't open cvg driver !\n"));
		return FALSE;
	}

	_tprintf(_T("Module Name: "));
	ptr = pBuffer;
	do {
		if (pBuffer[i] == L'\x00') {
			break;
		}

		if (pBuffer[i] == L',') {
			pBuffer[i] = L'\x00';
			_tprintf(_T("%s "), ptr);
			ptr = &pBuffer[i + 1];
		}
		i += 1;
	} while (1);
	LOG(_T("\nListModule complete\n"));
	return TRUE;
}

BOOLEAN LoadDriver(void)
{
	if (system("sc create cvg binPath= \"c:\\windows\\system32\\cvg.sys\" type= \"kernel\" start= \"demand\" error= \"normal\" Displayname= \"cvg\"")) {
		LOG(_T("Can't create cvg driver !\n"));
		return FALSE;
	}
	if (system("sc start cvg")) {
		LOG(_T("Can't start cvg driver !\n"));
		return FALSE;
	}

	LOG(_T("LoadDriver complete\n"));
	return TRUE;
}

BOOLEAN UnloadDriver(void)
{
	system("sc stop cvg");
	system("sc delete cvg");
	LOG(_T("UnloadDriver complete\n"));
	return TRUE;
}

void go()
{
	LoadDriver();
	ListModule();
	Run();
	UnloadDriver();
}

int main() {
	go();
}
