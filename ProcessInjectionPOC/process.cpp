#include "header.h"
#include "process.h"

BOOL EnableDebugPrivilege(void) {
	LUID	privilegeLuid;
	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &privilegeLuid)) {

		printf("[-] Failed to get SeDebugPrivilege\n ");
		return FALSE;
	}
	TOKEN_PRIVILEGES	tkPrivs;
	tkPrivs.PrivilegeCount = 1; // Only modify one privilege
	tkPrivs.Privileges[0].Luid = privilegeLuid; // specify the privilege to be modified i.e. SeDebugPrivilege
	tkPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // lets enable this privilege
	HANDLE	currentProcessHandle = GetCurrentProcess();
	HANDLE	processToken;
	if (!OpenProcessToken(currentProcessHandle, TOKEN_ADJUST_PRIVILEGES, &processToken)) {
		printf("[-] OpenProcessToken Failed\n");
		return FALSE;
	}

	// Let us now enable debug privileges in the token!

	if (!AdjustTokenPrivileges(processToken, false, &tkPrivs, 0, NULL, NULL)) {
		printf("[-] Failed to enable Privilege\n");
	}
	return TRUE;
}


DWORD ReturnProcessId(const WCHAR processname[])
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 processEntry32;
	ZeroMemory(&processEntry32, sizeof(processEntry32));
	processEntry32.dwSize = sizeof(PROCESSENTRY32);
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	do {
		//printf("%ws ------------ %ws\n", processname, processEntry32.szExeFile);
		if (wcscmp(processEntry32.szExeFile, processname) == 0){
			CloseHandle(hProcessSnap);
			return processEntry32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &processEntry32));
	CloseHandle(hProcessSnap);
	return 0;
}