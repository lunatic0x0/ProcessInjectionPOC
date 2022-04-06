#include "header.h"
#include "ntapi.h"

HANDLE NtOpenThread(DWORD dwProcessID, DWORD dwThreadID) {

    pNtOpenThread fpNtOpenThread = (pNtOpenThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenThread");
    if (!fpNtOpenThread) {
        printf("[-] Could not fetch NtOpenThread address\n");
        return 0;
    }

    printf("[+] NtOpenThread Address: 0x%p\n", fpNtOpenThread);
    HANDLE ThreadHandle = 0;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);
    ClientId.UniqueProcess = (PVOID)dwProcessID;
    ClientId.UniqueThread = (PVOID)dwThreadID;
    if (NT_SUCCESS(fpNtOpenThread(&ThreadHandle, THREAD_SET_CONTEXT, &ObjectAttributes, &ClientId))) {
        return ThreadHandle;
    }
   
    return 0;
}