#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "ntapi.h"
#include "process.h"
#include "inject.h"
#pragma once

int main(int argc, char* argv[]){

    if (argc < 3) {
        printf("[-] %s <pid> <dllpath>", argv[0]);
        return 0;
    }
    DWORD OPENPROCESS_TECH = 0, OPENTHREAD_TECH = 0, OPENPROCESS = 1, NTOPENPROCESS = 2, OPENTHREAD = 1, NTOPENTHREAD = 2;
    DWORD MEMALLOC_TECH = 0, VIRTUALALLOC2 = 1, VIRTUALALLOCEX = 2, NTALLOCATEVIRTUALMEMORY = 3, NTCREATESECTION = 4;
    DWORD MEMWRITE_TECH = 0, WRITEPROCESSMEMORY = 1, NTWRITEVIRTUALMEMORY = 2, RTLCOPYMEMORY = 3;
    DWORD INJECT_TECH = 0, CREATEREMOTETHREAD = 1, NTCREATETHREADEX = 2, QUEUEUSERAPC = 3, NTQUEUEAPCTHREAD = 4, RTLCREATEUSERTHREAD = 5;
    DWORD THREADRES_TECH = 0, RESUMETHREAD = 1, NTRESUMETHREAD = 2, NTALERTRESUMETHREAD = 3;

    printf("Select Process AccessTechnique:\n");
    printf("\t1 = OpenProcess\n");
    printf("\t2 = NtOpenProcess\n");
    printf("\tChoose: ");
    DWORD process_access_technique;
    scanf_s("%d", &process_access_technique);

    if (process_access_technique) {
        if (process_access_technique == 1) {
            OPENPROCESS_TECH = OPENPROCESS;
        }
        else if (process_access_technique == 2) {
            OPENPROCESS_TECH = NTOPENPROCESS;
        }
    }

    printf("Select Thread Access Technique:\n");
    printf("\t1 = OpenThread\n");
    printf("\t2 = NtOpenThread\n");
    printf("\tChoose: ");
    DWORD thread_access_technique;
    scanf_s("%d", &thread_access_technique);

    if (thread_access_technique) {
        if (thread_access_technique == 1) {
            OPENTHREAD_TECH = OPENTHREAD;
        }
        else if (thread_access_technique == 2) {
            OPENTHREAD_TECH = NTOPENTHREAD;
        }
    }

    printf("Select Memory Allocation Technique:\n");
    printf("\t1 = VirtualAllocEx\n");
    printf("\t2 = NtAllocateVirtualMemory\n");
    printf("\t3 = NtCreateSection, NtMapViewOfSection\n");
    printf("\tChoose: ");
    DWORD mem_alloc;
    scanf_s("%d", &mem_alloc);

    if (mem_alloc) {
        if(mem_alloc == 1){
            MEMALLOC_TECH = VIRTUALALLOCEX;
        }
        else if (mem_alloc == 2) {
            MEMALLOC_TECH = NTALLOCATEVIRTUALMEMORY;
        }
        else if (mem_alloc == 3) {
            MEMALLOC_TECH = NTCREATESECTION;
        }
    }

    printf("Select Memory Writing Technique:\n");
    printf("\t1 = WriteProcessMemory\n");
    printf("\t2 = NtWriteVirtualMemory\n");
    if(MEMALLOC_TECH == NTCREATESECTION)printf("\t3 = RtlCopyMemory \n");
    printf("\tChoose: ");
    DWORD mem_write;
    scanf_s("%d", &mem_write);

    if (mem_write) {
        if (mem_write == 1) {
            MEMWRITE_TECH = WRITEPROCESSMEMORY;
        }
        else if (mem_write == 2) {
            MEMWRITE_TECH = NTWRITEVIRTUALMEMORY;
        }
        else if (mem_write == 3) {
            MEMWRITE_TECH = RTLCOPYMEMORY;
        }
    }

    printf("Select Injection Technique:\n");
    printf("\t1 = CreateRemoteThread\n");
    printf("\t2 = NtCreateThreadEx\n");
    printf("\t3 = RtlCreateUserThread\n");
    printf("\t4 = QueueUserAPC, ResumeThread\n");
    printf("\t5 = QueueUserAPC, NtResumeThread\n");
    printf("\t6 = QueueUserAPC, NtAlertResumeThread\n");
    printf("\t7 = NtQueueAPCThread, ResumeThread\n");
    printf("\t8 = NtQueueAPCThread, NtResumeThread\n");
    printf("\t9 = NtQueueAPCThread, NtAlertResumeThread\n");
    printf("\tChoose: ");
    DWORD injection_technique;
    scanf_s("%d", &injection_technique);
    if (injection_technique) {
    
        if (injection_technique == 1) {
            INJECT_TECH = CREATEREMOTETHREAD;
        }
        else if (injection_technique == 2) {
            INJECT_TECH = NTCREATETHREADEX;
        }
        else if (injection_technique == 3) {
            INJECT_TECH = RTLCREATEUSERTHREAD;
        }
        else if (injection_technique == 4) {
            INJECT_TECH = QUEUEUSERAPC;
            THREADRES_TECH = RESUMETHREAD;
        }
        else if (injection_technique == 5) {
            INJECT_TECH = QUEUEUSERAPC;
            THREADRES_TECH = NTRESUMETHREAD;
        }
        else if (injection_technique == 6) {
            INJECT_TECH = QUEUEUSERAPC;
            THREADRES_TECH = NTALERTRESUMETHREAD;
        }
        else if (injection_technique == 7) {
            INJECT_TECH = NTQUEUEAPCTHREAD;
            THREADRES_TECH = RESUMETHREAD;
        }
        else if (injection_technique == 8) {
            INJECT_TECH = NTQUEUEAPCTHREAD;
            THREADRES_TECH = NTRESUMETHREAD;
        }
        else if (injection_technique == 9) {
            INJECT_TECH = NTQUEUEAPCTHREAD;
            THREADRES_TECH = NTALERTRESUMETHREAD;
        }
    }
    EnableDebugPrivilege();

    DWORD pid = atoi(argv[1]);

    BOOL ret = InjectionProcedure(pid, argv[2], OPENPROCESS_TECH, OPENTHREAD_TECH, MEMALLOC_TECH, MEMWRITE_TECH, INJECT_TECH, THREADRES_TECH);
    
    return 0;

}