#include "header.h"
#pragma once

//typedef VOID(NTAPI* PIO_APC_ROUTINE)(
//    IN PVOID            ApcContext,
//    IN PIO_STATUS_BLOCK IoStatusBlock,
//    IN ULONG            Reserved
//    );

typedef VOID KNORMAL_ROUTINE(
	__in_opt PVOID NormalContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

struct NtCreateThreadExBuffer
{
    SIZE_T	Size;
    SIZE_T	Unknown1;
    SIZE_T	Unknown2;
    PULONG	Unknown3;
    SIZE_T	Unknown4;
    SIZE_T	Unknown5;
    SIZE_T	Unknown6;
    PULONG	Unknown7;
    SIZE_T	Unknown8;
};

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS(NTAPI* pNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID, ULONG, ULONG, PLARGE_INTEGER, PULONG, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, CLIENT_ID*);
typedef NTSTATUS(NTAPI* pNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pNtAlertResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG);
typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS(WINAPI* pNtResumeThread)(HANDLE, PULONG);

HANDLE NtOpenThread(DWORD dwProcessID, DWORD dwThreadID);

