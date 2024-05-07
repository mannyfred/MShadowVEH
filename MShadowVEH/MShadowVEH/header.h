#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)

#define VEH_LIST_OFFSET_WIN10 0x1813F0
#define VEH_LIST_OFFSET_WIN11 0x199400

#define ROL(x, y) ((unsigned long long)(x) << (y) | (unsigned long long)(x) >> 64 - (y))

typedef struct _VECTORED_HANDLER_ENTRY {
	struct _VECTORED_HANDLER_ENTRY* Next;
	struct _VECTORED_HANDLER_ENTRY* Previous;
	ULONG                           Refs;
	PVECTORED_EXCEPTION_HANDLER     Handler;
} VECTORED_HANDLER_ENTRY;

typedef struct _VEH_HANDLER_ENTRY {
	LIST_ENTRY Entry;
	PVOID      VectoredHandler3;
	PVOID      VectoredHandler2;
	PVOID      VectoredHandler1;
} VEH_HANDLER_ENTRY, PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
	PVOID                   MutexException;
	VECTORED_HANDLER_ENTRY* FirstExceptionHandler;
	VECTORED_HANDLER_ENTRY* LastExceptionHandler;
	PVOID                   MutexContinue;
	VECTORED_HANDLER_ENTRY* FirstContinueHandler;
	VECTORED_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

typedef NTSTATUS(NTAPI* fnNtClose)(
	HANDLE	Handle
	);

typedef NTSTATUS(NTAPI* fnNtOpenProcess)(
	PHANDLE				ProcessHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	CLIENT_ID			ClientId
	);

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE				ProcessHandle,
	PROCESSINFOCLASS	ProcessInformationClass,
	PVOID				ProcessInformation,
	ULONG				ProcessInformationLenght,
	PULONG				ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	HANDLE	ProcessHandle,
	PVOID	*BaseAddress,
	SIZE_T	*RegionSize,
	ULONG	NewProtect,
	PULONG	OldProtect
	);

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	PHANDLE				SectionHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	PLARGE_INTEGER		MaximumSize,
	ULONG				SectionPageProtection,
	ULONG				AllocationAttributes,
	HANDLE				FileHandle
	);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	HANDLE				SectionHandle,
	HANDLE				ProcessHandle,
	PVOID*				BaseAddress,
	ULONG_PTR			ZeroBits,
	SIZE_T				CommitSize,
	PLARGE_INTEGER		SectionOffset,
	PSIZE_T				ViewSize,
	ULONG       		InheritDisposition,
	ULONG				AllocationType,
	ULONG				Win32Protect
	);

typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID		BaseAddress,
	PVOID*		Buffer,
	SIZE_T		BufferSize,
	PSIZE_T		NumberOfBytesRead
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID		BaseAddress,
	PVOID*		Buffer,
	SIZE_T		BufferSize,
	PSIZE_T		NumberOfBytesRead
	);