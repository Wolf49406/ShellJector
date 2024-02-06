#include "injection.h"

int GetPIDByName(const char* ProcName) {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot error: 0x%X\n", GetLastError());
		system("pause");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32FirstW(hSnap, &PE32);
	while (bRet) {
		if (!strcmp(ProcName, _bstr_t(PE32.szExeFile))) {
			PID = PE32.th32ProcessID;
			break;
		}

		bRet = Process32NextW(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	return PID;
}

HANDLE OpenProc(const char* ProcName) {
	int PID = GetPIDByName(ProcName);
	if (PID == 0) {
		printf("[-] Can't get %s PID\n", ProcName);
		system("pause");
		return nullptr;
	}

	printf("[+] %s PID: %d\n", ProcName, PID);

	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	if (!hProc) {
		printf("[-] OpenProcess error: 0x%X\n", GetLastError());
		system("pause");
		return nullptr;
	}

	return hProc;
}
