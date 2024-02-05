#include "injection.h"

struct MemoryStruct {
	char* memory;
	size_t size;
};

static size_t
WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;
	char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static int ProgressBar(void* ptr, double TotalToDownload, double NowDownloaded, double TotalToUpload, double NowUploaded) {
	if (TotalToDownload <= 0.0)
		return 0;

	int totaldotz = 40;
	double fractiondownloaded = NowDownloaded / TotalToDownload;
	int dotz = (int)round(fractiondownloaded * totaldotz);
	int ii = 0;

	printf("%3.0f%% [", fractiondownloaded * 100);

	for (; ii < dotz; ii++)
		printf("=");

	for (; ii < totaldotz; ii++)
		printf(" ");

	printf("]\r");
	fflush(stdout);

	return 0;
}

bool ManualMap(HANDLE hProc, const char* DllURL) {
	printf("[DEBUG] Downloading library...\n");

	struct MemoryStruct chunk;
	chunk.memory = (char*)malloc(1);
	chunk.size = 0;

	CURL* curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, DllURL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, FALSE);
	curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, ProgressBar);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	CURLcode CURLresult = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	if (CURLresult != CURLE_OK) {
		printf("[-] CURLresult: %d\n", CURLresult);
		return false;
	}

	printf("\n[DEBUG] Injecting...\n");

	BYTE* pSrcData = reinterpret_cast<BYTE*>(chunk.memory);
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		printf("[-] e_magic != 0x5A4D\n");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		printf("[-] VirtualAllocEx [1] Error: 0x%d\n", GetLastError());
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = 0;
	data.SEHSupport = true;

	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [1] Error: 0x%d\n", GetLastError());
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				printf("[-] WriteProcessMemory [2] Error: 0x%d\n", GetLastError());
				return false;
			}
		}
	}

	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		printf("[-] VirtualAllocEx [2] Error: 0x%d\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [3] Error: 0x%d\n", GetLastError());
		return false;
	}

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		printf("[-] VirtualAllocEx [3] Error: 0x%d\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [4] Error: 0x%d\n", GetLastError());
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		printf("[-] CreateRemoteThread Error: 0x%d\n", GetLastError());
		return false;
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			printf("[-] GetExitCodeProcess != STILL_ACTIVE\n");
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			printf("[-] hCheck == 0x404040\n");
			return false;
		}

		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024);
	if (emptyBuffer == nullptr) {
		printf("[-] emptyBuffer == nullptr\n");
		return false;
	}

	memset(emptyBuffer, 0, 1024 * 1024);
	WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr);

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			DWORD old = 0;
			DWORD newP = PAGE_READONLY;

			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
				newP = PAGE_READWRITE;
			else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
				newP = PAGE_EXECUTE_READ;
			VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old);
		}
	}

	DWORD old = 0;
	VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);

	WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr);
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);

	free(chunk.memory);

	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG RELOC_FLAG64

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
