#include "injection.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <fstream>
#include <Psapi.h>
#include <tchar.h>

void main(int argc, char* argv[]) {
	if (argc < 3){
		printf("Usage: injector.exe [process_name] [dll_to_inject]");
	}
	else{
		wchar_t process_name[MAX_PATH];
		wchar_t dll_name[MAX_PATH];

		size_t out_size;
		mbstowcs_s(&out_size,process_name, strlen(argv[1])+1,argv[1], strlen(argv[1]));
		mbstowcs_s(&out_size,dll_name, strlen(argv[2]) + 1,argv[2], strlen(argv[2]));
		std::injectDllRemoteProcess(std::getPIDFromName(process_name), dll_name);
	}
}
namespace std {
	void listProcesses() {
		HANDLE process_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 process_information;

		process_information.dwSize = sizeof(PROCESSENTRY32);

		bool temp = Process32First(process_list, &process_information);

		wprintf_s(L"%-48ls %-7ls\n%-48ls %\-7ls\n", L"Process Name", L"PID", L"____________", L"___");
		wprintf_s(L"%-48ls %-7d\n", process_information.szExeFile, process_information.th32ProcessID);

		while (Process32Next(process_list, &process_information)) {
			wprintf_s(L"%-48ls %-7d\n", process_information.szExeFile, process_information.th32ProcessID);
		}
	}

	int getPIDFromName(const wchar_t *process_name) {
		HANDLE process_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 process_information;

		process_information.dwSize = sizeof(PROCESSENTRY32);

		bool temp = Process32First(process_list, &process_information);

		if (lstrcmpW(process_name, process_information.szExeFile) == 0) {
			return process_information.th32ProcessID;
		}

		while (Process32Next(process_list, &process_information)) {
			if (lstrcmpW(process_name, process_information.szExeFile) == 0) {
				return process_information.th32ProcessID;
			}
		}
		return 0;
	}

	void injectDllRemoteProcess(unsigned int PID, const wchar_t *dll_path_) {
		char dll_path[MAX_PATH];
		size_t out_converted;
		wcstombs_s(&out_converted,dll_path, MAX_PATH,dll_path_, MAX_PATH);
		HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
		LPVOID WINAPI base_address = VirtualAllocEx(process_handle, NULL, filesize(dll_path), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(process_handle, base_address, dll_path, strlen(dll_path), NULL);
		LPTHREAD_START_ROUTINE load_library_address = (LPTHREAD_START_ROUTINE)((void*)getAddressOfFunc(process_handle, L"kernel32.dll", "LoadLibraryA"));
		CreateRemoteThread(process_handle, NULL, NULL, load_library_address, base_address, NULL,NULL);
		//VirtualFreeEx(process_handle, base_address, NULL, MEM_RELEASE); // cannot do this because race condition.
	}

	FARPROC getAddressOfFunc(HANDLE process_handle,const wchar_t *dll_name,const char *function_name) {
		HMODULE list_of_modules[1024];
		DWORD cb_needed;
		
		if (EnumProcessModules(process_handle, list_of_modules, sizeof(list_of_modules), &cb_needed)) {
			for (int counter = 0; counter < (cb_needed / sizeof(HMODULE)); counter++) {
				TCHAR dll_name_[MAX_PATH];
				if (GetModuleBaseName(process_handle, list_of_modules[counter], dll_name_, sizeof(dll_name_) / sizeof(TCHAR))) {
					if (wcscmp(dll_name, dll_name_) == 0) {
						return GetProcAddress(list_of_modules[counter], function_name);
					}
				}
			}
		}
		printf("%d", GetLastError());
		return 0;
	}

	int filesize(const char *filename)
	{
		ifstream in(filename, ifstream::ate | ifstream::binary);
		return in.tellg();
	}
}