#ifndef INJECTOR_H
#define INJECTOR_H
#include <Windows.h>
namespace std {
	void listProcesses();
	int getPIDFromName(const wchar_t *process_name);
	void injectDllRemoteProcess(unsigned int PID, const wchar_t *dll_path_);
	int filesize(const char *filename);
	FARPROC getAddressOfFunc(HANDLE process_handle, const wchar_t *dll_name,const char *function_name);
}
#endif INJECTOR_H