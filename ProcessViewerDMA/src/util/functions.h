#pragma once
#include <fstream>
#include <thread>
#include <chrono>
#include "../dependencies/dma/vmmdll.h"
#include "../globals.h"
#include "../render.h"

inline uint64_t cbSize = 0x80000;
//callback for VfsFileListU
inline VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
	if (strcmp(uszName, "dtb.txt") == 0)
		cbSize = cb;
}

struct Info
{
	uint32_t index;
	uint32_t process_id;
	uint64_t dtb;
	uint64_t kernelAddr;
	std::string name;
};

bool FixCr3(DWORD pid, std::string proc_name);
bool Read(DWORD pid, uintptr_t address, void* buffer, size_t size);
bool DumpMemory(DWORD pid, std::string proc_name);