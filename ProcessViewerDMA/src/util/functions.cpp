#include "functions.h"

bool FixCr3(DWORD pid, std::string proc_name)
{
	PVMMDLL_MAP_MODULEENTRY module_entry = NULL;
	bool result = VMMDLL_Map_GetModuleFromNameU(DMA::Handle,pid, const_cast<LPSTR>(proc_name.c_str()), &module_entry, NULL);
	if (result) return true;

	while (true)
	{
		BYTE bytes[4] = { 0 };
		DWORD i = 0;
		auto nt = VMMDLL_VfsReadW(DMA::Handle, const_cast<LPWSTR>(L"\\misc\\procinfo\\progress_percent.txt"), bytes, 3, &i, 0);
		if (nt == VMMDLL_STATUS_SUCCESS && atoi(reinterpret_cast<LPSTR>(bytes)) == 100)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	VMMDLL_VFS_FILELIST2 VfsFileList;
	VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
	VfsFileList.h = 0;
	VfsFileList.pfnAddDirectory = 0;
	VfsFileList.pfnAddFile = cbAddFile; //dumb af callback who made this system

	result = VMMDLL_VfsListU(DMA::Handle, const_cast<LPSTR>("\\misc\\procinfo\\"), &VfsFileList);
	if (!result) return false;

	const size_t buffer_size = cbSize;
	std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
	DWORD j = 0;
	auto nt = VMMDLL_VfsReadW(DMA::Handle, const_cast<LPWSTR>(L"\\misc\\procinfo\\dtb.txt"), bytes.get(), buffer_size - 1, &j, 0);
	if (nt != VMMDLL_STATUS_SUCCESS) return false;

	std::vector<uint64_t> possible_dtbs = { };
	std::string lines(reinterpret_cast<char*>(bytes.get()));
	std::istringstream iss(lines);
	std::string line = "";

	while (std::getline(iss, line))
	{
		Info info = { };

		std::istringstream info_ss(line);
		if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernelAddr >> info.name)
		{
			if (info.process_id == 0) //parts that lack a name or have a NULL pid are suspects
				possible_dtbs.push_back(info.dtb);
			if (proc_name.find(info.name) != std::string::npos)
				possible_dtbs.push_back(info.dtb);
		}
	}

	//loop over possible dtbs and set the config to use it til we find the correct one
	for (size_t i = 0; i < possible_dtbs.size(); i++)
	{
		auto dtb = possible_dtbs[i];
		VMMDLL_ConfigSet(DMA::Handle, VMMDLL_OPT_PROCESS_DTB | pid, dtb);
		result = VMMDLL_Map_GetModuleFromNameU(DMA::Handle, pid, const_cast<LPSTR>(proc_name.c_str()), &module_entry, NULL);
		if (result)
		{
			printf("[+] Patched DTB @ %llx\n", dtb);
			return true;
		}
	}

	return false;
}

bool Read(DWORD pid, uintptr_t address, void* buffer, size_t size)
{
	DWORD read_size = 0;
	if (!VMMDLL_MemReadEx(DMA::Handle, pid, address, (PBYTE)buffer, size, &read_size, VMMDLL_FLAG_NOCACHE))
		return false;

	return (size == read_size);
}

bool DumpMemory(DWORD pid, std::string module_name)
{
	PVMMDLL_MAP_MODULEENTRY module_entry = NULL;
	bool result = VMMDLL_Map_GetModuleFromNameU(DMA::Handle, pid, const_cast<LPSTR>(module_name.c_str()), &module_entry, NULL);
	if (!result) return false;

	/*PVMMDLL_MAP_VAD pVadMap = NULL;
	if (VMMDLL_Map_GetVadU(DMA::Handle, pid, TRUE, &pVadMap)) {
		for (DWORD i = 0; i < pVadMap->cMap; i++) {
			auto& vad = pVadMap->pMap[i];
			VMMDLL_MemPrefetchPages(DMA::Handle, pid, &vad.vaStart, (vad.vaEnd - vad.vaStart) / 0x1000);
		}
		VMMDLL_MemFree(pVadMap);
	}*/

	PIMAGE_SECTION_HEADER sections = nullptr;
	DWORD num_sections = 0;
	if (!VMMDLL_ProcessGetSectionsU(DMA::Handle, pid, const_cast<LPSTR>(module_name.c_str()), NULL, 0, &num_sections))
	{
		printf("[-] Failed To Get Number Of Memory Sections\n");
		return false;
	}
	sections = new IMAGE_SECTION_HEADER[num_sections];

	if (!VMMDLL_ProcessGetSectionsU(DMA::Handle, pid, const_cast<LPSTR>(module_name.c_str()), sections, num_sections, &num_sections))
	{
		printf("[-] Failed To Get Memory Sections\n");
		delete[] sections;
		return false;
	}



	BYTE* buffer = (PBYTE)malloc(module_entry->cbImageSize);
	if (!buffer) 
	{
		printf("[-] Failed to allocate memory for buffer\n");
		return false;
	}

	for (ULONG i = 0x0; i < module_entry->cbImageSize; i += 0x100)
	{
		if (!Read(pid, module_entry->vaBase + i, buffer + i, 0x100))
		{
			printf("[-] Failed Read On %llxn\n", module_entry->vaBase + i);
		}
	}
	printf("[+] Successfully Read Memory Into Buffer\n");

	auto pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);

	if (!pdos_header->e_lfanew)
	{
		printf("[!] Failed to get dos header from buffer\n");
		free(buffer);
		return false;
	}

	printf("[+] Dos header readed: %p\n", pdos_header);

	if (pdos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[!] Invalid dos header signature\n");
		free(buffer);
		return false;
	}

	auto pnt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + pdos_header->e_lfanew);

	if (!pnt_header)
	{
		printf("[!] Failed to read nt header from buffer\n");
		free(buffer);
		return false;
	}

	printf("[+] Nt header readed: 0x%p\n", pnt_header);

	if (pnt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[!] Invalid nt header signature from readed nt header\n");
		free(buffer);
		return false;
	}

	auto poptional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pnt_header->OptionalHeader);

	if (!poptional_header)
	{
		printf("[!] Failed to read optional header from buffer\n");
		free(buffer);
		return false;
	}

	printf("[+] Optional header readed: 0x%p\n", poptional_header);

	int i = 0;
	unsigned int section_offset = poptional_header->SizeOfHeaders;

	for (
		PIMAGE_SECTION_HEADER psection_header = IMAGE_FIRST_SECTION(pnt_header);
		i < pnt_header->FileHeader.NumberOfSections;
		i++, psection_header++
		)
	{
		psection_header->Misc.VirtualSize = psection_header->SizeOfRawData;

		memcpy(buffer + section_offset, psection_header, sizeof(IMAGE_SECTION_HEADER));
		section_offset += sizeof(IMAGE_SECTION_HEADER);

		Read(pid, poptional_header->ImageBase + psection_header->VirtualAddress, buffer + psection_header->PointerToRawData, psection_header->SizeOfRawData);
	}

	std::ofstream Dump(module_name.c_str(), std::ios::binary);
	Dump.write((char*)buffer, module_entry->cbImageSize);
	Dump.close();

	return true;
}