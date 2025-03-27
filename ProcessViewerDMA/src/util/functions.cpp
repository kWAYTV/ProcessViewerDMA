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
	ULONG64 flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOCACHEPUT | VMMDLL_FLAG_ZEROPAD_ON_FAIL;
	if (!VMMDLL_MemReadEx(DMA::Handle, pid, address, (PBYTE)buffer, size, &read_size, flags))
	{
		return false;
	}

	return true;
}

bool DumpMemory(DWORD pid, std::string module_name)
{
    PVMMDLL_MAP_MODULEENTRY module_entry = NULL;
    bool result = VMMDLL_Map_GetModuleFromNameU(DMA::Handle, pid, const_cast<LPSTR>(module_name.c_str()), &module_entry, NULL);
    if (!result) return false;

    BYTE* buffer = (PBYTE)malloc(module_entry->cbImageSize);
    if (!buffer)
    {
        printf("[-] Failed to allocate memory for buffer\n");
        return false;
    }

    std::vector<ULONG> failed_reads;

    // Read the module's memory into buffer
    for (ULONG i = 0x0; i < module_entry->cbImageSize - 0x1000; i += 0x1000)
    {
        if (!Read(pid, module_entry->vaBase + i, buffer + i, 0x1000))
        {
            failed_reads.push_back(i);
        }
    }

    // Retry failed reads with smaller chunks
    for (int i = 0; i < failed_reads.size(); i++)
    {
        for (int offset = 0; offset < 0x10; offset++)
        {
            Read(pid, module_entry->vaBase + failed_reads[i] * offset, buffer + failed_reads[i] * offset, 0x100);
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

    printf("[+] Dos header read: %p\n", pdos_header);

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

    printf("[+] NT header read: 0x%p\n", pnt_header);

    if (pnt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[!] Invalid nt header signature from read nt header\n");
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

    printf("[+] Optional header read: 0x%p\n", poptional_header);

    unsigned int section_offset = poptional_header->SizeOfHeaders;

    // Read Sections
    for (int i = 0; i < pnt_header->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER psection_header = IMAGE_FIRST_SECTION(pnt_header) + i;
        psection_header->Misc.VirtualSize = psection_header->SizeOfRawData;

        memcpy(buffer + section_offset, psection_header, sizeof(IMAGE_SECTION_HEADER));
        section_offset += sizeof(IMAGE_SECTION_HEADER);

        Read(pid, poptional_header->ImageBase + psection_header->VirtualAddress, buffer + psection_header->PointerToRawData, psection_header->SizeOfRawData);
    }

    // Rebuild Import Table
    PIMAGE_DATA_DIRECTORY importDir = &poptional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->VirtualAddress != 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(buffer + importDir->VirtualAddress);

        while (importDesc->Name)
        {
            char* moduleName = (char*)buffer + importDesc->Name;
            printf("[+] Rebuilding import: %s\n", moduleName);

            PVMMDLL_MAP_IAT iatMap = nullptr;
            if (!VMMDLL_Map_GetIATU(DMA::Handle, pid, moduleName, &iatMap))
            {
                printf("[-] Failed to get import address table for %s\n", moduleName);
                importDesc++;
                continue;
            }

            PIMAGE_THUNK_DATA originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(buffer + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(buffer + importDesc->FirstThunk);

            while (originalThunk->u1.Function)
            {
                if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    // If it's an ordinal, we resolve by ordinal
                    DWORD ordinal = originalThunk->u1.Ordinal & 0xFFFF;
                    FARPROC procAddr = nullptr;

                    for (DWORD i = 0; i < iatMap->cMap; i++)
                    {
                        if (iatMap->pMap[i].Thunk.rvaFirstThunk == ordinal)
                        {
                            procAddr = reinterpret_cast<FARPROC>(iatMap->pMap[i].vaFunction);
                            break;
                        }
                    }

                    if (procAddr)
                    {
                        firstThunk->u1.Function = reinterpret_cast<DWORD_PTR>(procAddr);
                        printf("[+] Resolved ordinal: 0x%x to address: 0x%p\n", ordinal, procAddr);
                    }
                    else
                    {
                        printf("[-] Failed to resolve ordinal: 0x%x\n", ordinal);
                    }
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(buffer + originalThunk->u1.AddressOfData);
                    char* functionName = (char*)importByName->Name;
                    FARPROC procAddr = nullptr;

                    // Search the IAT map for the function name
                    for (DWORD i = 0; i < iatMap->cMap; i++)
                    {
                        if (strcmp(functionName, (char*)iatMap->pbMultiText + iatMap->pMap[i].Thunk.rvaNameFunction) == 0)
                        {
                            procAddr = reinterpret_cast<FARPROC>(iatMap->pMap[i].vaFunction);
                            break;
                        }
                    }

                    if (procAddr)
                    {
                        firstThunk->u1.Function = reinterpret_cast<DWORD_PTR>(procAddr);
                        printf("[+] Resolved function: %s to address: 0x%p\n", functionName, procAddr);
                    }
                    else
                    {
                        printf("[-] Failed to resolve function: %s\n", functionName);
                    }
                }

                originalThunk++;
                firstThunk++;
            }

            VMMDLL_MemFree(iatMap);
            importDesc++;
        }
    }

    // Rebuild Export Table
    PIMAGE_DATA_DIRECTORY exportDir = &poptional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress != 0)
    {
        PIMAGE_EXPORT_DIRECTORY exportDesc = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(buffer + exportDir->VirtualAddress);
        printf("[+] Rebuilding export table\n");

        // Extract pointers to export addresses, names, and ordinals
        DWORD* addressOfNames = reinterpret_cast<DWORD*>(buffer + exportDesc->AddressOfNames);
        WORD* addressOfNameOrdinals = reinterpret_cast<WORD*>(buffer + exportDesc->AddressOfNameOrdinals);
        DWORD* addressOfFunctions = reinterpret_cast<DWORD*>(buffer + exportDesc->AddressOfFunctions);

        // Iterate over the number of functions to rebuild the export table
        for (DWORD i = 0; i < exportDesc->NumberOfNames; i++)
        {
            // Retrieve the name of the exported function
            char* functionName = reinterpret_cast<char*>(buffer + addressOfNames[i]);
            printf("[+] Rebuilding export function: %s\n", functionName);

            // Retrieve the function's ordinal and corresponding address in the export table
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];

            // Find the corresponding function's address (you might need to resolve this address based on the context)
            FARPROC procAddr = reinterpret_cast<FARPROC>(functionRVA + poptional_header->ImageBase);

            if (procAddr)
            {
                // Update the function's address in the export table
                addressOfFunctions[ordinal] = reinterpret_cast<DWORD>(procAddr);
                printf("[+] Updated export function: %s to address: 0x%p\n", functionName, procAddr);
            }
            else
            {
                printf("[-] Failed to resolve export function: %s\n", functionName);
            }
        }
    }

    // Write the modified memory back to the file (dump it)
    std::ofstream Dump(module_name.c_str(), std::ios::binary);
    if (!Dump.is_open())
    {
        printf("[-] Failed to open dump file\n");
        free(buffer);
        return false;
    }

    Dump.write((char*)buffer, module_entry->cbImageSize);
    Dump.close();

    free(buffer);
    return true;
}
