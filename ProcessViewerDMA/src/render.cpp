#include "render.h"

void GUI::Render()
{
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2((float)Window::Width, (float)Window::Height));
	ImGui::Begin("ProcessViewer", &Window::Exiting, 
		ImGuiWindowFlags_NoResize | 
		ImGuiWindowFlags_NoSavedSettings | 
		ImGuiWindowFlags_NoCollapse | 
		ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_MenuBar
	);

	GUI::MenuBar();
	GUI::TabBar();

	ImGui::End();
}

void GUI::MenuBar()
{
	if (ImGui::BeginMenuBar())
	{
		if (ImGui::BeginMenu("View"))
		{
			if (ImGui::MenuItem("Setup")) GUI::Tabs[0].open = true;
			if (ImGui::MenuItem("Processes")) GUI::Tabs[1].open = true;
			ImGui::EndMenu();
		}
		ImGui::EndMenuBar();
	}
}

void GUI::TabBar()
{
	if (ImGui::BeginTabBar("##1"))
	{
		for (int ctab = 0; ctab < GUI::Tabs.size(); ++ctab)
		{
			if (ImGui::BeginTabItem(GUI::Tabs[ctab].name.c_str(), &GUI::Tabs[ctab].open))
			{
				if (GUI::Tabs[ctab].name == "Setup")
					GUI::SetupTab();
				else if (GUI::Tabs[ctab].name == "Processes")
					GUI::ProcessesTab();
				else
					GUI::ProcessTab(GUI::Tabs[ctab]);
				ImGui::EndTabItem();
			}
		}

		ImGui::EndTabBar();
	}
}

void GUI::SetupTab()
{
	ImGui::Text("Status : %s", DMA::Connected ? "Connected" : "Not Connected");
	if (!DMA::Connected)
	{
		if (ImGui::Button("Connect"))
		{
			std::vector<LPCSTR> args;
			args.push_back("");
			args.push_back("-device");
			args.push_back("fpga://algo=0");
			args.push_back("");

			printf("[+] Attempting VMMDLL_Initialize\n");

			DMA::Handle = VMMDLL_Initialize(args.size(), args.data());
			if (DMA::Handle)
			{
				printf("[+] VMMDLL_Initialize Successful\n");
				DMA::Connected = true;
				VMMDLL_ConfigGet(DMA::Handle, LC_OPT_FPGA_FPGA_ID, &DMA::FPGA_ID);
				VMMDLL_ConfigGet(DMA::Handle, LC_OPT_FPGA_DEVICE_ID, &DMA::DEVICE_ID);
				VMMDLL_ConfigGet(DMA::Handle, LC_OPT_FPGA_VERSION_MAJOR, &DMA::VersionMajor);
				VMMDLL_ConfigGet(DMA::Handle, LC_OPT_FPGA_VERSION_MINOR, &DMA::VersionMinor);

				VMMDLL_InitializePlugins(DMA::Handle);
			}
		}
	}
	else
	{
		ImGui::Text("FPGA ID : %i", DMA::FPGA_ID);
		ImGui::Text("Device ID : %i", DMA::DEVICE_ID);
		ImGui::Text("Version : %i.%i", DMA::VersionMajor, DMA::VersionMinor);
	}
}

void GUI::ProcessesTab()
{
	SIZE_T pids_num = 0;
	DWORD* pid_list = nullptr;
	VMMDLL_PidList(DMA::Handle, nullptr, &pids_num);
	pid_list = new DWORD[pids_num];
	VMMDLL_PidList(DMA::Handle, pid_list, &pids_num);

	static char SearchText[256];
	ImGui::InputText("Search", SearchText, sizeof(SearchText));
	if (ImGui::BeginTable("table1", 3))
	{
		ImGui::TableSetupColumn("Process Name");
		ImGui::TableSetupColumn("PID");
		ImGui::TableSetupColumn("Status");

		ImGui::TableHeadersRow();

		for (int i = 0; i < pids_num; ++i)
		{
			VMMDLL_PROCESS_INFORMATION pProcessInformationEntry{};
			SIZE_T info_size = sizeof(VMMDLL_PROCESS_INFORMATION);
			VMMDLL_PROCESS_INFORMATION info{};
			pProcessInformationEntry.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
			pProcessInformationEntry.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
			if (!VMMDLL_ProcessGetInformation(DMA::Handle, pid_list[i], &pProcessInformationEntry, &info_size)) continue;
			if (!std::string(SearchText).empty() && std::string(pProcessInformationEntry.szNameLong).find(SearchText) == std::string::npos) continue;

			ImGui::TableNextRow(); 

			ImGui::PushID(i);

			ImGui::TableSetColumnIndex(0);
			ImGui::Text("%s", pProcessInformationEntry.szNameLong);
			if (ImGui::BeginPopupContextItem(""))
			{
				if (ImGui::Button("Open"))
				{
					GUI::Tabs.push_back({ pProcessInformationEntry.szNameLong, pProcessInformationEntry.dwPID });
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
			ImGui::TableSetColumnIndex(1);;
			ImGui::Text("%i", pProcessInformationEntry.dwPID);
			ImGui::TableSetColumnIndex(2);
			ImGui::Text("%s", (pProcessInformationEntry.dwPID % 2 == 0) ? "Running" : "Idle");

			ImGui::PopID();
		}
		ImGui::EndTable();
	}
}

void GUI::ProcessTab(Tab_t Tab)
{
	if (!FixCr3(Tab.pid, Tab.name))
	{
		printf("[-] Failed To Fix Cr3\n");
		return;
	}

	std::string proc_name = Tab.name;
	PVMMDLL_MAP_MODULE modules_list = NULL;
	if (!VMMDLL_Map_GetModuleU(DMA::Handle, Tab.pid, &modules_list, VMMDLL_MODULE_FLAG_NORMAL))
	{
		printf("[-] VMMDLL_Map_GetModuleU Failed\n");
		return;
	}

	std::wstring str(proc_name.begin(), proc_name.end());
	PVMMDLL_MAP_MODULEENTRY module_info;
	if (!VMMDLL_Map_GetModuleFromNameW(DMA::Handle, Tab.pid, const_cast<LPWSTR>(str.c_str()), &module_info, VMMDLL_MODULE_FLAG_NORMAL))
	{
		printf("[-] VMMDLL_Map_GetModuleFromNameW Failed\n");
		return; // cr3 fix later
	}
	  
	if (ImGui::BeginTabBar("##2"));
	if (ImGui::BeginTabItem("Overview"))
	{
		if (ImGui::BeginTable("table2", 2))
		{
			ImGui::TableNextColumn();
			ImGui::Text("Name");
			ImGui::TableNextColumn();
			ImGui::Text("%s", proc_name.c_str());

			ImGui::TableNextColumn();
			ImGui::Text("PID");
			ImGui::TableNextColumn();
			ImGui::Text("%i", Tab.pid);

			ImGui::TableNextColumn();
			ImGui::Text("Image Base");
			ImGui::TableNextColumn();
			ImGui::Text("%llx", module_info->vaBase);

			ImGui::TableNextColumn();
			ImGui::Text("Image Size");
			ImGui::TableNextColumn();
			ImGui::Text("%llx", module_info->cbImageSize);

			ImGui::EndTable();
		}

		ImGui::EndTabItem();
	}
	if (ImGui::BeginTabItem("Modules"))
	{
		if (ImGui::BeginTable("table3", 3))
		{
			ImGui::TableSetupColumn("Module Name");
			ImGui::TableSetupColumn("Base Address");
			ImGui::TableSetupColumn("Module Size");

			ImGui::TableHeadersRow();

			for (int i = 0; i < modules_list->cMap; ++i)
			{
				ImGui::PushID(i + 0x1000);

				ImGui::TableNextColumn();
				ImGui::Text("%s", modules_list->pMap[i].uszText);

				if (ImGui::BeginPopupContextItem("##1"))
				{
					if (ImGui::Button("Dump"))
					{
						if (!DumpMemory(Tab.pid, modules_list->pMap[i].uszText))
							printf("[-] Failed To Dump Memory\n");
						else
							printf("[+] Successfully Dumped Memory\n");
						ImGui::CloseCurrentPopup();
					}
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();
				ImGui::Text("%llx", modules_list->pMap[i].vaBase);
				ImGui::TableNextColumn();
				ImGui::Text("%llx", modules_list->pMap[i].cbImageSize);

				ImGui::PopID();
			}

			ImGui::EndTable();
		}

		ImGui::EndTabItem();
	}
	ImGui::EndTabBar();
}