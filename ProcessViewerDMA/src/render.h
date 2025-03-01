#pragma once
#include <string>
#include <vector>
#include "dependencies/imgui/imgui.h"
#include "dependencies/dma/vmmdll.h"
#include "globals.h"
#include "window.h"
#include "util/functions.h"

struct Tab_t
{
	std::string name;
	DWORD pid = 0;
	bool open = true;
};

inline SIZE_T pids_num = 0;

namespace GUI
{
	inline std::vector<Tab_t> Tabs = { { "Setup" }, { "Processes" } };
	inline int Tab = 0;

	void Render();
	void MenuBar();
	void TabBar();

	void SetupTab();
	void ProcessesTab();
	void ProcessTab(Tab_t Tab);
}