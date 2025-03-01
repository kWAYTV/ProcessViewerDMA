#pragma once
#include <windowsx.h>
#include "dependencies/imgui/imgui.h"
#include "dependencies/imgui/imgui_impl_win32.h"
#include "dependencies/imgui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

inline bool isDragging = false;
inline POINT dragStartPos;

namespace Window
{
	inline WNDCLASSEXW wc;
	inline HWND hwnd;
	inline POINTS Position = { 100, 100 };
	inline int Width = 800, Height = 600;
	inline bool Exiting = true; // imgui changes to false when x is clicked

	bool Create();
	bool StartRender();
	void EndRender();
	void Destroy();
}



