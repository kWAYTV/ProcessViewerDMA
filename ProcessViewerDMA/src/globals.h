#pragma once

namespace DMA
{
	inline bool Connected = false;
	inline VMM_HANDLE Handle;
	inline ULONG64 FPGA_ID = 0, DEVICE_ID = 0, VersionMajor = 0, VersionMinor = 0;
}