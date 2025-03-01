#include "includes.h"


int main()
{
	if (!Window::Create())
	{
		printf("[-] Failed To Create Window\n");
		std::cin.get();
		return 1;
	}

	printf("[+] Created Window\n");
	printf("[+] Starting Render Loop\n");

	while (Window::StartRender())
	{
		GUI::Render();
		Window::EndRender();
	}

	printf("[+] Destroying Window And Cleaning Up\n");

	Window::Destroy();

	printf("[+] Successfully Cleaned Up\n");

	return 0;
}