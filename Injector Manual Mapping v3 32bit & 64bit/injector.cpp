#include "common_definitions.h"

bool startInjection(dllInfo DllInfo, processInfo ProcessInfo) {
	// Checks pID is still valid. Incases where program crashed/restarted
	DWORD64 tempPID = ProcessInfo.pID;
	ProcessCheck(ProcessInfo);
	if (ProcessInfo.pID != tempPID) {
		printf("PID changed\n");
	}

	// Opening target process.
	HANDLE64 hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ProcessInfo.pID);
	if (hProcess == NULL) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error opening target process. Error code: " << errorCode << std::endl;
		return false;
	}

	// Allocating memory for the DLL
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, DllInfo.NtHeader->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ExecutableImage == NULL) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error allocating memory for the DLL in target process. Error code: " << errorCode << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	// Copy the headers to target process
	if (!WriteProcessMemory(hProcess, ExecutableImage, DllInfo.FileBuffer, DllInfo.NtHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error writing headers to target process. Error code: " << errorCode << std::endl;
		VirtualFreeEx(hProcess, ExecutableImage, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(DllInfo.NtHeader + 1);

	// Copying sections of the DLL to the target process
	for (int i = 0; i < DllInfo.NtHeader->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),(PVOID)((LPBYTE)DllInfo.FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	// Allocating memory for the loader code.
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (LoaderMemory == NULL) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error allocating memory for loader code in target process. Error code: " << errorCode << std::endl;
		VirtualFreeEx(hProcess, ExecutableImage, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Initialize params for LibraryLoader()
	loaderdata LoaderParams = LoaderDataInit(ExecutableImage, DllInfo.DosHeader, DllInfo.NtHeader);
	if (!WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata), NULL)) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error writing loader parameters to target process. Error code: " << errorCode << std::endl;
		VirtualFreeEx(hProcess, ExecutableImage, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Write the loader code to target process
	if (!WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), &LibraryLoader, (DWORD64)stub - (DWORD64)LibraryLoader, NULL)) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error writing loader code to target process. Error code: " << errorCode << std::endl;
		VirtualFreeEx(hProcess, ExecutableImage, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);
	if (hThread == NULL) {
		DWORD errorCode = GetLastError();
		std::cerr << "Error creating remote thread. Error code: " << errorCode << std::endl;
		VirtualFreeEx(hProcess, ExecutableImage, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	std::cout << "\nAddress of Loader: " << std::hex << LoaderMemory << std::endl;
	std::cout << "Address of Image: " << std::hex << ExecutableImage << "\n" << std::endl;

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE);

	// Free the allocated loader code
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}