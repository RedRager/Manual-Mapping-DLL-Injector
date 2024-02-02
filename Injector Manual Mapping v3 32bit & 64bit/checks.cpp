#include "common_definitions.h"

// Assigns DLL infomation to a struct for later use
// Handles errors for loading DLL and checks the platform the DLL is build for
bool DllCheck(dllInfo& info) {

	printf("\nChecking DLL\n");

	// Checks if the path actual exists
	if (!validPath(info.DllPathString)) {
		printf("Failed to load DLL: DLL path does not exist\n");
		return false;
	}

	// Stores LPCSTR to DLL path makes it easier for later
	info.DllPath = info.DllPathString.c_str();

	// Loads file into memory and handles errors
	info.FileBuffer = LoadFileIntoMemory(info.DllPath);
	if (!info.FileBuffer) {
		printf("Failed to load DLL into memory: %x\n", GetLastError());
		return false;
	}

	// Stores target Dll's headers
	info.DosHeader = (PIMAGE_DOS_HEADER)info.FileBuffer;
	info.NtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)info.FileBuffer + info.DosHeader->e_lfanew);
	info.FileHeader = (PIMAGE_FILE_HEADER)&info.NtHeader->FileHeader;

	// Print some info to console
	if (info.FileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("DLL file platform: 64bit\n");
	}
	else if (info.FileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
		printf("DLL file platform: 32bit\n");
	}
	else {
		printf("DLL file platform: unknown\n");
	}

	// Ensure the correct platform is used for the injector
#ifdef _WIN64
	if (info.FileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("DLL build for invalid plaform please use 64bit only\n");
		return false;
	}
#else
	if (info.FileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		printf("DLL build for invalid plaform please use 32bit only\n");
		return false;
	}
#endif

	return true;
}

// Used by DllCheck() to load DLL into memory and return a buffer for it
PVOID LoadFileIntoMemory(LPCSTR Dll) {
	HANDLE hFile = CreateFileA(Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Failed to open file %s: %lu\n", Dll, GetLastError());
		return nullptr;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);
	if (FileSize == INVALID_FILE_SIZE) {
		printf("Failed to get file size: %lu\n", GetLastError());
		CloseHandle(hFile);
		return nullptr;
	}
	
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (FileBuffer == nullptr) {
		printf("Failed to allocate memory: %lu\n", GetLastError());
		CloseHandle(hFile);
		return nullptr;
	}

	DWORD bytesRead;
	if (!ReadFile(hFile, FileBuffer, FileSize, &bytesRead, NULL)) {
		printf("Failed to read file: %lu\n", GetLastError());
		VirtualFree(FileBuffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return nullptr;
	}

	if (bytesRead != FileSize) {
		printf("ReadFile did not read the entire file: expected %lu bytes, read %lu bytes\n", FileSize, bytesRead);
		VirtualFree(FileBuffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return nullptr;
	}

	CloseHandle(hFile);
	return FileBuffer;
}

// Valids any paths
// Only used for DllCheck()
bool validPath(const string& path) {
	fs::path filePath(path);

	if (!fs::exists(filePath)) {
		return false;
	}
	return true;
}

// Valids the give process ID or name
bool ProcessCheck(processInfo& info) {
	map<DWORD64, string> processList = listProcesses();

	if (isPid(info.process)) {
		const auto& entry = processList.find(stringToDWORD(info.process));
		if (entry != processList.end()) {
			printf("\nProcess found:\n");
			cout << "PID: " << setw(pidWidth) << entry->first << ", Process Name: " << entry->second << endl;
			
			info.pID = entry->first;
			info.process = entry->second;
		}
	}
	else {
		DWORD64 pID = FindProcessId(info.process);

		if (pID == 0) {
			printf("\nProcess not found\n");
			return false;
		}

		printf("\nProcess found:\n");
		cout << "PID: " << setw(pidWidth) << pID << ", Process Name: " << info.process << endl;

		info.pID = pID;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)info.pID);
	if (hProcess == NULL) {
		printf("Failed to open process: %x\n", GetLastError());
		return false;
	}

	BOOL isWow64 = FALSE;
	if (IsWow64Process(hProcess, &isWow64) && isWow64) {
#ifdef _WIN64
		printf("\nInavlid platform: Please only use 64bit processes with this injector\n");
		return false;
#endif // _WIN64
		printf("Process platform: 32-bit (WOW64)\n");
	}
	else {
#ifdef _M_IX86
		printf("\nInavlid platform: Please only use 32bit processes with this injector\n");
		return false;
#endif //_M_IX86
		printf("Process platform: 64-bit\n");
	}

	CloseHandle(hProcess);

	return true;
}

bool isPid(const std::string& input) {
	regex pidPattern("\\d+");
	return regex_match(input, pidPattern);
}

bool isProcessName(const std::string& input) {
	regex processNamePattern("^[^\\.]+\\.exe$");
	return regex_match(input, processNamePattern);
}

DWORD_REF FindProcessId(string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE_REF processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

DWORD stringToDWORD(const std::string& pidString) {
	try {
		return std::stoul(pidString);
	}
	catch (const std::invalid_argument& e) {
		std::cerr << "Invalid argument: " << e.what() << std::endl;
		return 0;
	}
	catch (const std::out_of_range& e) {
		std::cerr << "Out of range: " << e.what() << std::endl;
		return 0;
	}
}