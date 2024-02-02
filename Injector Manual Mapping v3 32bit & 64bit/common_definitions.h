#pragma once

#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

#include <map>
#include <regex>
#include <cctype>
#include <vector>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>

using std::string, std::to_string, std::tolower, std::stoul, std::getline;
using std::vector;
using std::cout, std::cin, std::endl, std::hex;
using std::map, std::pair;
using std::setw;
using std::regex, std::regex_match;

namespace fs = std::filesystem;

#ifdef _WIN64
#define DWORD_REF DWORD64
#define PDWORD_REF PDWORD64
#define PIMAGE_NT_HEADERS_REF PIMAGE_NT_HEADERS64
#define HANDLE_REF HANDLE64
#else
#define DWORD_REF DWORD
#define PDWORD_REF PDWORD
#define PIMAGE_NT_HEADERS_REF PIMAGE_NT_HEADERS
#define HANDLE_REF HANDLE
#endif

extern const int pidWidth;

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT(__stdcall* dllmain)(HMODULE, DWORD_REF, LPVOID);

struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS_REF NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

};

struct processInfo {
	DWORD64 pID;
	string process;
};

struct dllInfo
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_FILE_HEADER FileHeader;

	PVOID FileBuffer;
	string DllPathString;
	LPCSTR DllPath;
};

// checks.cpp
bool DllCheck(dllInfo& info);

PVOID LoadFileIntoMemory(LPCSTR Dll);

bool validPath(const string& path);

bool ProcessCheck(processInfo& info);

bool isPid(const std::string& input);

bool isProcessName(const std::string& input);

DWORD_REF FindProcessId(string processName);

DWORD stringToDWORD(const std::string& pidString);

// loader.cpp
DWORD64 __stdcall LibraryLoader(LPVOID Memory);

loaderdata LoaderDataInit(PVOID ExecutableImage, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeaders);

// injector.cpp
bool startInjection(dllInfo DllInfo, processInfo ProcessInfo);

// main.cpp
bool getUserDecision(string output);

DWORD_REF __stdcall stub();

map<DWORD64, string> listProcesses();

#endif // COMMON_DEFINITIONS_H