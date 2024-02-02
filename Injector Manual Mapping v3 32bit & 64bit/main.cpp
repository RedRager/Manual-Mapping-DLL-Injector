#include "common_definitions.h"

const int pidWidth = 8;

int main(){
	while (true) {
		bool DllNotValid = true;
		bool pIDNotValid = true;
		dllInfo DllInfo{ 0 };
		processInfo ProcessInfo{ 0 };

		while (DllNotValid) {
			cout << endl;
			cout << "Enter DLL path: ";
			cin >> DllInfo.DllPathString;

			if (!DllCheck(DllInfo)) {
				printf("\nAn error occurred while loading the DLL\n");

				if (!getUserDecision("Try again? Yes or No")) {
					return 0;
				}
			}
			else {
				DllNotValid = false;
			}
		}

		while (pIDNotValid) {
			cout << endl;
			cout << "Enter process ID or process name: ";
			getline(cin >> std::ws, ProcessInfo.process);

			if (!ProcessCheck(ProcessInfo)) {
				string Decision;
				printf("\nAn error occurred while checking process\n");

				if(!getUserDecision("Try again? Yes or No")){
					return 0;
				}
			}
			else {
				pIDNotValid = false;
			}
		}

		bool injection = true;
		while (injection){
			if (!pIDNotValid && !DllNotValid) {
				if(getUserDecision("\nStart injection? Yes or No")){
					if (!startInjection(DllInfo, ProcessInfo)) {
						printf("Injection failed\n");
					}
					else {
						printf("Injection successful\n");
					}

					while (getUserDecision("\nRepeat injection? Yes or No")) {
						if (!startInjection(DllInfo, ProcessInfo)) {
							printf("Injection failed\n");
						}
						else {
							printf("Injection successful\n");
						}
					}

					injection = false;
				}
			}
		}
	}
	return 0;
}

bool getUserDecision(string output) {
	string decision;
    while (decision.empty()) {
        cout << output << "\n";
        cin >> decision;

        for (char& c : decision) {
            c = tolower(c);
        }

        if (!(decision == "y" || decision == "yes" || decision == "n" || decision == "no")) {
            decision.clear();
        } else if (decision == "y" || decision == "yes") {
			return true;
		} else if (decision == "n" || decision == "no") {
			return false;
		}
    }
	return false;
}

map<DWORD64, string> listProcesses(){
	PROCESSENTRY32 processInfo{};
	map<DWORD64, string> processMap;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE_REF processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return processMap;

	if (Process32First(processSnapshot, &processInfo)) {
		do {
			if (processInfo.th32ProcessID <= 4)
				continue;

			processMap.emplace(processInfo.th32ProcessID, processInfo.szExeFile);
		} while (Process32Next(processSnapshot, &processInfo));
	}

	CloseHandle(processSnapshot);
	return processMap;
}

DWORD_REF __stdcall stub() {
	return 0;
}