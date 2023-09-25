#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
DWORD GetProcID(const char* procname)
{
    DWORD procID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procname))
                {
                    procID = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procID;
}

SIZE_T bytesRead;
SIZE_T bytesWritten;
DWORD oldProtect;
DWORD temp;


auto Readmem(HANDLE proc , uintptr_t address1, char buffer[250], SIZE_T bytestoread) {
    ReadProcessMemory(proc, (LPCVOID)address1, &buffer, sizeof(buffer), &bytestoread);

    return buffer;

}

auto Writemem(HANDLE proc, uintptr_t address1, std::string buffer , SIZE_T bytestowrite) {
    VirtualProtectEx(proc, (LPVOID)address1, sizeof(buffer), PAGE_READWRITE, &oldProtect);
	WriteProcessMemory(proc, (LPVOID)address1, &buffer, sizeof(buffer), &bytestowrite);
    VirtualProtectEx(proc, (LPVOID)address1, sizeof(buffer), oldProtect, &temp);
	return buffer;
}

//make a function that will read the memory of the process that will get as arguments: handle proc, unitptt_t addr1, char buffer, SIZE_T bytestoread
int main() {
    const char* procname = "CrackMeVentRat.exe";
    DWORD procID = 0;

    char data[] = "newpass";
    
    char user[] = "newuser"; 
    while (!procID) {
        procID = GetProcID(procname);
        Sleep(30);
    }
    uintptr_t userAddress = 0x00007FF7253036C8;
    uintptr_t passwordAddress = 0x00007FF7253036E0;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (process == NULL) {
        std::cerr << "Failed to open process!" << std::endl;
        return 1;
    }

    // User
    char buffer[256];
   
  
  
    CloseHandle(process);

    return 0;
}
