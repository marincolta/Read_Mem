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




bool ReadMemory(HANDLE hProc, LPCVOID lpBaseAddress, LPVOID lpBuffer1, SIZE_T bufferssize , DWORD protection, DWORD& oldProtect, SIZE_T& bytesRead)
{
    if (ReadProcessMemory(hProc, lpBaseAddress, lpBuffer1, bufferssize, &bytesRead))
    {
        if (VirtualProtectEx(hProc, const_cast<LPVOID>(lpBaseAddress), bufferssize, protection, &oldProtect))
        {
			return true;
		}
	}
}

bool WriteMemory(HANDLE hProc, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T bufferSize, DWORD protection, DWORD& oldProtect, SIZE_T& bytesWritten) {
    if (WriteProcessMemory(hProc, const_cast<LPVOID>(lpBaseAddress), lpBuffer, bufferSize, &bytesWritten)) {
        if (VirtualProtectEx(hProc, const_cast<LPVOID>(lpBaseAddress), bufferSize, protection, &oldProtect)) {
            return true; // Success
        }
        else {
            std::cerr << "Failed to change memory protection!" << std::endl;
        }
    }
    else {
        std::cerr << "Failed to write memory!" << std::endl;
    }

    return false; // Failure
}


int main() {
    const char* procname = "CrackMeVentRat.exe";
    DWORD procID = 0;

    char data[] = "newpass";
    char buffer[10];
    char user[] = "newuser"; 
    while (!procID) {
        procID = GetProcID(procname);
        Sleep(30);
    }
    uintptr_t userAddress = 0x00007FF6011D11BD;
    uintptr_t passwordAddress = 0x00007FF6011D11BD;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (process == NULL) {
        std::cerr << "Failed to open process!" << std::endl;
        return 1;
    }
   
   LPCVOID lpBaseAddress = (LPCVOID)userAddress;
   LPVOID lpBuffer = (LPVOID)buffer;
   SIZE_T bufferssize = sizeof(buffer);
   DWORD protection = PAGE_READWRITE;
   DWORD oldProtect;
   SIZE_T bytesRead;
   LPVOID lpBuffer1 = (LPVOID)user;
   SIZE_T bufferssize1 = sizeof(user);
   ReadMemory(process, lpBaseAddress, lpBuffer, bufferssize, protection, oldProtect, bytesRead);
   std::cout << "The address: " << std::hex << lpBaseAddress  << std::endl;
   std::cout << "---------------------The value: " << buffer <<"---------------------"<<std::endl;

   WriteMemory(process, lpBaseAddress, lpBuffer1, bufferssize1, protection, oldProtect, bytesRead);

   ReadMemory(process, lpBaseAddress, lpBuffer, bufferssize, protection, oldProtect, bytesRead);
   std::cout << "The address: " << std::hex << lpBaseAddress << std::endl;
   std::cout << "---------------------The value: " << buffer << "---------------------" << std::endl;
  

   //now for the password
    lpBaseAddress = (LPCVOID)passwordAddress;
    lpBuffer = (LPVOID)buffer;
    bufferssize = sizeof(buffer);
    LPVOID lpBuffer2 = (LPVOID)data;
    SIZE_T bufferssize2 = sizeof(data);
    ReadMemory(process, lpBaseAddress, lpBuffer, bufferssize, protection, oldProtect, bytesRead);
    std::cout << "The address: " << std::hex << lpBaseAddress << std::endl;
    std::cout << "---------------------The value: " << buffer << "---------------------" << std::endl;
    //write memory
    WriteMemory(process, lpBaseAddress, lpBuffer2, bufferssize2, protection, oldProtect, bytesRead);
    ReadMemory(process, lpBaseAddress, lpBuffer, bufferssize, protection, oldProtect, bytesRead);
    std::cout << "The address: " << std::hex << lpBaseAddress << std::endl;
    std::cout << "---------------------The value: " << buffer << "---------------------" << std::endl;
    CloseHandle(process);

    return 0;
}
