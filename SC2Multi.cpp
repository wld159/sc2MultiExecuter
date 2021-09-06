// SC2Multi.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.

#include "pch.h"
#include <vector>
#include <ShlObj_core.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <tchar.h>

#include <memory> 
#pragma comment(lib, "ntdll") 
#define NT_SUCCESS(status) (status >= 0)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

void wait() {
    char a;
    scanf_s("%c", &a);
}

const char * WinGetEnv(const char * name)
{
    const DWORD buffSize = 65535;
    static char buffer[buffSize];
    if (GetEnvironmentVariableA(name, buffer, buffSize))
    {
        return buffer;
    }
    else
    {
        return 0;
    }
}

std::vector<DWORD> FindSC2() {
    std::vector<DWORD> v_pid;
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return v_pid;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    // skip the idle process
    ::Process32First(hSnapshot, &pe);

    DWORD pid = 0;
    while (::Process32Next(hSnapshot, &pe)) {
        if (::_wcsicmp(pe.szExeFile, L"sc2_x64.exe") == 0) {
            // found SC2_x64.exe!    
            pid = pe.th32ProcessID;
            v_pid.push_back(pid);
        }
        else if (::_wcsicmp(pe.szExeFile, L"sc2.exe") == 0) {
            // found SC2_exe!
            pid = pe.th32ProcessID;
            v_pid.push_back(pid);
        }
    }
    ::CloseHandle(hSnapshot);
    return v_pid;
}

std::string FindSC2Path(bool get_excutepath = FALSE) {
    wchar_t szPath[MAX_PATH] = { 0, };
    HRESULT r = SHGetSpecialFolderPathW(NULL, szPath, CSIDL_PERSONAL, FALSE);
    std::wstring ws(szPath);
    std::string excuteinfo_path(ws.begin(), ws.end());

    if (r != S_OK) {
        excuteinfo_path = WinGetEnv("USERPROFILE");
        excuteinfo_path += "\\Documents";
        if (excuteinfo_path == "") {
            printf("Can't find ExcuteInfo.txt file.\nError code: 0x%08X", r, "\n");
            return "";
        }
    }

    excuteinfo_path += "\\StarCraft II\\ExecuteInfo.txt";
    std::ifstream file(excuteinfo_path);
    std::string excuteinfo;
    if (file.is_open() == true) {
        std::getline(file, excuteinfo);
        file.close();
    }


    std::string::size_type start, end;
    // excuteinfo 에서 설치 경로를 찾는다.
    start = excuteinfo.find("=") + 2;
    end = excuteinfo.find("Versions");
    excuteinfo = excuteinfo.substr(start, end - start); // 스타2 설치 경로

    if (get_excutepath) {
        excuteinfo += "Support\\SC2Switcher.exe";
    }
    printf("Found SC2.exe. \n Path: %s", excuteinfo);
    return excuteinfo;
}

void RunSC2() {
    std::string sc2exe = FindSC2Path(true);
    //std::wstring stemp = std::wstring(sc2exe.begin(), sc2exe.end());
    //LPCWSTR sw = stemp.c_str();
    if (sc2exe != "")
        ShellExecuteA(NULL, "open", sc2exe.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

enum PROCESSINFOCLASS {
    ProcessHandleInformation = 51
};

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectNameInformation = 1
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

extern "C" NTSTATUS NTAPI NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

int main()
{
    setlocale(LC_ALL, "");

    std::vector<DWORD> v_pid = FindSC2();

    if (v_pid.size() == 0) {
        printf("Failed to Find StarCraft II.\nThe fisrt SC2 must be run from blizard app.\n");
        printf("\n현재 실행된 스타2를 찾지 못했습니다.\n 최초 클라이언트는 블리자드 앱을 통해서 실행 바랍니다.\n");
        // run SC2
        wait();
        return 1;
    }

    for (auto pid : v_pid)
    {
        // 스타2 프로세스 검색
        printf("Found PID=%u\n", pid);

        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            FALSE, pid);
        if (!hProcess) {
            printf("Failed to open StarCraft II process handle (error=%u)\n",
                ::GetLastError());
            return 1;
        }


        // 선택한 프로세스의 핸들 얻기
        ULONG size = 1 << 10;
        std::unique_ptr<BYTE[]> buffer;
        for (;;) {
            buffer = std::make_unique<BYTE[]>(size);
            auto status = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation,
                buffer.get(), size, &size);
            if (NT_SUCCESS(status))
            {
                break;
            }
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                size += 1 << 10;
                continue;
            }
            printf("Error enumerating handles\n");
            return 1;
        }

        // 타겟 핸들 이름 설정
        WCHAR targetName0[256], targetName1[256], targetName2[256], targetName3[256], 
             targetName4[256], targetName5[256], targetName6[256], 
            targetName7[256], targetName8[256], targetName9[256];
        DWORD sessionId;
        ::ProcessIdToSessionId(pid, &sessionId);
        ::swprintf_s(targetName0,
            L"\\BaseNamedObjects\\StarCraft II Game Application (Global)",
            sessionId);
        ::swprintf_s(targetName1,
            L"\\Sessions\\1\\BaseNamedObjects\\StarCraft II Game Application",
            sessionId);
        ::swprintf_s(targetName2,
            L"\\Sessions\\1\\BaseNamedObjects\\StarCraft II",
            sessionId);
        ::swprintf_s(targetName3,
            L"\\Sessions\\1\\BaseNamedObjects\\StarCraft II IPC Mem",
            sessionId);
        ::swprintf_s(targetName4,
            L"\\Sessions\\2\\BaseNamedObjects\\StarCraft II Game Application",
            sessionId);
        ::swprintf_s(targetName5,
            L"\\Sessions\\2\\BaseNamedObjects\\StarCraft II",
            sessionId);
        ::swprintf_s(targetName6,
            L"\\Sessions\\2\\BaseNamedObjects\\StarCraft II IPC Mem",
            sessionId);
        ::swprintf_s(targetName7,
            L"\\Sessions\\3\\BaseNamedObjects\\StarCraft II Game Application",
            sessionId);
        ::swprintf_s(targetName8,
            L"\\Sessions\\3\\BaseNamedObjects\\StarCraft II",
            sessionId);
        ::swprintf_s(targetName9,
            L"\\Sessions\\3\\BaseNamedObjects\\StarCraft II IPC Mem",
            sessionId);
        size_t len0 = ::wcslen(targetName0);
        size_t len1 = ::wcslen(targetName1);
        size_t len2 = ::wcslen(targetName2);
        size_t len3 = ::wcslen(targetName3);


        // 모든 핸들을 현재 프로세스로 복제
        auto info = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*>(buffer.get());
        for (ULONG i = 0; i < info->NumberOfHandles; i++) {
            HANDLE h = info->Handles[i].HandleValue;
            HANDLE hTarget;
            if (!::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
                0, FALSE, DUPLICATE_SAME_ACCESS))
                continue;   // move to next handle

            BYTE nameBuffer[1 << 10];
            auto status = ::NtQueryObject(hTarget, ObjectNameInformation,
                nameBuffer, sizeof(nameBuffer), nullptr);
            ::CloseHandle(hTarget);
            if (!NT_SUCCESS(status))
                continue;

            auto name = reinterpret_cast<UNICODE_STRING*>(nameBuffer);
            if (name->Buffer &&
                (::_wcsnicmp(name->Buffer, targetName0, len0) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName1, len1) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName2, len2) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName3, len3) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName4, len1) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName5, len2) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName6, len3) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName7, len1) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName8, len2) == 0 ||
                    ::_wcsnicmp(name->Buffer, targetName9, len3) == 0)) {
                // found it!
                ::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
                    0, FALSE, DUPLICATE_CLOSE_SOURCE);
                ::CloseHandle(hTarget);
                printf("Found and closed %S\n", name->Buffer);
            }
        }
    }
    printf("------------------------\n");
    printf("\nReady to run multiple SC2 instances is complete.\n");
    printf("스타2 멀티 클라이언트 실행을 위한 작업이 완료 되었습니다.\n");
    printf("\n------------------------\n");
    printf("\n Author: 기동아 (3-S2-1-1137080)\n\n Email: ehdrl3600@naver.com\n\n");
    printf("------------------------\n\n");
    printf("  If you want run SC2(32bit), Press the Enter key.\n");
    printf("    else, Close this program.\n");
    printf(" 스타2 실행을 원한다면, 엔터 키를 눌러주세요.\n");
    printf("만약 원치 않는다면, 이 프로그램을 종료 해주세요.\n");
    printf("\n\n     백신 등의 이유로 스타2가 실행이 되지 않을 수 있습니다.\n");
    printf("     그런 경우, 블리자드 앱에서 스타2를 실행하면 정상적으로 멀티 클라이언트 실행이 됩니다.");


    wait();
    RunSC2();

    return 0;
}
