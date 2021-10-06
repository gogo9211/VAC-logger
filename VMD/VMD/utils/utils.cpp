#include "utils.hpp"

#include <psapi.h>
#include <TlHelp32.h>

// something i use to prevent VAC from detecting cheat engine, but i will not include the actual bypass codes when publishing to github for now

DWORD vmd::utils::get_cheat_engine_pid()
{
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 process;

    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process))
    {
        do
        {
            if (std::wcsstr(process.szExeFile, L"cheatengine"))
            {
                CloseHandle(snapshot);

                return process.th32ProcessID;
            }

        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    return {};
}