#include <Windows.h>
#include <thread>
#include <fstream>
#include <filesystem>

#include "tlhelp32.h"

#include "hooking/hooking.hpp"
#include "addresses/addresses.hpp"
#include "modules/modules.hpp"
#include "utils/utils.hpp"

inline const auto steam_service = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("steamservice.dll"));
inline HMODULE dir_mod;

using get_module_address_t = std::uintptr_t(*)(HMODULE handle, const char* name);
get_module_address_t get_module_address_original = nullptr;

auto get_proc_address_original = reinterpret_cast<decltype(&GetProcAddress)>(0x0);

const auto module_invoker_start = steam_service + vmd::addresses::module_invoker_address;
const auto module_invoker_end = module_invoker_start + 0x6;

void __stdcall hook_stub(std::uintptr_t module_info, std::uint32_t load_status)
{
    std::ofstream file;

    char log_p[MAX_PATH];
    GetModuleFileNameA(dir_mod, log_p, MAX_PATH);

    std::string log_location = log_p;

    log_location = log_location.substr(0, log_location.find_last_of("/\\") + 1) + "\\logs";
    if (!std::filesystem::exists(log_location))
        std::filesystem::create_directory(log_location);

    const auto module_handle = *reinterpret_cast<HMODULE*>(module_info + 0x4);
    const auto module_entry_point = *reinterpret_cast<std::uintptr_t*>(module_info + 0xC);
    const auto module_size = *reinterpret_cast<std::uint32_t*>(module_info + 0x14);
    const auto module_ret = *reinterpret_cast<std::uint32_t*>(module_info + 0x10);

    char file_name[MAX_PATH];

    GetModuleFileNameA(module_handle, file_name, MAX_PATH);

    std::string file_s{ file_name };

    file.open(log_location + "\\module_calls.txt", std::ios_base::app);

    const auto t_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    tm time;

    localtime_s(&time, &t_c);

    file << "Time: " << std::put_time(&time, "%F %T") << " | Module Called: " << file_s << " | Base: " << module_handle << " | Size: " << std::hex << module_size << " | Entry Point: " << std::hex << module_entry_point << " | Load Status: " << load_status << " | Call Status: " << module_ret << "\n";

    file.close();
}

_declspec(naked) void module_invoker_hook()
{
    std::uint32_t load_status;
    std::uintptr_t module_info;

    __asm
    {
        push eax
        mov eax, [ebx + 0x10]
        mov load_status, eax
        pop eax

        mov [ebx + 0x10], eax
        mov esi, [ebp + 0x28]

        mov module_info, ebx
        pushad
    }

    hook_stub(module_info, load_status);

    __asm
    {
        popad
        jmp module_invoker_end
    }
}

std::uintptr_t get_module_address_hook(HMODULE mod, const char* name, std::uintptr_t mod_data)
{
    std::ofstream file;

    char file_name[MAX_PATH];

    GetModuleFileNameA(mod, file_name, MAX_PATH);

    std::string file_s{ file_name };

    if (file_s.substr(file_s.find_last_of(".") + 1) == "tmp")
    {
        char log_p[MAX_PATH];
		GetModuleFileNameA(dir_mod, log_p, MAX_PATH);

		std::string log_location = log_p;

    	log_location = log_location.substr(0, log_location.find_last_of("/\\") + 1) + "\\logs";
        if (!std::filesystem::exists(log_location))
			std::filesystem::create_directory(log_location);

        file.open(log_location + "\\module_loads.txt", std::ios_base::app);

        const auto t_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm time;

        localtime_s(&time, &t_c);

        const auto hash = vmd::modules::hash_module(file_name);

        file << "Time: " << std::put_time(&time, "%F %T") << " | Module: " << std::hex << mod << " | Hash: " << std::hex << hash << " | Function: " << name << " | Location: " << file_name << "\n";

        file.close();

        std::filesystem::path source_file = file_name;
        std::filesystem::path target_file = log_location;

        auto target = target_file / source_file.filename();

        std::filesystem::copy_file(source_file, target, std::filesystem::copy_options::overwrite_existing);
    }

    return get_module_address_original(mod, name);
}

FARPROC __stdcall get_proc_address_hook(HMODULE mod, const char* const name)
{
    std::ofstream file;

    char file_name[MAX_PATH];

    std::uintptr_t ret_addr;

    __asm mov eax, [ebp + 4]
    __asm mov ret_addr, eax

    const auto mod_base = vmd::modules::get_module_from_address(ret_addr);

    if (!mod_base)
        return get_proc_address_original(mod, name);

    GetModuleFileNameA(mod_base, file_name, MAX_PATH);

    std::string file_s{ file_name };

    char log_p[MAX_PATH];
    GetModuleFileNameA(dir_mod, log_p, MAX_PATH);

    std::string log_location = log_p;

    log_location = log_location.substr(0, log_location.find_last_of("/\\") + 1) + "\\logs\\";

    if (!std::filesystem::exists(log_location))
        std::filesystem::create_directory(log_location);

    auto base_filename = file_s.substr(file_s.find_last_of("/\\") + 1);

    log_location.append(base_filename.substr(0, base_filename.find_last_of('.')));
    log_location.append(".txt");

    if (file_s.substr(file_s.find_last_of(".") + 1) == "tmp")
    {
        file.open(log_location, std::ios_base::app);

        const auto t_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm time;

        localtime_s(&time, &t_c);

        file << "Time: " << std::put_time(&time, "%F %T") << " | Import: " << name << "\n";

        file.close();
    }

    return get_proc_address_original(mod, name);
}

void main_d()
{
    const auto get_module_address = steam_service + vmd::addresses::get_module_address;
    const auto loadlib_condition = steam_service + vmd::addresses::loadlib_condition;

    DWORD old_protect{};

    VirtualProtect(reinterpret_cast<void*>(loadlib_condition), 0x1, 0x40, &old_protect);

    *reinterpret_cast<std::uint8_t*>(loadlib_condition) = 0xEB;

    VirtualProtect(reinterpret_cast<void*>(loadlib_condition), 0x1, old_protect, &old_protect);

    get_module_address_original = reinterpret_cast<get_module_address_t>(vmd::hooking::tramp_hook(reinterpret_cast<void*>(get_module_address), get_module_address_hook, 6));
    get_proc_address_original = reinterpret_cast<decltype(&GetProcAddress)>(vmd::hooking::tramp_hook(GetProcAddress, get_proc_address_hook, 5));

    VirtualProtect(reinterpret_cast<void*>(module_invoker_start), 0x6, PAGE_EXECUTE_READWRITE, &old_protect);

    std::memset(reinterpret_cast<void*>(module_invoker_start), 0x90, 0x6);

    *reinterpret_cast<std::uint8_t*>(module_invoker_start) = 0xE9;
    *reinterpret_cast<std::uintptr_t*>(module_invoker_start + 1) = (reinterpret_cast<std::uintptr_t>(module_invoker_hook) - module_invoker_start - 5);

    VirtualProtect(reinterpret_cast<void*>(module_invoker_start), 0x6, old_protect, &old_protect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        dir_mod = hModule;

        std::thread{ main_d }.detach();
    }

    return TRUE;
}