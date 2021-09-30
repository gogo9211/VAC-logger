#include <Windows.h>
#include <thread>
#include <fstream>
#include <filesystem>
#include <psapi.h>

#include "hooking/hooking.hpp"
#include "addresses/addresses.hpp"
#include "modules/modules.hpp"

inline const auto steam_service = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("steamservice.dll"));
inline HMODULE dir_mod;

using get_module_address_t = std::uintptr_t(*)(HMODULE handle, const char* name);
get_module_address_t get_module_address_original = nullptr;

auto get_proc_address_original = reinterpret_cast<decltype(&GetProcAddress)>(0x0);

std::uintptr_t get_module_address_hook(HMODULE mod, const char* name)
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

        file.open(log_location + "\\module_logs.txt", std::ios_base::app);

        const auto t_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm time;

        localtime_s(&time, &t_c);

        file << "Time: " << std::put_time(&time, "%F %T") << " | Module: " << std::hex << mod << " | Function: " << name << " | Location: " << file_name << "\n";

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