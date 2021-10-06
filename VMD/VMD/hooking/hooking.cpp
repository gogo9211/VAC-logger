#include "hooking.hpp"

std::uintptr_t vmd::hooking::tramp_hook(void* func, const void* new_func, const std::size_t inst_size)
{
	constexpr auto extra_size = 5;

	auto func_n = reinterpret_cast<std::uintptr_t>(func);
	const auto new_func_n = reinterpret_cast<std::uintptr_t>(new_func);

	auto clone = reinterpret_cast<std::uintptr_t>(VirtualAlloc(nullptr, inst_size + extra_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!clone)
		return 0;

	std::memmove(reinterpret_cast<void*>(clone), reinterpret_cast<void*>(func_n), inst_size);

	const auto jmp_pos = (func_n - clone - extra_size);

	*reinterpret_cast<std::uint8_t*>(clone + inst_size) = 0xE9;
	*reinterpret_cast<std::uintptr_t*>(clone + inst_size + 1) = jmp_pos;

	DWORD old_protect{};

	VirtualProtect(reinterpret_cast<void*>(func_n), inst_size, PAGE_EXECUTE_READWRITE, &old_protect);

	std::memset(reinterpret_cast<void*>(func_n), 0x90, inst_size);

	*reinterpret_cast<std::uint8_t*>(func_n) = 0xE9;
	*reinterpret_cast<std::uintptr_t*>(func_n + 1) = (new_func_n - func_n - extra_size);

	VirtualProtect(reinterpret_cast<void*>(func_n), inst_size, old_protect, &old_protect);

	return clone;
}