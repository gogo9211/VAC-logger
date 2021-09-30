#pragma once
#include <Windows.h>
#include <iostream>

namespace vmd::hooking
{
	std::uintptr_t tramp_hook(void* func, const void* new_func, const std::size_t inst_size);
}