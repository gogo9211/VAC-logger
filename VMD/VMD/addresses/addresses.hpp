#pragma once
#include <Windows.h>
#include <iostream>

namespace vmd::addresses
{
	constexpr auto loadlib_condition = 0x57A0Eu;
	constexpr auto module_invoker_address = 0x577A1u;
	constexpr auto get_module_address = 0x80D00u;
}