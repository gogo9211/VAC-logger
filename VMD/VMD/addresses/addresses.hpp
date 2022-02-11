#pragma once
#include <Windows.h>
#include <iostream>

namespace vmd::addresses
{
	constexpr auto loadlib_condition = 0x5817Eu; //F6 45 0C 02 -> next instruction
	constexpr auto module_invoker_address = 0x57A04u; //the xref of ^^
	constexpr auto get_module_address = 0x81B40; //55 8B EC 8B 45 08 FF 75 0C 
}