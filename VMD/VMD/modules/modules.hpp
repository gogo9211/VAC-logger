#pragma once
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <vector>
#include <winnt.h>
#include <wintrust.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <Softpub.h>

struct LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 in_load_order_links;

	std::uint8_t pad[16];
	std::uint32_t dll_base;
	std::uint32_t entry_point;
	std::size_t size_of_image;

	UNICODE_STRING full_name;
	UNICODE_STRING base_name;
};

struct PEB_LDR_DATA32
{
	std::uint8_t pad[9];

	LIST_ENTRY32* in_load_order_module_list;
};

struct peb_entry_data
{
	std::uint32_t start_address;
	std::uint32_t end_address;
};

namespace vmd::modules
{
	std::vector<peb_entry_data> walk_peb();

	HMODULE get_module_from_address(std::uintptr_t address);

	std::uint32_t hash_module(const char* mod_location);
}