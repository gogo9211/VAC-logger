#include "modules.hpp"

#include "../xxhash/xxhash.hpp"

std::vector<peb_entry_data> vmd::modules::walk_peb()
{
	std::vector<peb_entry_data> result;

	auto peb_ldr_data = reinterpret_cast<PEB_LDR_DATA32*>(reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<std::uintptr_t>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock->Ldr);

	auto module = peb_ldr_data->in_load_order_module_list->Flink;

	const auto last_module = peb_ldr_data->in_load_order_module_list->Blink;

	while (true)
	{
		auto module_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>(module);

		if (module_entry->dll_base)
		{
			peb_entry_data data;

			data.start_address = module_entry->dll_base;
			data.end_address = module_entry->dll_base + module_entry->size_of_image;

			result.push_back(data);
		}

		if (module == last_module)
		{
			module = (reinterpret_cast<LIST_ENTRY32*>(module))->Flink;

			auto module_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>(module);

			peb_entry_data data;

			data.start_address = module_entry->dll_base;
			data.end_address = module_entry->dll_base + module_entry->size_of_image;

			result.push_back(data);

			break;
		}

		module = (reinterpret_cast<LIST_ENTRY32*>(module))->Flink;
	}

	return result;
}

HMODULE vmd::modules::get_module_from_address(std::uintptr_t address)
{
	for (const auto modules = walk_peb(); const auto& mod : modules)
		if (mod.end_address >= address && mod.start_address <= address)
			return reinterpret_cast<HMODULE>(mod.start_address);
	
	return {};
}

// hashes only the unique code of modules so should identity modules properly, since they have their debug/export dir in .text some modules will be similar but hashing entire .text will change hash
// so what i do here is scan from end of debug dir all the way to beginning of export dir which should basically contain the unique function code

std::uint32_t vmd::modules::hash_module(const char* mod_location)
{
	FILE* file;

	if (fopen_s(&file, mod_location, "rb"))
		return {};

	std::uint32_t start = ftell(file);

	fseek(file, 0, 2);

	std::uint32_t end = ftell(file);

	fseek(file, start, 0);

	std::uint8_t* buffer = new std::uint8_t[end];

	fread(buffer, end, 1, file);

	fclose(file);

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer)->e_lfanew;
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dos_header);
	const auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);

	for (auto i = 0u; i < nt_headers->FileHeader.NumberOfSections; ++i)
	{
		const auto segment_name = reinterpret_cast<const char*>(section_headers[i].Name);

		const auto debug_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		const auto export_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		if (!debug_dir || !export_dir)
			return {};

		const auto debug_dir_offset = debug_dir - section_headers[i].VirtualAddress + section_headers[i].PointerToRawData;

		if (strcmp(segment_name, ".text") == 0)
			return XXHash32::hash(reinterpret_cast<void*>(buffer + debug_dir_offset), export_dir - debug_dir, 0);
	}

	return {};
}