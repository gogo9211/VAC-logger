#include "modules.hpp"

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
	{
		if (mod.end_address >= address && mod.start_address <= address)
			return reinterpret_cast<HMODULE>(mod.start_address);
	}
	
	return {};
}