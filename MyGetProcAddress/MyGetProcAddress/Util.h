#pragma once
#include "ApiWrapper.h"

namespace Util
{



	__forceinline  DWORD64 GetKernelModuleBySystemModule(char* moduleName)
	{
		ULONG poolSize = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &poolSize); //get the estimated size first

		if (status != STATUS_INFO_LENGTH_MISMATCH)	//thats normal, it will return the required pool size anyways
		{
			Log("ZwQuerySystemInformation failed!");
			return 0;
		}

		auto sysModInfo = (SYSTEM_MODULE_INFORMATION*)ExAllocatePool(NonPagedPool, poolSize);

		if (!sysModInfo)
		{
			Log("Unable to allocate pool!");
			return 0;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, sysModInfo, poolSize, nullptr);

		if (!NT_SUCCESS(status))
		{
			Log("ZwQuerySystemInformation failed! -> %lx", status);
			ExFreePool(sysModInfo);
			return 0;
		}

		DWORD64 address = 0;

		for (unsigned int i = 0; i < sysModInfo->NumberOfModules; i++)
		{
			auto moduleEntry = sysModInfo->Modules[i];

			if (NoCRT::string::strstr((char*)moduleEntry.FullPathName, moduleName))
			{
				address = (DWORD64)moduleEntry.ImageBase;
			}
		}

		ExFreePool(sysModInfo);
		return address;
	}



	__forceinline  DWORD64 GetKernelBasebyDisk(const wchar_t* name)
	{

		UNICODE_STRING DriverName;
		PDRIVER_OBJECT DiskDriver = NULL;
		DriverName = ApiWrapper::InitUnicodeString(xorstr(L"\\Driver\\disk"));
		auto status = ObReferenceObjectByName(
			&DriverName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			0,
			*IoDriverObjectType,
			KernelMode,
			NULL,
			(PVOID*)&DiskDriver);

		if (NT_SUCCESS(status))
		{


			PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DiskDriver->DeviceObject->DriverObject->DriverSection;
			PLDR_DATA_TABLE_ENTRY first = entry;
			while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderModuleList.Flink != first)
			{
				if (NoCRT::string::wstricmp(entry->BaseDllName.Buffer, name) == 0)
					return	(DWORD64)entry->DllBase;
				entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderModuleList.Flink;
			}
			return 0;
		}
		else
		{
			return 0;
		}
	}


	EXTERN_C DWORD64 GetKernelBase();




	__forceinline PVOID MyGetProcAddress(PVOID baseDll, const char* nameFunthion)
	{
		// return RtlFindExportedRoutineByName(baseDll, nameFunthion);


		return WindowsLeak::MiLocateExportName(baseDll, (char*)nameFunthion);
	}


}