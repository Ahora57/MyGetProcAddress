#include "Util.h"





NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	//PIDHelp::Init();



	PVOID baseNtOskrln = (PVOID)Util::GetKernelBase();
	auto ApiRtlInitUnicodeString = Util::MyGetProcAddress(baseNtOskrln, xorstr("RtlInitUnicodeString"));
	auto us_RtlInitUnicodeString = ApiWrapper::InitUnicodeString(xorstr(L"RtlInitUnicodeString"));
	auto ApiRtlInitUnicodeStringNoWrapper = MmGetSystemRoutineAddress(&us_RtlInitUnicodeString);

	Log("Api address wrapper ->\t %p", ApiRtlInitUnicodeString);
	Log("Api address no wrapper ->\t %p", ApiRtlInitUnicodeStringNoWrapper);


	return STATUS_SUCCESS;
}