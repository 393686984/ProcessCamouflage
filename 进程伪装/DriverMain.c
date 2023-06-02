#include <ntifs.h>
#include "FakeProcess.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	PEPROCESS TargetProcess = NULL;

	PsLookupProcessByProcessId(7004,&TargetProcess);

	
	FakeProcessByPid(TargetProcess, 512);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}