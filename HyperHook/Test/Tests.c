#include "Tests.h"
#include "../Global/Global.h"
#include "../Utils/Utils.h"
#include "../Hooks/PageHook.h"
#include "../Hooks/SyscallHook.h"

#define SSDTIndex(ptr)              *(PULONG)((ULONG_PTR)ptr + 0x15)

ULONG64 calls1 = 0, calls2 = 0;
PVOID g_NtClose = NULL;
typedef NTSTATUS(*pfnNtClose)(HANDLE);


NTSTATUS hkNtClose(HANDLE handle)
{
	calls1++;
	return ((pfnNtClose)g_NtClose)(handle);
}

NTSTATUS hkNtClose2(HANDLE handle)
{
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(g_NtClose);
	if (pEntry)
	{
		calls2++;
		return ((pfnNtClose)pEntry->OriginalData)(handle);
	}

	return STATUS_SUCCESS;
}

ULONG64 TestFn(ULONG64 in1, ULONG64 in2);
#pragma alloc_text(".text0", TestFn)
ULONG64 TestFn(ULONG64 in1, ULONG64 in2)
{
	ULONG64 data1 = 0x500;

	return in1 + in2;
}

ULONG64 hkTestFn(ULONG64 in1, ULONG64 in2);
#pragma alloc_text(".text1", hkTestFn)
ULONG64 hkTestFn(ULONG64 in1, ULONG64 in2)
{
	// Call original
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry((PVOID)(ULONG_PTR)TestFn);
	if (pEntry)
		((ULONG64(*)(ULONG64, ULONG64))(ULONG_PTR)pEntry->OriginalData)(in1, in2);

	return 0x666666;
}

VOID TestPageHook()
{
	UCHAR buf[32] = { 0 };
	PVOID pFn = (PVOID)TestFn;

	RtlCopyMemory(buf, pFn, 16);
	DPRINT("HyperHook: CPU %d: %s: Buffer contents: 0x%p, Call result 0x%X\n", CPU_INDEX, __FUNCTION__, *(PULONG64)buf, TestFn(100, 5));

	PHHook(pFn, (PVOID)hkTestFn);

	RtlCopyMemory(buf, pFn, 16);
	DPRINT("HyperHook: CPU %d: %s: Buffer contents: 0x%p, Call result 0x%X\n", CPU_INDEX, __FUNCTION__, *(PULONG64)buf, TestFn(100, 5));

	PHRestore(pFn);

	RtlCopyMemory(buf, pFn, 16);
	DPRINT("HyperHook: CPU %d: %s: Buffer contents: 0x%p, Call result 0x%X\n", CPU_INDEX, __FUNCTION__, *(PULONG64)buf, TestFn(100, 5));
}


VOID TestStart(IN BOOLEAN SyscallHook, IN BOOLEAN PageHook1, IN BOOLEAN PageHook2)
{
	//PHInitialize();

	if (PageHook1)
	{
		TestPageHook();
	}

	g_NtClose = (PVOID)UtilSSDTEntry(SSDTIndex(&ZwClose));
	if (g_NtClose)
	{
		if (SyscallHook)
		{
			if (NT_SUCCESS(SHInitHook()))
				SHHookSyscall(SSDTIndex(&ZwClose), (PVOID)hkNtClose, 1);
			else
				DPRINT("HyperHook: CPU %d: %s: SHInitHook() failed\n", CPU_INDEX, __FUNCTION__);
		}

		if (PageHook2)
		{
			if (g_NtClose)
			{
				if (!NT_SUCCESS(PHHook(g_NtClose, (PVOID)hkNtClose2)))
					DPRINT("HyperHook: CPU %d: %s: PHHook() failed\n", CPU_INDEX, __FUNCTION__);
			}
			else
				DPRINT("HyperHook: CPU %d: %s: NtClose not found\n", CPU_INDEX, __FUNCTION__);
		}
	}
	else
		DPRINT("HyperHook: CPU %d: %s: NtClose not found\n", CPU_INDEX, __FUNCTION__);
}

VOID TestStop()
{
	PHRestore(g_NtClose);
	SHRestoreSyscall(SSDTIndex(&ZwClose));
	SHDestroyHook();
	//PHCleanup();
}

VOID TestPrintResults()
{
	DPRINT("HyperHook: CPU %d: %s: SyscallHook Calls made %d\n", CPU_INDEX, __FUNCTION__, calls1);
	DPRINT("HyperHook: CPU %d: %s: PageHook Calls made %d\n", CPU_INDEX, __FUNCTION__, calls2);
}