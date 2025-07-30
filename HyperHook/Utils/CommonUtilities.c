#include "CommonUtilities.h"
#include "HardwareDetection.h"
#include "../Core/HypervisorCore.h"
#include "../Assembly/VmxAssembly.h"
#include <intrin.h>

/*****************************************************
 * 功能：通用工具函数实现
 * 备注：实现系统初始化、DPC调度等通用功能
*****************************************************/

/*****************************************************
 * 功能：启动虚拟化DPC回调函数
 * 参数：Dpc - DPC对象指针
 *       DeferredContext - 延迟上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU核心上启动VMX虚拟化
*****************************************************/
VOID CommonStartVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // 获取当前处理器编号
    ULONG processorNumber = KeGetCurrentProcessorNumber();

    // 检查硬件虚拟化支持
    BOOLEAN biosEnabled = HwDetectVmxBiosEnabled();
    BOOLEAN cpuSupport = HwDetectVmxCpuSupport();
    BOOLEAN cr4Available = HwDetectVmxCr4Available();

    // 输出当前处理器的检测结果
    DbgPrint("[VMX] 处理器 %d: BIOS=%d, CPU支持=%d, CR4可用=%d\n",
             processorNumber, biosEnabled, cpuSupport, cr4Available);

    // 在当前处理器上初始化VMX
    if (biosEnabled && cpuSupport && cr4Available) {
        NTSTATUS status = HvInitializeProcessor();
        if (!NT_SUCCESS(status)) {
            DbgPrint("[VMX] 处理器 %d 初始化失败: 0x%08X\n", processorNumber, status);
        }
    }
    else {
        DbgPrint("[VMX] 处理器 %d 不支持虚拟化\n", processorNumber);
    }

    // 通知DPC完成
    KeSignalCallDpcDone(SystemArgument1);
    KeSignalCallDpcSynchronize(SystemArgument2);
}

/*****************************************************
 * 功能：停止虚拟化DPC回调函数
 * 参数：Dpc - DPC对象指针
 *       DeferredContext - 延迟上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU核心上停止VMX虚拟化
*****************************************************/
VOID CommonStopVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // 发送VMCALL退出虚拟化
    VmxExecuteVmcall(1, 0, 0, 0);

    // 释放当前处理器的内存资源
    HvCleanupProcessor();

    // 通知DPC完成
    KeSignalCallDpcDone(SystemArgument1);
    KeSignalCallDpcSynchronize(SystemArgument2);
}