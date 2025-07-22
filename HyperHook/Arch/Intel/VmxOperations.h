/*****************************************************
 * 文件：VmxOperations.h
 * 功能：VMX操作函数头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：定义VMX虚拟化操作的核心接口函数
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmxStructures.h"

// VMX操作常量定义
#define VMX_VMCALL_MAGIC_NUMBER         0x48595045  // 'HYPE'
#define VMX_MAX_PROCESSORS              256         // 最大处理器数量
#define VMX_ALIGNMENT_PAGE_SIZE         4096        // 页面对齐大小

// 超级调用命令定义
#define HYPERCALL_BASE                  0x1000
#define HYPERCALL_UNLOAD                (HYPERCALL_BASE + 0)
#define HYPERCALL_HOOK_PAGE             (HYPERCALL_BASE + 1)
#define HYPERCALL_UNHOOK_PAGE           (HYPERCALL_BASE + 2)
#define HYPERCALL_GET_VERSION           (HYPERCALL_BASE + 3)
#define HYPERCALL_GET_STATISTICS        (HYPERCALL_BASE + 4)
#define HYPERCALL_EPT_RESTORE_ACCESS    (HYPERCALL_BASE + 5)
#define HYPERCALL_EPT_SWITCH_PAGE       (HYPERCALL_BASE + 6)
#define HYPERCALL_EPT_FLUSH_ALL         (HYPERCALL_BASE + 7)
#define HYPERCALL_EPT_FLUSH_PAGE        (HYPERCALL_BASE + 8)
#define HYPERCALL_INSTALL_SYSCALL_HOOK  (HYPERCALL_BASE + 9)
#define HYPERCALL_UNINSTALL_SYSCALL_HOOK (HYPERCALL_BASE + 10)

// 函数声明

/*****************************************************
 * 功能：初始化CPU的VMX
 * 参数：pVcpu - VCPU结构指针
 *       SystemCr3 - 系统CR3值
 * 返回：NTSTATUS - 状态码
 * 备注：在指定CPU上初始化VMX虚拟化环境
*****************************************************/
NTSTATUS VmxInitializeCpu(_In_ PIVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * 功能：释放CPU的VMX资源
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：清理指定CPU的VMX相关资源
*****************************************************/
VOID VmxReleaseCpu(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：分配VMX区域
 * 参数：RegionSize - 区域大小
 *       RevisionId - 修订标识符
 *       ppRegionVa - 输出虚拟地址指针
 *       pRegionPa - 输出物理地址指针
 * 返回：NTSTATUS - 状态码
 * 备注：分配VMXON或VMCS区域
*****************************************************/
NTSTATUS VmxAllocateVmxRegion(
    _In_ ULONG RegionSize,
    _In_ ULONG RevisionId,
    _Out_ PVOID* ppRegionVa,
    _Out_ PPHYSICAL_ADDRESS pRegionPa
);

/*****************************************************
 * 功能：释放VMX区域
 * 参数：pRegionVa - 虚拟地址指针
 * 返回：无
 * 备注：释放之前分配的VMX区域
*****************************************************/
VOID VmxFreeVmxRegion(_In_ PVOID pRegionVa);

/*****************************************************
 * 功能：启动VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：启动VMX根操作模式
*****************************************************/
NTSTATUS VmxStartOperation(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：停止VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：停止VMX根操作模式
*****************************************************/
NTSTATUS VmxStopOperation(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：设置VMCS主机状态
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：配置VMCS的主机状态区域
*****************************************************/
NTSTATUS VmxSetupHostState(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：设置VMCS客户机状态
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：配置VMCS的客户机状态区域
*****************************************************/
NTSTATUS VmxSetupGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：设置VMCS控制字段
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：配置VMCS的控制字段
*****************************************************/
NTSTATUS VmxSetupControlFields(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：启动虚拟机
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：首次启动虚拟机执行
*****************************************************/
NTSTATUS VmxLaunchVm(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：保存客户机状态
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：保存当前客户机的寄存器状态
*****************************************************/
VOID VmxSaveGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：恢复客户机状态
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：恢复客户机的寄存器状态
*****************************************************/
VOID VmxRestoreGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：准备客户机寄存器
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：从当前CPU状态准备客户机寄存器
*****************************************************/
VOID VmxPrepareGuestRegisters(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：获取段访问权限
 * 参数：SegmentSelector - 段选择器
 * 返回：ULONG - 访问权限值
 * 备注：从段选择器计算VMX格式的访问权限
*****************************************************/
ULONG VmxGetSegmentAccessRights(_In_ USHORT SegmentSelector);

/*****************************************************
 * 功能：调整CR0值
 * 参数：Cr0Value - 原始CR0值
 * 返回：ULONG64 - 调整后的CR0值
 * 备注：根据VMX_CR0_FIXED MSR调整CR0值
*****************************************************/
ULONG64 VmxAdjustCr0(_In_ ULONG64 Cr0Value);

/*****************************************************
 * 功能：调整CR4值
 * 参数：Cr4Value - 原始CR4值
 * 返回：ULONG64 - 调整后的CR4值
 * 备注：根据VMX_CR4_FIXED MSR调整CR4值
*****************************************************/
ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value);

/*****************************************************
 * 功能：处理VMCALL超级调用
 * 参数：pVcpu - VCPU结构指针
 *       pVmcallParams - VMCALL参数结构
 * 返回：NTSTATUS - 状态码
 * 备注：处理来自客户机的VMCALL超级调用
*****************************************************/
NTSTATUS VmxHandleVmcall(
    _In_ PIVCPU pVcpu,
    _In_ PVMX_VMCALL_PARAMETERS pVmcallParams
);

/*****************************************************
 * 功能：注入事件到客户机
 * 参数：pVcpu - VCPU结构指针
 *       InterruptionType - 中断类型
 *       Vector - 中断向量
 *       DeliverErrorCode - 是否传递错误代码
 *       ErrorCode - 错误代码
 * 返回：无
 * 备注：向客户机注入中断或异常
*****************************************************/
VOID VmxInjectEvent(
    _In_ PIVCPU pVcpu,
    _In_ ULONG InterruptionType,
    _In_ ULONG Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ ULONG ErrorCode
);

/*****************************************************
 * 功能：检查VM入口控制
 * 参数：pVcpu - VCPU结构指针
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：检查VM入口控制字段的有效性
*****************************************************/
BOOLEAN VmxCheckVmentryControls(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：检查VM退出控制
 * 参数：pVcpu - VCPU结构指针
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：检查VM退出控制字段的有效性
*****************************************************/
BOOLEAN VmxCheckVmexitControls(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：检查主机状态有效性
 * 参数：pVcpu - VCPU结构指针
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：检查主机状态区域的有效性
*****************************************************/
BOOLEAN VmxCheckHostState(_In_ PIVCPU pVcpu);

/*****************************************************
 * 功能：检查客户机状态有效性
 * 参数：pVcpu - VCPU结构指针
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：检查客户机状态区域的有效性
*****************************************************/
BOOLEAN VmxCheckGuestState(_In_ PIVCPU pVcpu);

// 汇编函数声明（由汇编代码实现）

/*****************************************************
 * 功能：VM退出处理程序入口点
 * 参数：无（通过堆栈传递）
 * 返回：无
 * 备注：汇编实现的VM退出处理程序入口点
*****************************************************/
EXTERN_C VOID VmxVmExitHandler(VOID);

/*****************************************************
 * 功能：保存主机状态
 * 参数：pHostState - 主机状态结构指针
 * 返回：无
 * 备注：汇编实现的主机状态保存函数
*****************************************************/
EXTERN_C VOID VmxSaveHostState(_In_ PVOID pHostState);

/*****************************************************
 * 功能：恢复主机状态
 * 参数：pHostState - 主机状态结构指针
 * 返回：无
 * 备注：汇编实现的主机状态恢复函数
*****************************************************/
EXTERN_C VOID VmxRestoreHostState(_In_ PVOID pHostState);

/*****************************************************
 * 功能：启动客户机执行
 * 参数：无
 * 返回：无
 * 备注：汇编实现的客户机启动函数
*****************************************************/
EXTERN_C VOID VmxLaunchGuest(VOID);

/*****************************************************
 * 功能：恢复客户机执行
 * 参数：无
 * 返回：无
 * 备注：汇编实现的客户机恢复函数
*****************************************************/
EXTERN_C VOID VmxResumeGuest(VOID);