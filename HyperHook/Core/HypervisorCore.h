#pragma once
#include <ntifs.h>

/*****************************************************
 * 功能：检测是否支持VT-x/AMD-V
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：调用CPUID等指令检测当前CPU虚拟化扩展支持情况
 *****************************************************/
BOOLEAN HvIsVirtualizationSupported(VOID);

/*****************************************************
 * 功能：检查并扩展VMX支持的特性
 * 参数：
 *     pFeatures - 用于存放检测结果
 * 返回：VOID
 * 备注：
*****************************************************/
VOID HvCheckFeatures();

/*****************************************************
 * 功能：对每个CPU进行虚拟化初始化
 * 参数：无
 * 返回：NTSTATUS 状态码
 * 备注：依次对所有处理器启动虚拟化环境
 *****************************************************/
NTSTATUS HvStartVirtualization(VOID);

/*****************************************************
 * 功能：对每个CPU取消虚拟化
 * 参数：无
 * 返回：NTSTATUS 状态码
 * 备注：依次对所有处理器退出虚拟化环境
 *****************************************************/
NTSTATUS HvStopVirtualization(VOID);

/*****************************************************
 * 功能：调整MSR控制值
 * 参数：
 *     MsrNumber    - MSR寄存器编号
 *     ControlValue - 控制值
 * 返回：ULONG - 调整后的控制值
 * 备注：根据MSR能力调整控制字段值，确保满足硬件要求
 *****************************************************/
ULONG HvAdjustMsrControl(_In_ ULONG64 MsrNumber, _In_ ULONG ControlValue);

/*****************************************************
 * 功能：设置MSR读写权限
 * 参数：
 *     MsrNumber     - MSR寄存器编号
 *     IsWrite       - TRUE=写操作，FALSE=读操作
 *     InterceptFlag - TRUE=拦截，FALSE=放行
 * 返回：无
 * 备注：在MSR位图中设置指定MSR的拦截状态
 *****************************************************/
VOID HvSetMsrInterception(_In_ ULONG64 MsrNumber, _In_ BOOLEAN IsWrite, _In_ BOOLEAN InterceptFlag);