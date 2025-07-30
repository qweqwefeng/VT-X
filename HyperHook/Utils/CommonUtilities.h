#pragma once

#include <ntifs.h>
#include "../Definitions/SystemDefinitions.h"

/*****************************************************
 * 功能：通用工具函数头文件
 * 备注：提供系统初始化、DPC调度等通用功能
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
    _In_opt_ PVOID SystemArgument2
);

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
    _In_opt_ PVOID SystemArgument2
);