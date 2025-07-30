#pragma once
#include "../Arch/Intel/Vmx.h"

// VMX相关常量定义
#define VMX_TAG							'VMXF'
#define VMX_MSR_BITMAP_SIZE             4096        // MSR位图大小（4KB）
#define VMX_MAX_PROCESSOR_COUNT         256         // 最大支持处理器数量
#define VMM_STACK_SIZE                  0x6000      // VMM堆栈大小


/*****************************************************
 * 结构：VMX_ENGINE_CONTEXT
 * 功能：VMX引擎全局上下文
 * 说明：管理整个VMX虚拟化引擎的状态和资源
*****************************************************/
typedef struct _VMX_ENGINE_CONTEXT
{
	// 同步对象
	KSPIN_LOCK              VmxSpinLock;            // VMX操作自旋锁

	PVCPU* VcpuArray;								// VCPU数组指针
	ULONG                   ProcessorCount;         // 处理器数量

	// VMX资源
	PUCHAR                  MsrBitmap;              // MSR访问位图
	PHYSICAL_ADDRESS        MsrBitmapPhysical;      // MSR位图物理地址

} VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * 结构：VMX_INITIALIZATION_CONTEXT
 * 功能：VMX初始化同步上下文
 * 说明：用于多CPU并行初始化的同步控制
*****************************************************/
typedef struct _VMX_INITIALIZATION_CONTEXT
{
	PVMX_ENGINE_CONTEXT     VmxContext;            // VMX引擎上下文
	ULONG64                 SystemCr3;             // 系统CR3值
	volatile LONG           SuccessCount;          // 成功初始化的CPU数量
	volatile LONG           FailureCount;          // 失败的CPU数量
	NTSTATUS                Status;                // 初始化状态
	KEVENT                  CompletionEvent;       // 完成事件
	BOOLEAN                 ForceInitialization;   // 强制初始化标志
} VMX_INITIALIZATION_CONTEXT, * PVMX_INITIALIZATION_CONTEXT;

/*****************************************************
 * 功能：初始化VMX引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：检查硬件支持并初始化VMX环境
*****************************************************/
NTSTATUS VmxInitializeEngineContext(PVMX_ENGINE_CONTEXT* ppVmxContext);

/*****************************************************
 * 功能：清理VMX引擎上下文
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：释放VMX引擎相关的所有资源
*****************************************************/
VOID VmxCleanupEngineContext(_In_opt_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * 功能：检查VMX硬件支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：全面检查CPU和BIOS对VMX的支持情况
*****************************************************/
BOOLEAN VmxCheckHardwareSupport(VOID);

/*****************************************************
 * 功能：分配MSR位图
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：分配并初始化MSR访问控制位图
*****************************************************/
NTSTATUS VmxAllocateMsrBitmap(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * 功能：初始化VMX MSR位图，配置关键MSR拦截
 * 参数：pMsrBitmap - 指向4KB MSR位图内存（需4KB对齐）
 * 返回：无
 * 备注：
 *     - 按Intel SDM规范分为读低、读高、写低、写高四区块
 *     - 可根据需求增加/减少拦截的MSR
*****************************************************/
VOID VmxInitializeMsrBitmap(_In_ PUCHAR pMsrBitmap);

/*****************************************************
 * 功能：在所有处理器上启动VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：使用DPC在每个CPU上并行初始化VMX
*****************************************************/
NTSTATUS VmxStartOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * 功能：VMX初始化DPC例程
 * 参数：Dpc - DPC对象
 *       Context - 初始化上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX初始化的实际工作
*****************************************************/
VOID VmxInitializationDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);

/*****************************************************
 * 功能：在所有处理器上停止VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：使用DPC在每个CPU上并行停止VMX
*****************************************************/
VOID VmxStopOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * 功能：VMX停止DPC例程
 * 参数：Dpc - DPC对象
 *       Context - VMX引擎上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX停止操作
*****************************************************/
VOID VmxStopDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);
