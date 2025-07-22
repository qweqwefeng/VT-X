/*****************************************************
 * 文件：DisassemblerEngine.h
 * 功能：反汇编引擎头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：重构的LDasm反汇编引擎，提供指令分析功能
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// 反汇编引擎常量定义
#define DISASM_MAX_INSTRUCTION_LENGTH   15          // x64最大指令长度
#define DISASM_MAX_ANALYZE_LENGTH       128         // 最大分析长度
#define DISASM_MIN_HOOK_SIZE            5           // 最小Hook大小

// 指令标志定义
#define DISASM_FLAG_INVALID             0x01        // 无效指令
#define DISASM_FLAG_PREFIX              0x02        // 前缀
#define DISASM_FLAG_REX                 0x04        // REX前缀
#define DISASM_FLAG_MODRM               0x08        // ModR/M字节
#define DISASM_FLAG_SIB                 0x10        // SIB字节
#define DISASM_FLAG_DISPLACEMENT        0x20        // 位移
#define DISASM_FLAG_IMMEDIATE           0x40        // 立即数
#define DISASM_FLAG_RELATIVE            0x80        // 相对跳转

// 指令类型定义
#define DISASM_TYPE_UNKNOWN             0           // 未知指令
#define DISASM_TYPE_DATA_TRANSFER       1           // 数据传送
#define DISASM_TYPE_ARITHMETIC          2           // 算术运算
#define DISASM_TYPE_LOGICAL             3           // 逻辑运算
#define DISASM_TYPE_CONTROL_TRANSFER    4           // 控制转移
#define DISASM_TYPE_STRING              5           // 字符串操作
#define DISASM_TYPE_SYSTEM              6           // 系统指令
#define DISASM_TYPE_SSE                 7           // SSE指令
#define DISASM_TYPE_AVX                 8           // AVX指令

/*****************************************************
 * 结构：DISASM_INSTRUCTION
 * 功能：反汇编指令信息
 * 说明：包含单条指令的详细信息
*****************************************************/
typedef struct _DISASM_INSTRUCTION
{
    // 基本信息
    UCHAR                   Flags;                  // 指令标志
    UCHAR                   Length;                 // 指令长度
    UCHAR                   Type;                   // 指令类型
    UCHAR                   Opcode;                 // 操作码

    // 前缀信息
    UCHAR                   PrefixCount;            // 前缀数量
    UCHAR                   Prefixes[4];            // 前缀字节

    // REX前缀
    UCHAR                   Rex;                    // REX前缀
    BOOLEAN                 HasRex;                 // 是否有REX前缀

    // ModR/M和SIB
    UCHAR                   ModRm;                  // ModR/M字节
    UCHAR                   Sib;                    // SIB字节
    BOOLEAN                 HasModRm;               // 是否有ModR/M
    BOOLEAN                 HasSib;                 // 是否有SIB

    // 偏移信息
    UCHAR                   OpcodeOffset;           // 操作码偏移
    UCHAR                   OpcodeSize;             // 操作码大小
    UCHAR                   DisplacementOffset;     // 位移偏移
    UCHAR                   DisplacementSize;       // 位移大小
    UCHAR                   ImmediateOffset;        // 立即数偏移
    UCHAR                   ImmediateSize;          // 立即数大小

    // 原始字节
    UCHAR                   RawBytes[DISASM_MAX_INSTRUCTION_LENGTH]; // 原始字节

} DISASM_INSTRUCTION, * PDISASM_INSTRUCTION;

/*****************************************************
 * 结构：DISASM_ANALYSIS_RESULT
 * 功能：反汇编分析结果
 * 说明：包含函数分析的结果信息
*****************************************************/
typedef struct _DISASM_ANALYSIS_RESULT
{
    // 基本信息
    PVOID                   FunctionStart;          // 函数起始地址
    ULONG                   AnalyzedSize;           // 已分析大小
    ULONG                   TotalInstructions;      // 总指令数
    ULONG                   ValidInstructions;      // 有效指令数

    // Hook信息
    ULONG                   MinHookSize;            // 最小Hook大小
    ULONG                   RecommendedHookSize;    // 推荐Hook大小
    BOOLEAN                 CanHook;                // 是否可以Hook

    // 指令统计
    ULONG                   JumpInstructions;       // 跳转指令数
    ULONG                   CallInstructions;       // 调用指令数
    ULONG                   ReturnInstructions;     // 返回指令数
    ULONG                   InvalidInstructions;    // 无效指令数

    // 特殊指令
    BOOLEAN                 HasRelativeJumps;       // 是否有相对跳转
    BOOLEAN                 HasAbsoluteJumps;       // 是否有绝对跳转
    BOOLEAN                 HasCalls;               // 是否有调用
    BOOLEAN                 HasComplexInstructions; // 是否有复杂指令

} DISASM_ANALYSIS_RESULT, * PDISASM_ANALYSIS_RESULT;

/*****************************************************
 * 结构：DISASM_ENGINE_CONTEXT
 * 功能：反汇编引擎上下文
 * 说明：管理反汇编引擎的状态和配置
*****************************************************/
typedef struct _DISASM_ENGINE_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsInitialized;          // 是否已初始化
    BOOLEAN                 IsX64Mode;              // 是否为64位模式

    // 配置选项
    BOOLEAN                 EnableDetailedAnalysis; // 启用详细分析
    BOOLEAN                 EnableCaching;          // 启用缓存
    BOOLEAN                 EnableValidation;       // 启用验证
    ULONG                   MaxAnalyzeSize;         // 最大分析大小

    // 统计信息
    ULONG64                 TotalAnalyses;          // 总分析次数
    ULONG64                 SuccessfulAnalyses;     // 成功分析次数
    ULONG64                 FailedAnalyses;         // 失败分析次数
    ULONG64                 CacheHits;              // 缓存命中次数

} DISASM_ENGINE_CONTEXT, * PDISASM_ENGINE_CONTEXT;

// 函数声明

/*****************************************************
 * 功能：初始化反汇编引擎
 * 参数：IsX64Mode - 是否为64位模式
 * 返回：NTSTATUS - 状态码
 * 备注：初始化反汇编引擎的全局状态
*****************************************************/
NTSTATUS
DeInitializeEngine(
    _In_ BOOLEAN IsX64Mode
);

/*****************************************************
 * 功能：卸载反汇编引擎
 * 参数：无
 * 返回：无
 * 备注：清理反汇编引擎资源
*****************************************************/
VOID
DeUninitializeEngine(
    VOID
);

/*****************************************************
 * 功能：反汇编单条指令
 * 参数：pCode - 指令代码指针
 *       pInstruction - 输出指令信息
 *       IsX64 - 是否为64位模式
 * 返回：ULONG - 指令长度，0表示失败
 * 备注：反汇编单条x86/x64指令
*****************************************************/
ULONG
DeDisassembleInstruction(
    _In_ PVOID pCode,
    _Out_ PDISASM_INSTRUCTION pInstruction,
    _In_ BOOLEAN IsX64
);

/*****************************************************
 * 功能：分析函数并复制字节
 * 参数：pFunction - 函数指针
 *       pBuffer - 输出缓冲区
 *       BufferSize - 缓冲区大小
 *       pCopiedSize - 输出复制的大小
 * 返回：NTSTATUS - 状态码
 * 备注：分析函数并复制足够的字节用于Hook
*****************************************************/
NTSTATUS
DeAnalyzeFunctionAndCopy(
    _In_ PVOID pFunction,
    _Out_ PUCHAR pBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG pCopiedSize
);

/*****************************************************
 * 功能：分析函数结构
 * 参数：pFunction - 函数指针
 *       MaxSize - 最大分析大小
 *       pResult - 输出分析结果
 * 返回：NTSTATUS - 状态码
 * 备注：详细分析函数的结构和特征
*****************************************************/
NTSTATUS
DeAnalyzeFunction(
    _In_ PVOID pFunction,
    _In_ ULONG MaxSize,
    _Out_ PDISASM_ANALYSIS_RESULT pResult
);

/*****************************************************
 * 功能：计算Hook所需的最小大小
 * 参数：pFunction - 函数指针
 *       pMinSize - 输出最小大小
 * 返回：NTSTATUS - 状态码
 * 备注：计算安全Hook所需的最小字节数
*****************************************************/
NTSTATUS
DeCalculateMinimumHookSize(
    _In_ PVOID pFunction,
    _Out_ PULONG pMinSize
);

/*****************************************************
 * 功能：验证指令完整性
 * 参数：pCode - 指令代码指针
 *       Size - 代码大小
 * 返回：BOOLEAN - TRUE完整，FALSE不完整
 * 备注：验证指令边界的完整性
*****************************************************/
BOOLEAN
DeVerifyInstructionIntegrity(
    _In_ PVOID pCode,
    _In_ ULONG Size
);

/*****************************************************
 * 功能：检查是否为跳转指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是跳转指令，FALSE不是
 * 备注：检查指令是否为各种类型的跳转
*****************************************************/
BOOLEAN
DeIsJumpInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

/*****************************************************
 * 功能：检查是否为调用指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是调用指令，FALSE不是
 * 备注：检查指令是否为函数调用
*****************************************************/
BOOLEAN
DeIsCallInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

/*****************************************************
 * 功能：检查是否为返回指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是返回指令，FALSE不是
 * 备注：检查指令是否为函数返回
*****************************************************/
BOOLEAN
DeIsReturnInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

/*****************************************************
 * 功能：获取指令的目标地址
 * 参数：pInstruction - 指令信息
 *       InstructionAddress - 指令地址
 *       pTargetAddress - 输出目标地址
 * 返回：BOOLEAN - TRUE成功，FALSE失败
 * 备注：计算跳转或调用指令的目标地址
*****************************************************/
BOOLEAN
DeGetInstructionTarget(
    _In_ PDISASM_INSTRUCTION pInstruction,
    _In_ ULONG_PTR InstructionAddress,
    _Out_ PULONG_PTR pTargetAddress
);

/*****************************************************
 * 功能：解析函数大小
 * 参数：pFunction - 函数指针
 * 返回：ULONG - 函数大小，0表示失败
 * 备注：通过反汇编分析确定函数大小
*****************************************************/
ULONG
DeGetFunctionSize(
    _In_ PVOID pFunction
);

/*****************************************************
 * 功能：解析跳转目标
 * 参数：pFunction - 函数指针
 * 返回：PVOID - 跳转目标地址，NULL表示不是跳转
 * 备注：解析函数是否为简单跳转，并返回目标
*****************************************************/
PVOID
DeResolveJumpTarget(
    _In_ PVOID pFunction
);

/*****************************************************
 * 功能：获取反汇编引擎统计信息
 * 参数：pContext - 输出引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前反汇编引擎的运行统计
*****************************************************/
NTSTATUS
DeGetEngineStatistics(
    _Out_ PDISASM_ENGINE_CONTEXT pContext
);