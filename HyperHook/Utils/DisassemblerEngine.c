/*****************************************************
 * 文件：DisassemblerEngine.c
 * 功能：反汇编引擎核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：重构的反汇编引擎，基于LDasm改进
*****************************************************/

#include "DisassemblerEngine.h"
#include "../Memory/MemoryManager.h"

// 全局反汇编引擎上下文
static DISASM_ENGINE_CONTEXT g_DisasmEngineContext = { 0 };

// x86/x64指令表
static const UCHAR g_InstructionTable[256] = {
    // 这里是简化的指令表，实际实现需要完整的指令编码表
    // 每个字节对应一个指令的长度信息和标志

    // 0x00-0x0F
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x00,

    // 0x10-0x1F
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,

    // 继续填充其他字节...
    // 为了简化，这里只显示部分
};

/*****************************************************
 * 功能：初始化反汇编引擎
 * 参数：IsX64Mode - 是否为64位模式
 * 返回：NTSTATUS - 状态码
 * 备注：初始化反汇编引擎的全局状态
*****************************************************/
NTSTATUS
DeInitializeEngine(
    _In_ BOOLEAN IsX64Mode
)
{
    if (g_DisasmEngineContext.IsInitialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    // 初始化引擎上下文
    RtlZeroMemory(&g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    g_DisasmEngineContext.IsInitialized = TRUE;
    g_DisasmEngineContext.IsX64Mode = IsX64Mode;

    // 设置默认配置
    g_DisasmEngineContext.EnableDetailedAnalysis = TRUE;
    g_DisasmEngineContext.EnableCaching = FALSE; // 暂时禁用缓存
    g_DisasmEngineContext.EnableValidation = TRUE;
    g_DisasmEngineContext.MaxAnalyzeSize = DISASM_MAX_ANALYZE_LENGTH;

    // 初始化统计信息
    g_DisasmEngineContext.TotalAnalyses = 0;
    g_DisasmEngineContext.SuccessfulAnalyses = 0;
    g_DisasmEngineContext.FailedAnalyses = 0;
    g_DisasmEngineContext.CacheHits = 0;

    DPRINT("反汇编引擎初始化成功 [模式: %s]\n", IsX64Mode ? "x64" : "x86");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：卸载反汇编引擎
 * 参数：无
 * 返回：无
 * 备注：清理反汇编引擎资源
*****************************************************/
VOID
DeUninitializeEngine(
    VOID
)
{
    if (!g_DisasmEngineContext.IsInitialized)
    {
        return;
    }

    // 打印统计信息
    DPRINT("反汇编引擎统计信息:\n");
    DPRINT("  总分析次数: %I64u\n", g_DisasmEngineContext.TotalAnalyses);
    DPRINT("  成功分析次数: %I64u\n", g_DisasmEngineContext.SuccessfulAnalyses);
    DPRINT("  失败分析次数: %I64u\n", g_DisasmEngineContext.FailedAnalyses);
    DPRINT("  缓存命中次数: %I64u\n", g_DisasmEngineContext.CacheHits);

    // 清理上下文
    RtlZeroMemory(&g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    DPRINT("反汇编引擎卸载完成\n");
}

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
)
{
    PUCHAR pBytes = NULL;
    ULONG length = 0;
    ULONG offset = 0;
    UCHAR opcode = 0;
    BOOLEAN hasModRm = FALSE;
    BOOLEAN hasSib = FALSE;
    ULONG displacementSize = 0;
    ULONG immediateSize = 0;

    if (pCode == NULL || pInstruction == NULL)
    {
        return 0;
    }

    __try
    {
        pBytes = (PUCHAR)pCode;
        RtlZeroMemory(pInstruction, sizeof(DISASM_INSTRUCTION));

        // 解析前缀
        while (offset < DISASM_MAX_INSTRUCTION_LENGTH)
        {
            UCHAR currentByte = pBytes[offset];

            // 检查是否为前缀
            if (DeIsPrefix(currentByte))
            {
                if (pInstruction->PrefixCount < sizeof(pInstruction->Prefixes))
                {
                    pInstruction->Prefixes[pInstruction->PrefixCount] = currentByte;
                    pInstruction->PrefixCount++;
                }

                pInstruction->Flags |= DISASM_FLAG_PREFIX;
                offset++;
                continue;
            }

            // 检查REX前缀（仅64位模式）
            if (IsX64 && (currentByte >= 0x40 && currentByte <= 0x4F))
            {
                pInstruction->Rex = currentByte;
                pInstruction->HasRex = TRUE;
                pInstruction->Flags |= DISASM_FLAG_REX;
                offset++;
                continue;
            }

            // 操作码
            pInstruction->OpcodeOffset = (UCHAR)offset;
            opcode = currentByte;
            pInstruction->Opcode = opcode;
            offset++;

            // 检查是否为双字节操作码
            if (opcode == 0x0F)
            {
                if (offset >= DISASM_MAX_INSTRUCTION_LENGTH)
                {
                    pInstruction->Flags |= DISASM_FLAG_INVALID;
                    return 0;
                }

                opcode = pBytes[offset];
                pInstruction->Opcode = opcode;
                pInstruction->OpcodeSize = 2;
                offset++;
            }
            else
            {
                pInstruction->OpcodeSize = 1;
            }

            break;
        }

        // 检查是否需要ModR/M字节
        hasModRm = DeNeedsModRm(pInstruction->Opcode);
        if (hasModRm)
        {
            if (offset >= DISASM_MAX_INSTRUCTION_LENGTH)
            {
                pInstruction->Flags |= DISASM_FLAG_INVALID;
                return 0;
            }

            pInstruction->ModRm = pBytes[offset];
            pInstruction->HasModRm = TRUE;
            pInstruction->Flags |= DISASM_FLAG_MODRM;
            offset++;

            // 检查是否需要SIB字节
            UCHAR mod = (pInstruction->ModRm >> 6) & 3;
            UCHAR rm = pInstruction->ModRm & 7;

            if (mod != 3 && rm == 4)
            {
                if (offset >= DISASM_MAX_INSTRUCTION_LENGTH)
                {
                    pInstruction->Flags |= DISASM_FLAG_INVALID;
                    return 0;
                }

                pInstruction->Sib = pBytes[offset];
                pInstruction->HasSib = TRUE;
                pInstruction->Flags |= DISASM_FLAG_SIB;
                hasSib = TRUE;
                offset++;
            }

            // 计算位移大小
            displacementSize = DeCalculateDisplacementSize(pInstruction);
            if (displacementSize > 0)
            {
                pInstruction->DisplacementOffset = (UCHAR)offset;
                pInstruction->DisplacementSize = (UCHAR)displacementSize;
                pInstruction->Flags |= DISASM_FLAG_DISPLACEMENT;
                offset += displacementSize;
            }
        }

        // 计算立即数大小
        immediateSize = DeCalculateImmediateSize(pInstruction);
        if (immediateSize > 0)
        {
            if (offset + immediateSize > DISASM_MAX_INSTRUCTION_LENGTH)
            {
                pInstruction->Flags |= DISASM_FLAG_INVALID;
                return 0;
            }

            pInstruction->ImmediateOffset = (UCHAR)offset;
            pInstruction->ImmediateSize = (UCHAR)immediateSize;
            pInstruction->Flags |= DISASM_FLAG_IMMEDIATE;
            offset += immediateSize;
        }

        // 设置指令长度
        length = offset;
        pInstruction->Length = (UCHAR)length;

        // 复制原始字节
        if (length <= sizeof(pInstruction->RawBytes))
        {
            RtlCopyMemory(pInstruction->RawBytes, pBytes, length);
        }

        // 确定指令类型
        pInstruction->Type = DeGetInstructionType(pInstruction);

        // 检查相对跳转
        if (DeIsRelativeJump(pInstruction))
        {
            pInstruction->Flags |= DISASM_FLAG_RELATIVE;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("反汇编指令时发生异常: 0x%08X\n", GetExceptionCode());
        pInstruction->Flags |= DISASM_FLAG_INVALID;
        return 0;
    }

    // 更新统计
    InterlockedIncrement64(&g_DisasmEngineContext.TotalAnalyses);

    if (pInstruction->Flags & DISASM_FLAG_INVALID)
    {
        InterlockedIncrement64(&g_DisasmEngineContext.FailedAnalyses);
        return 0;
    }
    else
    {
        InterlockedIncrement64(&g_DisasmEngineContext.SuccessfulAnalyses);
        return length;
    }
}

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
)
{
    PUCHAR pCode = NULL;
    ULONG totalLength = 0;
    ULONG instructionLength = 0;
    DISASM_INSTRUCTION instruction = { 0 };

    if (pFunction == NULL || pBuffer == NULL || pCopiedSize == NULL || BufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *pCopiedSize = 0;

    __try
    {
        pCode = (PUCHAR)pFunction;

        // 分析函数，复制足够的字节用于Hook
        while (totalLength < DISASM_MIN_HOOK_SIZE && totalLength < BufferSize)
        {
            instructionLength = DeDisassembleInstruction(
                pCode + totalLength,
                &instruction,
                g_DisasmEngineContext.IsX64Mode
            );

            if (instructionLength == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
            {
                DPRINT("在偏移 %u 处遇到无效指令\n", totalLength);
                return STATUS_UNSUCCESSFUL;
            }

            // 检查是否为终止指令
            if (DeIsReturnInstruction(&instruction) ||
                (instruction.Opcode == 0xCC) || // INT3 (断点)
                (instruction.Opcode == 0xC3))   // RET
            {
                DPRINT("在偏移 %u 处遇到终止指令\n", totalLength);
                break;
            }

            totalLength += instructionLength;
        }

        // 确保有足够的长度
        if (totalLength < DISASM_MIN_HOOK_SIZE)
        {
            DPRINT("函数长度不足，无法安全Hook: %u < %u\n", totalLength, DISASM_MIN_HOOK_SIZE);
            return STATUS_BUFFER_TOO_SMALL;
        }

        // 复制字节
        if (totalLength > BufferSize)
        {
            totalLength = BufferSize;
        }

        RtlCopyMemory(pBuffer, pCode, totalLength);
        *pCopiedSize = totalLength;

        DPRINT("函数分析完成: 复制了 %u 字节\n", totalLength);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("分析函数时发生异常: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

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
)
{
    PUCHAR pCode = NULL;
    ULONG offset = 0;
    ULONG instructionLength = 0;
    DISASM_INSTRUCTION instruction = { 0 };

    if (pFunction == NULL || pResult == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (MaxSize == 0 || MaxSize > g_DisasmEngineContext.MaxAnalyzeSize)
    {
        MaxSize = g_DisasmEngineContext.MaxAnalyzeSize;
    }

    // 初始化分析结果
    RtlZeroMemory(pResult, sizeof(DISASM_ANALYSIS_RESULT));
    pResult->FunctionStart = pFunction;
    pResult->MinHookSize = DISASM_MIN_HOOK_SIZE;
    pResult->CanHook = TRUE;

    __try
    {
        pCode = (PUCHAR)pFunction;

        // 逐条分析指令
        while (offset < MaxSize)
        {
            instructionLength = DeDisassembleInstruction(
                pCode + offset,
                &instruction,
                g_DisasmEngineContext.IsX64Mode
            );

            if (instructionLength == 0)
            {
                pResult->InvalidInstructions++;
                offset++; // 跳过无效字节
                continue;
            }

            if (instruction.Flags & DISASM_FLAG_INVALID)
            {
                pResult->InvalidInstructions++;
                break;
            }

            pResult->TotalInstructions++;
            pResult->ValidInstructions++;

            // 分类指令
            if (DeIsJumpInstruction(&instruction))
            {
                pResult->JumpInstructions++;

                if (instruction.Flags & DISASM_FLAG_RELATIVE)
                {
                    pResult->HasRelativeJumps = TRUE;
                }
                else
                {
                    pResult->HasAbsoluteJumps = TRUE;
                }
            }
            else if (DeIsCallInstruction(&instruction))
            {
                pResult->CallInstructions++;
                pResult->HasCalls = TRUE;
            }
            else if (DeIsReturnInstruction(&instruction))
            {
                pResult->ReturnInstructions++;

                // 如果在前几个字节就遇到返回指令，可能不适合Hook
                if (offset < DISASM_MIN_HOOK_SIZE)
                {
                    pResult->CanHook = FALSE;
                }
                break; // 函数结束
            }

            // 检查复杂指令
            if (DeIsComplexInstruction(&instruction))
            {
                pResult->HasComplexInstructions = TRUE;
            }

            offset += instructionLength;
        }

        pResult->AnalyzedSize = offset;

        // 计算推荐Hook大小
        pResult->RecommendedHookSize = max(pResult->MinHookSize,
                                           DeCalculateRecommendedHookSize(pResult));

        // 最终Hook可行性检查
        if (pResult->AnalyzedSize < DISASM_MIN_HOOK_SIZE)
        {
            pResult->CanHook = FALSE;
        }

        DPRINT("函数分析完成: 大小=%u, 指令=%u, 可Hook=%s\n",
               pResult->AnalyzedSize, pResult->TotalInstructions,
               pResult->CanHook ? "是" : "否");

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("详细分析函数时发生异常: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

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
)
{
    PUCHAR pCode = NULL;
    ULONG totalLength = 0;
    ULONG instructionLength = 0;
    DISASM_INSTRUCTION instruction = { 0 };

    if (pFunction == NULL || pMinSize == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *pMinSize = 0;

    __try
    {
        pCode = (PUCHAR)pFunction;

        // 分析指令直到满足最小Hook大小
        while (totalLength < DISASM_MIN_HOOK_SIZE)
        {
            instructionLength = DeDisassembleInstruction(
                pCode + totalLength,
                &instruction,
                g_DisasmEngineContext.IsX64Mode
            );

            if (instructionLength == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
            {
                return STATUS_UNSUCCESSFUL;
            }

            // 检查指令边界完整性
            if (totalLength + instructionLength > DISASM_MIN_HOOK_SIZE)
            {
                // 如果下一条指令会超出最小大小，需要包含完整指令
                totalLength += instructionLength;
                break;
            }

            totalLength += instructionLength;
        }

        *pMinSize = totalLength;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

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
)
{
    PUCHAR pBytes = NULL;
    ULONG offset = 0;
    ULONG instructionLength = 0;
    DISASM_INSTRUCTION instruction = { 0 };

    if (pCode == NULL || Size == 0)
    {
        return FALSE;
    }

    __try
    {
        pBytes = (PUCHAR)pCode;

        while (offset < Size)
        {
            instructionLength = DeDisassembleInstruction(
                pBytes + offset,
                &instruction,
                g_DisasmEngineContext.IsX64Mode
            );

            if (instructionLength == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
            {
                return FALSE;
            }

            offset += instructionLength;
        }

        // 确保最后一条指令不会超出边界
        return (offset == Size);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*****************************************************
 * 功能：检查是否为跳转指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是跳转指令，FALSE不是
 * 备注：检查指令是否为各种类型的跳转
*****************************************************/
BOOLEAN
DeIsJumpInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    if (pInstruction == NULL)
    {
        return FALSE;
    }

    UCHAR opcode = pInstruction->Opcode;

    // 条件跳转指令 (0x70-0x7F)
    if (opcode >= 0x70 && opcode <= 0x7F)
    {
        return TRUE;
    }

    // 无条件跳转
    if (opcode == 0xE9 || opcode == 0xEB || opcode == 0xEA)
    {
        return TRUE;
    }

    // 间接跳转
    if (opcode == 0xFF)
    {
        UCHAR modrmReg = (pInstruction->ModRm >> 3) & 7;
        return (modrmReg == 4 || modrmReg == 5); // JMP r/m64 或 JMP m16:64
    }

    // 双字节操作码的条件跳转 (0x0F 0x80-0x8F)
    if (pInstruction->OpcodeSize == 2 && pInstruction->Prefixes[0] == 0x0F)
    {
        return (opcode >= 0x80 && opcode <= 0x8F);
    }

    return FALSE;
}

/*****************************************************
 * 功能：检查是否为调用指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是调用指令，FALSE不是
 * 备注：检查指令是否为函数调用
*****************************************************/
BOOLEAN
DeIsCallInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    if (pInstruction == NULL)
    {
        return FALSE;
    }

    UCHAR opcode = pInstruction->Opcode;

    // 直接调用
    if (opcode == 0xE8)
    {
        return TRUE;
    }

    // 远程调用
    if (opcode == 0x9A)
    {
        return TRUE;
    }

    // 间接调用
    if (opcode == 0xFF)
    {
        UCHAR modrmReg = (pInstruction->ModRm >> 3) & 7;
        return (modrmReg == 2 || modrmReg == 3); // CALL r/m64 或 CALL m16:64
    }

    return FALSE;
}

/*****************************************************
 * 功能：检查是否为返回指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是返回指令，FALSE不是
 * 备注：检查指令是否为函数返回
*****************************************************/
BOOLEAN
DeIsReturnInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    if (pInstruction == NULL)
    {
        return FALSE;
    }

    UCHAR opcode = pInstruction->Opcode;

    // 各种返回指令
    return (opcode == 0xC3 ||  // RET near
            opcode == 0xC2 ||  // RET near imm16
            opcode == 0xCB ||  // RET far
            opcode == 0xCA);   // RET far imm16
}

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
)
{
    if (pInstruction == NULL || pTargetAddress == NULL)
    {
        return FALSE;
    }

    *pTargetAddress = 0;

    // 只处理相对跳转和调用
    if (!(pInstruction->Flags & DISASM_FLAG_RELATIVE))
    {
        return FALSE;
    }

    if (!DeIsJumpInstruction(pInstruction) && !DeIsCallInstruction(pInstruction))
    {
        return FALSE;
    }

    if (pInstruction->ImmediateSize == 0)
    {
        return FALSE;
    }

    __try
    {
        LONG_PTR displacement = 0;
        PUCHAR pImmediate = pInstruction->RawBytes + pInstruction->ImmediateOffset;

        // 根据立即数大小计算位移
        switch (pInstruction->ImmediateSize)
        {
            case 1:
                displacement = (CHAR)pImmediate[0];
                break;
            case 2:
                displacement = (SHORT)(pImmediate[0] | (pImmediate[1] << 8));
                break;
            case 4:
                displacement = (LONG)(pImmediate[0] | (pImmediate[1] << 8) |
                                      (pImmediate[2] << 16) | (pImmediate[3] << 24));
                break;
            default:
                return FALSE;
        }

        // 计算目标地址 = 指令地址 + 指令长度 + 位移
        *pTargetAddress = InstructionAddress + pInstruction->Length + displacement;

        return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*****************************************************
 * 功能：解析函数大小
 * 参数：pFunction - 函数指针
 * 返回：ULONG - 函数大小，0表示失败
 * 备注：通过反汇编分析确定函数大小
*****************************************************/
ULONG
DeGetFunctionSize(
    _In_ PVOID pFunction
)
{
    DISASM_ANALYSIS_RESULT result = { 0 };
    NTSTATUS status;

    if (pFunction == NULL)
    {
        return 0;
    }

    status = DeAnalyzeFunction(pFunction, g_DisasmEngineContext.MaxAnalyzeSize, &result);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    return result.AnalyzedSize;
}

/*****************************************************
 * 功能：解析跳转目标
 * 参数：pFunction - 函数指针
 * 返回：PVOID - 跳转目标地址，NULL表示不是跳转
 * 备注：解析函数是否为简单跳转，并返回目标
*****************************************************/
PVOID
DeResolveJumpTarget(
    _In_ PVOID pFunction
)
{
    DISASM_INSTRUCTION instruction = { 0 };
    ULONG_PTR targetAddress = 0;

    if (pFunction == NULL)
    {
        return NULL;
    }

    __try
    {
        // 反汇编第一条指令
        ULONG length = DeDisassembleInstruction(pFunction, &instruction, g_DisasmEngineContext.IsX64Mode);
        if (length == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
        {
            return NULL;
        }

        // 检查是否为无条件跳转
        if (!DeIsJumpInstruction(&instruction))
        {
            return NULL;
        }

        // 只处理简单的无条件跳转
        if (instruction.Opcode != 0xE9 && instruction.Opcode != 0xEB)
        {
            return NULL;
        }

        // 计算目标地址
        if (DeGetInstructionTarget(&instruction, (ULONG_PTR)pFunction, &targetAddress))
        {
            return (PVOID)targetAddress;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 忽略异常
    }

    return NULL;
}

/*****************************************************
 * 功能：获取反汇编引擎统计信息
 * 参数：pContext - 输出引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前反汇编引擎的运行统计
*****************************************************/
NTSTATUS
DeGetEngineStatistics(
    _Out_ PDISASM_ENGINE_CONTEXT pContext
)
{
    if (pContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_DisasmEngineContext.IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 复制统计信息
    RtlCopyMemory(pContext, &g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    return STATUS_SUCCESS;
}

// 内部辅助函数实现

/*****************************************************
 * 功能：检查是否为前缀字节
 * 参数：Byte - 字节值
 * 返回：BOOLEAN - TRUE是前缀，FALSE不是
 * 备注：检查x86/x64前缀字节
*****************************************************/
BOOLEAN
DeIsPrefix(
    _In_ UCHAR Byte
)
{
    // x86/x64前缀字节
    switch (Byte)
    {
        case 0x26: // ES segment override
        case 0x2E: // CS segment override
        case 0x36: // SS segment override
        case 0x3E: // DS segment override
        case 0x64: // FS segment override
        case 0x65: // GS segment override
        case 0x66: // Operand size override
        case 0x67: // Address size override
        case 0xF0: // LOCK
        case 0xF2: // REPNE/REPNZ
        case 0xF3: // REP/REPE/REPZ
            return TRUE;
        default:
            return FALSE;
    }
}

/*****************************************************
 * 功能：检查指令是否需要ModR/M字节
 * 参数：Opcode - 操作码
 * 返回：BOOLEAN - TRUE需要，FALSE不需要
 * 备注：根据操作码判断是否需要ModR/M字节
*****************************************************/
BOOLEAN
DeNeedsModRm(
    _In_ UCHAR Opcode
)
{
    // 这是简化的实现，实际需要更完整的操作码表
    // 大部分操作码都需要ModR/M字节，这里列出不需要的
    switch (Opcode)
    {
        case 0x90: // NOP
        case 0xC3: // RET near
        case 0xCB: // RET far
        case 0xCC: // INT3
        case 0xF4: // HLT
        case 0xFA: // CLI
        case 0xFB: // STI
            return FALSE;
        default:
            // 大部分指令都需要ModR/M
            return TRUE;
    }
}

/*****************************************************
 * 功能：计算位移大小
 * 参数：pInstruction - 指令信息
 * 返回：ULONG - 位移大小
 * 备注：根据ModR/M字节计算位移大小
*****************************************************/
ULONG
DeCalculateDisplacementSize(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    if (!pInstruction->HasModRm)
    {
        return 0;
    }

    UCHAR mod = (pInstruction->ModRm >> 6) & 3;
    UCHAR rm = pInstruction->ModRm & 7;

    switch (mod)
    {
        case 0: // [reg] or [disp32]
            if (rm == 5) // [disp32]
                return 4;
            else if (rm == 4 && pInstruction->HasSib) // [SIB]
            {
                UCHAR base = pInstruction->Sib & 7;
                return (base == 5) ? 4 : 0; // [disp32 + index*scale] or [base + index*scale]
            }
            return 0;

        case 1: // [reg + disp8]
            return 1;

        case 2: // [reg + disp32]
            return 4;

        case 3: // reg
            return 0;

        default:
            return 0;
    }
}

/*****************************************************
 * 功能：计算立即数大小
 * 参数：pInstruction - 指令信息
 * 返回：ULONG - 立即数大小
 * 备注：根据操作码计算立即数大小
*****************************************************/
ULONG
DeCalculateImmediateSize(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    UCHAR opcode = pInstruction->Opcode;

    // 这是简化的实现，实际需要更完整的操作码分析
    switch (opcode)
    {
        case 0xE8: // CALL rel32
        case 0xE9: // JMP rel32
            return 4;

        case 0xEB: // JMP rel8
            return 1;

        case 0xC2: // RET imm16
        case 0xCA: // RET far imm16
            return 2;

            // 条件跳转 rel8
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            return 1;

        default:
            // 需要根据具体指令进一步分析
            return 0;
    }
}

/*****************************************************
 * 功能：获取指令类型
 * 参数：pInstruction - 指令信息
 * 返回：UCHAR - 指令类型
 * 备注：根据操作码确定指令类型
*****************************************************/
UCHAR
DeGetInstructionType(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    UCHAR opcode = pInstruction->Opcode;

    // 控制转移指令
    if (DeIsJumpInstruction(pInstruction) || DeIsCallInstruction(pInstruction) ||
        DeIsReturnInstruction(pInstruction))
    {
        return DISASM_TYPE_CONTROL_TRANSFER;
    }

    // 算术运算指令
    if ((opcode >= 0x00 && opcode <= 0x05) || // ADD
        (opcode >= 0x28 && opcode <= 0x2D) || // SUB
        (opcode >= 0x38 && opcode <= 0x3D))   // CMP
    {
        return DISASM_TYPE_ARITHMETIC;
    }

    // 数据传送指令
    if ((opcode >= 0x88 && opcode <= 0x8B) || // MOV
        (opcode >= 0xB0 && opcode <= 0xBF))   // MOV immediate
    {
        return DISASM_TYPE_DATA_TRANSFER;
    }

    // 默认为未知类型
    return DISASM_TYPE_UNKNOWN;
}

/*****************************************************
 * 功能：检查是否为相对跳转
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是相对跳转，FALSE不是
 * 备注：检查跳转指令是否使用相对地址
*****************************************************/
BOOLEAN
DeIsRelativeJump(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    if (!DeIsJumpInstruction(pInstruction) && !DeIsCallInstruction(pInstruction))
    {
        return FALSE;
    }

    UCHAR opcode = pInstruction->Opcode;

    // 相对跳转指令
    return (opcode == 0xE8 || // CALL rel32
            opcode == 0xE9 || // JMP rel32
            opcode == 0xEB || // JMP rel8
            (opcode >= 0x70 && opcode <= 0x7F) || // 条件跳转 rel8
            (pInstruction->OpcodeSize == 2 && pInstruction->Prefixes[0] == 0x0F &&
            opcode >= 0x80 && opcode <= 0x8F)); // 条件跳转 rel32
}

/*****************************************************
 * 功能：检查是否为复杂指令
 * 参数：pInstruction - 指令信息
 * 返回：BOOLEAN - TRUE是复杂指令，FALSE不是
 * 备注：检查指令是否为复杂的多字节指令
*****************************************************/
BOOLEAN
DeIsComplexInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    // 多前缀指令
    if (pInstruction->PrefixCount > 2)
    {
        return TRUE;
    }

    // 长指令
    if (pInstruction->Length > 7)
    {
        return TRUE;
    }

    // 双字节操作码
    if (pInstruction->OpcodeSize > 1)
    {
        return TRUE;
    }

    // 有SIB字节的指令
    if (pInstruction->HasSib)
    {
        return TRUE;
    }

    return FALSE;
}

/*****************************************************
 * 功能：计算推荐Hook大小
 * 参数：pResult - 分析结果
 * 返回：ULONG - 推荐Hook大小
 * 备注：根据分析结果计算最佳Hook大小
*****************************************************/
ULONG
DeCalculateRecommendedHookSize(
    _In_ PDISASM_ANALYSIS_RESULT pResult
)
{
    ULONG recommendedSize = DISASM_MIN_HOOK_SIZE;

    // 如果有相对跳转，增加Hook大小以避免问题
    if (pResult->HasRelativeJumps)
    {
        recommendedSize += 8;
    }

    // 如果有复杂指令，增加Hook大小
    if (pResult->HasComplexInstructions)
    {
        recommendedSize += 4;
    }

    // 确保不超过分析的大小
    if (recommendedSize > pResult->AnalyzedSize)
    {
        recommendedSize = pResult->AnalyzedSize;
    }

    return recommendedSize;
}