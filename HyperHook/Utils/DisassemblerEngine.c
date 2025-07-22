/*****************************************************
 * �ļ���DisassemblerEngine.c
 * ���ܣ�������������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ع��ķ�������棬����LDasm�Ľ�
*****************************************************/

#include "DisassemblerEngine.h"
#include "../Memory/MemoryManager.h"

// ȫ�ַ��������������
static DISASM_ENGINE_CONTEXT g_DisasmEngineContext = { 0 };

// x86/x64ָ���
static const UCHAR g_InstructionTable[256] = {
    // �����Ǽ򻯵�ָ���ʵ��ʵ����Ҫ������ָ������
    // ÿ���ֽڶ�Ӧһ��ָ��ĳ�����Ϣ�ͱ�־

    // 0x00-0x0F
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x00,

    // 0x10-0x1F
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x05, 0x01, 0x01,

    // ������������ֽ�...
    // Ϊ�˼򻯣�����ֻ��ʾ����
};

/*****************************************************
 * ���ܣ���ʼ�����������
 * ������IsX64Mode - �Ƿ�Ϊ64λģʽ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ������������ȫ��״̬
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

    // ��ʼ������������
    RtlZeroMemory(&g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    g_DisasmEngineContext.IsInitialized = TRUE;
    g_DisasmEngineContext.IsX64Mode = IsX64Mode;

    // ����Ĭ������
    g_DisasmEngineContext.EnableDetailedAnalysis = TRUE;
    g_DisasmEngineContext.EnableCaching = FALSE; // ��ʱ���û���
    g_DisasmEngineContext.EnableValidation = TRUE;
    g_DisasmEngineContext.MaxAnalyzeSize = DISASM_MAX_ANALYZE_LENGTH;

    // ��ʼ��ͳ����Ϣ
    g_DisasmEngineContext.TotalAnalyses = 0;
    g_DisasmEngineContext.SuccessfulAnalyses = 0;
    g_DisasmEngineContext.FailedAnalyses = 0;
    g_DisasmEngineContext.CacheHits = 0;

    DPRINT("����������ʼ���ɹ� [ģʽ: %s]\n", IsX64Mode ? "x64" : "x86");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ж�ط��������
 * ��������
 * ���أ���
 * ��ע���������������Դ
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

    // ��ӡͳ����Ϣ
    DPRINT("���������ͳ����Ϣ:\n");
    DPRINT("  �ܷ�������: %I64u\n", g_DisasmEngineContext.TotalAnalyses);
    DPRINT("  �ɹ���������: %I64u\n", g_DisasmEngineContext.SuccessfulAnalyses);
    DPRINT("  ʧ�ܷ�������: %I64u\n", g_DisasmEngineContext.FailedAnalyses);
    DPRINT("  �������д���: %I64u\n", g_DisasmEngineContext.CacheHits);

    // ����������
    RtlZeroMemory(&g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    DPRINT("���������ж�����\n");
}

/*****************************************************
 * ���ܣ�����൥��ָ��
 * ������pCode - ָ�����ָ��
 *       pInstruction - ���ָ����Ϣ
 *       IsX64 - �Ƿ�Ϊ64λģʽ
 * ���أ�ULONG - ָ��ȣ�0��ʾʧ��
 * ��ע������൥��x86/x64ָ��
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

        // ����ǰ׺
        while (offset < DISASM_MAX_INSTRUCTION_LENGTH)
        {
            UCHAR currentByte = pBytes[offset];

            // ����Ƿ�Ϊǰ׺
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

            // ���REXǰ׺����64λģʽ��
            if (IsX64 && (currentByte >= 0x40 && currentByte <= 0x4F))
            {
                pInstruction->Rex = currentByte;
                pInstruction->HasRex = TRUE;
                pInstruction->Flags |= DISASM_FLAG_REX;
                offset++;
                continue;
            }

            // ������
            pInstruction->OpcodeOffset = (UCHAR)offset;
            opcode = currentByte;
            pInstruction->Opcode = opcode;
            offset++;

            // ����Ƿ�Ϊ˫�ֽڲ�����
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

        // ����Ƿ���ҪModR/M�ֽ�
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

            // ����Ƿ���ҪSIB�ֽ�
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

            // ����λ�ƴ�С
            displacementSize = DeCalculateDisplacementSize(pInstruction);
            if (displacementSize > 0)
            {
                pInstruction->DisplacementOffset = (UCHAR)offset;
                pInstruction->DisplacementSize = (UCHAR)displacementSize;
                pInstruction->Flags |= DISASM_FLAG_DISPLACEMENT;
                offset += displacementSize;
            }
        }

        // ������������С
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

        // ����ָ���
        length = offset;
        pInstruction->Length = (UCHAR)length;

        // ����ԭʼ�ֽ�
        if (length <= sizeof(pInstruction->RawBytes))
        {
            RtlCopyMemory(pInstruction->RawBytes, pBytes, length);
        }

        // ȷ��ָ������
        pInstruction->Type = DeGetInstructionType(pInstruction);

        // ��������ת
        if (DeIsRelativeJump(pInstruction))
        {
            pInstruction->Flags |= DISASM_FLAG_RELATIVE;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("�����ָ��ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        pInstruction->Flags |= DISASM_FLAG_INVALID;
        return 0;
    }

    // ����ͳ��
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
 * ���ܣ����������������ֽ�
 * ������pFunction - ����ָ��
 *       pBuffer - ���������
 *       BufferSize - ��������С
 *       pCopiedSize - ������ƵĴ�С
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������������㹻���ֽ�����Hook
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

        // ���������������㹻���ֽ�����Hook
        while (totalLength < DISASM_MIN_HOOK_SIZE && totalLength < BufferSize)
        {
            instructionLength = DeDisassembleInstruction(
                pCode + totalLength,
                &instruction,
                g_DisasmEngineContext.IsX64Mode
            );

            if (instructionLength == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
            {
                DPRINT("��ƫ�� %u ��������Чָ��\n", totalLength);
                return STATUS_UNSUCCESSFUL;
            }

            // ����Ƿ�Ϊ��ָֹ��
            if (DeIsReturnInstruction(&instruction) ||
                (instruction.Opcode == 0xCC) || // INT3 (�ϵ�)
                (instruction.Opcode == 0xC3))   // RET
            {
                DPRINT("��ƫ�� %u ��������ָֹ��\n", totalLength);
                break;
            }

            totalLength += instructionLength;
        }

        // ȷ�����㹻�ĳ���
        if (totalLength < DISASM_MIN_HOOK_SIZE)
        {
            DPRINT("�������Ȳ��㣬�޷���ȫHook: %u < %u\n", totalLength, DISASM_MIN_HOOK_SIZE);
            return STATUS_BUFFER_TOO_SMALL;
        }

        // �����ֽ�
        if (totalLength > BufferSize)
        {
            totalLength = BufferSize;
        }

        RtlCopyMemory(pBuffer, pCode, totalLength);
        *pCopiedSize = totalLength;

        DPRINT("�����������: ������ %u �ֽ�\n", totalLength);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("��������ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����������ṹ
 * ������pFunction - ����ָ��
 *       MaxSize - ��������С
 *       pResult - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϸ���������Ľṹ������
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

    // ��ʼ���������
    RtlZeroMemory(pResult, sizeof(DISASM_ANALYSIS_RESULT));
    pResult->FunctionStart = pFunction;
    pResult->MinHookSize = DISASM_MIN_HOOK_SIZE;
    pResult->CanHook = TRUE;

    __try
    {
        pCode = (PUCHAR)pFunction;

        // ��������ָ��
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
                offset++; // ������Ч�ֽ�
                continue;
            }

            if (instruction.Flags & DISASM_FLAG_INVALID)
            {
                pResult->InvalidInstructions++;
                break;
            }

            pResult->TotalInstructions++;
            pResult->ValidInstructions++;

            // ����ָ��
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

                // �����ǰ�����ֽھ���������ָ����ܲ��ʺ�Hook
                if (offset < DISASM_MIN_HOOK_SIZE)
                {
                    pResult->CanHook = FALSE;
                }
                break; // ��������
            }

            // ��鸴��ָ��
            if (DeIsComplexInstruction(&instruction))
            {
                pResult->HasComplexInstructions = TRUE;
            }

            offset += instructionLength;
        }

        pResult->AnalyzedSize = offset;

        // �����Ƽ�Hook��С
        pResult->RecommendedHookSize = max(pResult->MinHookSize,
                                           DeCalculateRecommendedHookSize(pResult));

        // ����Hook�����Լ��
        if (pResult->AnalyzedSize < DISASM_MIN_HOOK_SIZE)
        {
            pResult->CanHook = FALSE;
        }

        DPRINT("�����������: ��С=%u, ָ��=%u, ��Hook=%s\n",
               pResult->AnalyzedSize, pResult->TotalInstructions,
               pResult->CanHook ? "��" : "��");

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("��ϸ��������ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����Hook�������С��С
 * ������pFunction - ����ָ��
 *       pMinSize - �����С��С
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����㰲ȫHook�������С�ֽ���
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

        // ����ָ��ֱ��������СHook��С
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

            // ���ָ��߽�������
            if (totalLength + instructionLength > DISASM_MIN_HOOK_SIZE)
            {
                // �����һ��ָ��ᳬ����С��С����Ҫ��������ָ��
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
 * ���ܣ���ָ֤��������
 * ������pCode - ָ�����ָ��
 *       Size - �����С
 * ���أ�BOOLEAN - TRUE������FALSE������
 * ��ע����ָ֤��߽��������
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

        // ȷ�����һ��ָ��ᳬ���߽�
        return (offset == Size);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ��תָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE����תָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ�������͵���ת
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

    // ������תָ�� (0x70-0x7F)
    if (opcode >= 0x70 && opcode <= 0x7F)
    {
        return TRUE;
    }

    // ��������ת
    if (opcode == 0xE9 || opcode == 0xEB || opcode == 0xEA)
    {
        return TRUE;
    }

    // �����ת
    if (opcode == 0xFF)
    {
        UCHAR modrmReg = (pInstruction->ModRm >> 3) & 7;
        return (modrmReg == 4 || modrmReg == 5); // JMP r/m64 �� JMP m16:64
    }

    // ˫�ֽڲ������������ת (0x0F 0x80-0x8F)
    if (pInstruction->OpcodeSize == 2 && pInstruction->Prefixes[0] == 0x0F)
    {
        return (opcode >= 0x80 && opcode <= 0x8F);
    }

    return FALSE;
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ����ָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�ǵ���ָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ��������
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

    // ֱ�ӵ���
    if (opcode == 0xE8)
    {
        return TRUE;
    }

    // Զ�̵���
    if (opcode == 0x9A)
    {
        return TRUE;
    }

    // ��ӵ���
    if (opcode == 0xFF)
    {
        UCHAR modrmReg = (pInstruction->ModRm >> 3) & 7;
        return (modrmReg == 2 || modrmReg == 3); // CALL r/m64 �� CALL m16:64
    }

    return FALSE;
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ����ָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�Ƿ���ָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ��������
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

    // ���ַ���ָ��
    return (opcode == 0xC3 ||  // RET near
            opcode == 0xC2 ||  // RET near imm16
            opcode == 0xCB ||  // RET far
            opcode == 0xCA);   // RET far imm16
}

/*****************************************************
 * ���ܣ���ȡָ���Ŀ���ַ
 * ������pInstruction - ָ����Ϣ
 *       InstructionAddress - ָ���ַ
 *       pTargetAddress - ���Ŀ���ַ
 * ���أ�BOOLEAN - TRUE�ɹ���FALSEʧ��
 * ��ע��������ת�����ָ���Ŀ���ַ
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

    // ֻ���������ת�͵���
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

        // ������������С����λ��
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

        // ����Ŀ���ַ = ָ���ַ + ָ��� + λ��
        *pTargetAddress = InstructionAddress + pInstruction->Length + displacement;

        return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*****************************************************
 * ���ܣ�����������С
 * ������pFunction - ����ָ��
 * ���أ�ULONG - ������С��0��ʾʧ��
 * ��ע��ͨ����������ȷ��������С
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
 * ���ܣ�������תĿ��
 * ������pFunction - ����ָ��
 * ���أ�PVOID - ��תĿ���ַ��NULL��ʾ������ת
 * ��ע�����������Ƿ�Ϊ����ת��������Ŀ��
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
        // ������һ��ָ��
        ULONG length = DeDisassembleInstruction(pFunction, &instruction, g_DisasmEngineContext.IsX64Mode);
        if (length == 0 || (instruction.Flags & DISASM_FLAG_INVALID))
        {
            return NULL;
        }

        // ����Ƿ�Ϊ��������ת
        if (!DeIsJumpInstruction(&instruction))
        {
            return NULL;
        }

        // ֻ����򵥵���������ת
        if (instruction.Opcode != 0xE9 && instruction.Opcode != 0xEB)
        {
            return NULL;
        }

        // ����Ŀ���ַ
        if (DeGetInstructionTarget(&instruction, (ULONG_PTR)pFunction, &targetAddress))
        {
            return (PVOID)targetAddress;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // �����쳣
    }

    return NULL;
}

/*****************************************************
 * ���ܣ���ȡ���������ͳ����Ϣ
 * ������pContext - �������������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ��������������ͳ��
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

    // ����ͳ����Ϣ
    RtlCopyMemory(pContext, &g_DisasmEngineContext, sizeof(DISASM_ENGINE_CONTEXT));

    return STATUS_SUCCESS;
}

// �ڲ���������ʵ��

/*****************************************************
 * ���ܣ�����Ƿ�Ϊǰ׺�ֽ�
 * ������Byte - �ֽ�ֵ
 * ���أ�BOOLEAN - TRUE��ǰ׺��FALSE����
 * ��ע�����x86/x64ǰ׺�ֽ�
*****************************************************/
BOOLEAN
DeIsPrefix(
    _In_ UCHAR Byte
)
{
    // x86/x64ǰ׺�ֽ�
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
 * ���ܣ����ָ���Ƿ���ҪModR/M�ֽ�
 * ������Opcode - ������
 * ���أ�BOOLEAN - TRUE��Ҫ��FALSE����Ҫ
 * ��ע�����ݲ������ж��Ƿ���ҪModR/M�ֽ�
*****************************************************/
BOOLEAN
DeNeedsModRm(
    _In_ UCHAR Opcode
)
{
    // ���Ǽ򻯵�ʵ�֣�ʵ����Ҫ�������Ĳ������
    // �󲿷ֲ����붼��ҪModR/M�ֽڣ������г�����Ҫ��
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
            // �󲿷�ָ���ҪModR/M
            return TRUE;
    }
}

/*****************************************************
 * ���ܣ�����λ�ƴ�С
 * ������pInstruction - ָ����Ϣ
 * ���أ�ULONG - λ�ƴ�С
 * ��ע������ModR/M�ֽڼ���λ�ƴ�С
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
 * ���ܣ�������������С
 * ������pInstruction - ָ����Ϣ
 * ���أ�ULONG - ��������С
 * ��ע�����ݲ����������������С
*****************************************************/
ULONG
DeCalculateImmediateSize(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    UCHAR opcode = pInstruction->Opcode;

    // ���Ǽ򻯵�ʵ�֣�ʵ����Ҫ�������Ĳ��������
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

            // ������ת rel8
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            return 1;

        default:
            // ��Ҫ���ݾ���ָ���һ������
            return 0;
    }
}

/*****************************************************
 * ���ܣ���ȡָ������
 * ������pInstruction - ָ����Ϣ
 * ���أ�UCHAR - ָ������
 * ��ע�����ݲ�����ȷ��ָ������
*****************************************************/
UCHAR
DeGetInstructionType(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    UCHAR opcode = pInstruction->Opcode;

    // ����ת��ָ��
    if (DeIsJumpInstruction(pInstruction) || DeIsCallInstruction(pInstruction) ||
        DeIsReturnInstruction(pInstruction))
    {
        return DISASM_TYPE_CONTROL_TRANSFER;
    }

    // ��������ָ��
    if ((opcode >= 0x00 && opcode <= 0x05) || // ADD
        (opcode >= 0x28 && opcode <= 0x2D) || // SUB
        (opcode >= 0x38 && opcode <= 0x3D))   // CMP
    {
        return DISASM_TYPE_ARITHMETIC;
    }

    // ���ݴ���ָ��
    if ((opcode >= 0x88 && opcode <= 0x8B) || // MOV
        (opcode >= 0xB0 && opcode <= 0xBF))   // MOV immediate
    {
        return DISASM_TYPE_DATA_TRANSFER;
    }

    // Ĭ��Ϊδ֪����
    return DISASM_TYPE_UNKNOWN;
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ�����ת
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�������ת��FALSE����
 * ��ע�������תָ���Ƿ�ʹ����Ե�ַ
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

    // �����תָ��
    return (opcode == 0xE8 || // CALL rel32
            opcode == 0xE9 || // JMP rel32
            opcode == 0xEB || // JMP rel8
            (opcode >= 0x70 && opcode <= 0x7F) || // ������ת rel8
            (pInstruction->OpcodeSize == 2 && pInstruction->Prefixes[0] == 0x0F &&
            opcode >= 0x80 && opcode <= 0x8F)); // ������ת rel32
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ����ָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�Ǹ���ָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ���ӵĶ��ֽ�ָ��
*****************************************************/
BOOLEAN
DeIsComplexInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
)
{
    // ��ǰ׺ָ��
    if (pInstruction->PrefixCount > 2)
    {
        return TRUE;
    }

    // ��ָ��
    if (pInstruction->Length > 7)
    {
        return TRUE;
    }

    // ˫�ֽڲ�����
    if (pInstruction->OpcodeSize > 1)
    {
        return TRUE;
    }

    // ��SIB�ֽڵ�ָ��
    if (pInstruction->HasSib)
    {
        return TRUE;
    }

    return FALSE;
}

/*****************************************************
 * ���ܣ������Ƽ�Hook��С
 * ������pResult - �������
 * ���أ�ULONG - �Ƽ�Hook��С
 * ��ע�����ݷ�������������Hook��С
*****************************************************/
ULONG
DeCalculateRecommendedHookSize(
    _In_ PDISASM_ANALYSIS_RESULT pResult
)
{
    ULONG recommendedSize = DISASM_MIN_HOOK_SIZE;

    // ����������ת������Hook��С�Ա�������
    if (pResult->HasRelativeJumps)
    {
        recommendedSize += 8;
    }

    // ����и���ָ�����Hook��С
    if (pResult->HasComplexInstructions)
    {
        recommendedSize += 4;
    }

    // ȷ�������������Ĵ�С
    if (recommendedSize > pResult->AnalyzedSize)
    {
        recommendedSize = pResult->AnalyzedSize;
    }

    return recommendedSize;
}