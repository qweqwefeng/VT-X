/*****************************************************
 * �ļ���DisassemblerEngine.h
 * ���ܣ����������ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ع���LDasm��������棬�ṩָ���������
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// ��������泣������
#define DISASM_MAX_INSTRUCTION_LENGTH   15          // x64���ָ���
#define DISASM_MAX_ANALYZE_LENGTH       128         // ����������
#define DISASM_MIN_HOOK_SIZE            5           // ��СHook��С

// ָ���־����
#define DISASM_FLAG_INVALID             0x01        // ��Чָ��
#define DISASM_FLAG_PREFIX              0x02        // ǰ׺
#define DISASM_FLAG_REX                 0x04        // REXǰ׺
#define DISASM_FLAG_MODRM               0x08        // ModR/M�ֽ�
#define DISASM_FLAG_SIB                 0x10        // SIB�ֽ�
#define DISASM_FLAG_DISPLACEMENT        0x20        // λ��
#define DISASM_FLAG_IMMEDIATE           0x40        // ������
#define DISASM_FLAG_RELATIVE            0x80        // �����ת

// ָ�����Ͷ���
#define DISASM_TYPE_UNKNOWN             0           // δָ֪��
#define DISASM_TYPE_DATA_TRANSFER       1           // ���ݴ���
#define DISASM_TYPE_ARITHMETIC          2           // ��������
#define DISASM_TYPE_LOGICAL             3           // �߼�����
#define DISASM_TYPE_CONTROL_TRANSFER    4           // ����ת��
#define DISASM_TYPE_STRING              5           // �ַ�������
#define DISASM_TYPE_SYSTEM              6           // ϵͳָ��
#define DISASM_TYPE_SSE                 7           // SSEָ��
#define DISASM_TYPE_AVX                 8           // AVXָ��

/*****************************************************
 * �ṹ��DISASM_INSTRUCTION
 * ���ܣ������ָ����Ϣ
 * ˵������������ָ�����ϸ��Ϣ
*****************************************************/
typedef struct _DISASM_INSTRUCTION
{
    // ������Ϣ
    UCHAR                   Flags;                  // ָ���־
    UCHAR                   Length;                 // ָ���
    UCHAR                   Type;                   // ָ������
    UCHAR                   Opcode;                 // ������

    // ǰ׺��Ϣ
    UCHAR                   PrefixCount;            // ǰ׺����
    UCHAR                   Prefixes[4];            // ǰ׺�ֽ�

    // REXǰ׺
    UCHAR                   Rex;                    // REXǰ׺
    BOOLEAN                 HasRex;                 // �Ƿ���REXǰ׺

    // ModR/M��SIB
    UCHAR                   ModRm;                  // ModR/M�ֽ�
    UCHAR                   Sib;                    // SIB�ֽ�
    BOOLEAN                 HasModRm;               // �Ƿ���ModR/M
    BOOLEAN                 HasSib;                 // �Ƿ���SIB

    // ƫ����Ϣ
    UCHAR                   OpcodeOffset;           // ������ƫ��
    UCHAR                   OpcodeSize;             // �������С
    UCHAR                   DisplacementOffset;     // λ��ƫ��
    UCHAR                   DisplacementSize;       // λ�ƴ�С
    UCHAR                   ImmediateOffset;        // ������ƫ��
    UCHAR                   ImmediateSize;          // ��������С

    // ԭʼ�ֽ�
    UCHAR                   RawBytes[DISASM_MAX_INSTRUCTION_LENGTH]; // ԭʼ�ֽ�

} DISASM_INSTRUCTION, * PDISASM_INSTRUCTION;

/*****************************************************
 * �ṹ��DISASM_ANALYSIS_RESULT
 * ���ܣ������������
 * ˵�����������������Ľ����Ϣ
*****************************************************/
typedef struct _DISASM_ANALYSIS_RESULT
{
    // ������Ϣ
    PVOID                   FunctionStart;          // ������ʼ��ַ
    ULONG                   AnalyzedSize;           // �ѷ�����С
    ULONG                   TotalInstructions;      // ��ָ����
    ULONG                   ValidInstructions;      // ��Чָ����

    // Hook��Ϣ
    ULONG                   MinHookSize;            // ��СHook��С
    ULONG                   RecommendedHookSize;    // �Ƽ�Hook��С
    BOOLEAN                 CanHook;                // �Ƿ����Hook

    // ָ��ͳ��
    ULONG                   JumpInstructions;       // ��תָ����
    ULONG                   CallInstructions;       // ����ָ����
    ULONG                   ReturnInstructions;     // ����ָ����
    ULONG                   InvalidInstructions;    // ��Чָ����

    // ����ָ��
    BOOLEAN                 HasRelativeJumps;       // �Ƿ��������ת
    BOOLEAN                 HasAbsoluteJumps;       // �Ƿ��о�����ת
    BOOLEAN                 HasCalls;               // �Ƿ��е���
    BOOLEAN                 HasComplexInstructions; // �Ƿ��и���ָ��

} DISASM_ANALYSIS_RESULT, * PDISASM_ANALYSIS_RESULT;

/*****************************************************
 * �ṹ��DISASM_ENGINE_CONTEXT
 * ���ܣ����������������
 * ˵����������������״̬������
*****************************************************/
typedef struct _DISASM_ENGINE_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsInitialized;          // �Ƿ��ѳ�ʼ��
    BOOLEAN                 IsX64Mode;              // �Ƿ�Ϊ64λģʽ

    // ����ѡ��
    BOOLEAN                 EnableDetailedAnalysis; // ������ϸ����
    BOOLEAN                 EnableCaching;          // ���û���
    BOOLEAN                 EnableValidation;       // ������֤
    ULONG                   MaxAnalyzeSize;         // ��������С

    // ͳ����Ϣ
    ULONG64                 TotalAnalyses;          // �ܷ�������
    ULONG64                 SuccessfulAnalyses;     // �ɹ���������
    ULONG64                 FailedAnalyses;         // ʧ�ܷ�������
    ULONG64                 CacheHits;              // �������д���

} DISASM_ENGINE_CONTEXT, * PDISASM_ENGINE_CONTEXT;

// ��������

/*****************************************************
 * ���ܣ���ʼ�����������
 * ������IsX64Mode - �Ƿ�Ϊ64λģʽ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ������������ȫ��״̬
*****************************************************/
NTSTATUS
DeInitializeEngine(
    _In_ BOOLEAN IsX64Mode
);

/*****************************************************
 * ���ܣ�ж�ط��������
 * ��������
 * ���أ���
 * ��ע���������������Դ
*****************************************************/
VOID
DeUninitializeEngine(
    VOID
);

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
);

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
);

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
);

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
);

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
);

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ��תָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE����תָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ�������͵���ת
*****************************************************/
BOOLEAN
DeIsJumpInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ����ָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�ǵ���ָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ��������
*****************************************************/
BOOLEAN
DeIsCallInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

/*****************************************************
 * ���ܣ�����Ƿ�Ϊ����ָ��
 * ������pInstruction - ָ����Ϣ
 * ���أ�BOOLEAN - TRUE�Ƿ���ָ�FALSE����
 * ��ע�����ָ���Ƿ�Ϊ��������
*****************************************************/
BOOLEAN
DeIsReturnInstruction(
    _In_ PDISASM_INSTRUCTION pInstruction
);

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
);

/*****************************************************
 * ���ܣ�����������С
 * ������pFunction - ����ָ��
 * ���أ�ULONG - ������С��0��ʾʧ��
 * ��ע��ͨ����������ȷ��������С
*****************************************************/
ULONG
DeGetFunctionSize(
    _In_ PVOID pFunction
);

/*****************************************************
 * ���ܣ�������תĿ��
 * ������pFunction - ����ָ��
 * ���أ�PVOID - ��תĿ���ַ��NULL��ʾ������ת
 * ��ע�����������Ƿ�Ϊ����ת��������Ŀ��
*****************************************************/
PVOID
DeResolveJumpTarget(
    _In_ PVOID pFunction
);

/*****************************************************
 * ���ܣ���ȡ���������ͳ����Ϣ
 * ������pContext - �������������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ��������������ͳ��
*****************************************************/
NTSTATUS
DeGetEngineStatistics(
    _Out_ PDISASM_ENGINE_CONTEXT pContext
);