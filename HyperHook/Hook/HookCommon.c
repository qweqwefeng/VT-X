/*****************************************************
 * �ļ���HookCommon.c
 * ���ܣ�Hook����ͨ�ù���ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩ����Hook���͹��õĹ��ܺ͹��ߺ���
*****************************************************/

#include "HookCommon.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"
#include <bcrypt.h>

// ȫ��Hook ID������
static volatile LONG g_NextHookId = 1;

// ȫ��Hook��ͻ�������
static LIST_ENTRY g_GlobalHookList = { 0 };
static KSPIN_LOCK g_GlobalHookListLock = { 0 };
static BOOLEAN g_HookCommonInitialized = FALSE;

/*****************************************************
 * ���ܣ���ʼ��Hookͨ��ģ��
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��Hookͨ�ù��ܵ�ȫ��״̬
*****************************************************/
NTSTATUS
HookInitializeCommon(
    VOID
)
{
    if (g_HookCommonInitialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    // ��ʼ��ȫ��Hook�������
    InitializeListHead(&g_GlobalHookList);
    KeInitializeSpinLock(&g_GlobalHookListLock);

    g_HookCommonInitialized = TRUE;

    DPRINT("Hookͨ��ģ���ʼ���ɹ�\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����Hookͨ��ģ��
 * ��������
 * ���أ���
 * ��ע������Hookͨ�ù��ܵ�ȫ����Դ
*****************************************************/
VOID
HookCleanupCommon(
    VOID
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PHOOK_DESCRIPTOR pHookDescriptor = NULL;
    ULONG cleanupCount = 0;

    if (!g_HookCommonInitialized)
    {
        return;
    }

    // ����ȫ��Hook����
    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    while (!IsListEmpty(&g_GlobalHookList))
    {
        pListEntry = RemoveHeadList(&g_GlobalHookList);
        pHookDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pHookDescriptor != NULL)
        {
            // ����ֻ�Ǵ�ȫ���������Ƴ������ͷ��ڴ�
            // �ڴ��ɸ��Ե�Hook���渺���ͷ�
            cleanupCount++;
        }
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    g_HookCommonInitialized = FALSE;

    DPRINT("Hookͨ��ģ��������ɣ��Ƴ���%u��Hook������\n", cleanupCount);
}

/*****************************************************
 * ���ܣ���ʼ��Hook������
 * ������pHookDescriptor - Hook������
 *       Type - Hook����
 *       Method - Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��Hook�������Ļ�����Ϣ
*****************************************************/
NTSTATUS
HookInitializeDescriptor(
    _Out_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ HOOK_TYPE Type,
    _In_ HOOK_METHOD Method
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pHookDescriptor == NULL || Type >= HookTypeMax || Method >= HookMethodMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ����������
        RtlZeroMemory(pHookDescriptor, sizeof(HOOK_DESCRIPTOR));

        // ���û�����Ϣ
        pHookDescriptor->HookId = HookAllocateId();
        pHookDescriptor->Signature = HOOK_SIGNATURE;
        pHookDescriptor->Type = Type;
        pHookDescriptor->Method = Method;
        pHookDescriptor->State = HOOK_STATE_INITIALIZED;
        pHookDescriptor->Priority = HOOK_PRIORITY_NORMAL;
        pHookDescriptor->Flags = HookFlagNone;

        // ��ʼ��ʱ��
        KeQuerySystemTime(&pHookDescriptor->CreateTime);
        pHookDescriptor->EnableTime.QuadPart = 0;
        pHookDescriptor->LastModifyTime = pHookDescriptor->CreateTime;

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pHookDescriptor->Statistics, sizeof(HOOK_STATISTICS));
        pHookDescriptor->Statistics.FirstCallTime.QuadPart = 0;
        pHookDescriptor->Statistics.LastCallTime.QuadPart = 0;
        pHookDescriptor->Statistics.MinExecutionTime = MAXULONG64;

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pHookDescriptor->HookSpinLock);
        pHookDescriptor->ReferenceCount = 1;

        // ���ð�ȫ��Ϣ
        pHookDescriptor->SecurityFlags = 0;
        pHookDescriptor->CreatingProcess = PsGetCurrentProcess();

        // ���������Թ�ϣ
        status = HookCalculateHash(
            pHookDescriptor,
            FIELD_OFFSET(HOOK_DESCRIPTOR, IntegrityHash),
            pHookDescriptor->IntegrityHash
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����Hook��������ϣʧ��: 0x%08X\n", status);
            // ���������󣬼���ִ��
        }

        DPRINT("Hook��������ʼ���ɹ� [ID: %u, ����: %d, ����: %d]\n",
               pHookDescriptor->HookId, Type, Method);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("��ʼ��Hook������ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * ���ܣ�����Hook������
 * ������pHookDescriptor - Hook������
 * ���أ���
 * ��ע������Hook���������ͷ������Դ
*****************************************************/
VOID
HookCleanupDescriptor(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    KIRQL oldIrql;

    if (pHookDescriptor == NULL)
    {
        return;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        DPRINT("Hook������ǩ����Ч: 0x%08X\n", pHookDescriptor->Signature);
        return;
    }

    DPRINT("����Hook������ [ID: %u]\n", pHookDescriptor->HookId);

    // ����״̬Ϊ���󣬷�ֹ����ʹ��
    pHookDescriptor->State = HOOK_STATE_ERROR;

    // ��ȫ���������Ƴ�
    if (g_HookCommonInitialized)
    {
        KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

        if (pHookDescriptor->ListEntry.Flink != NULL &&
            pHookDescriptor->ListEntry.Blink != NULL)
        {
            RemoveEntryList(&pHookDescriptor->ListEntry);
        }

        KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);
    }

    // ������������
    RtlSecureZeroMemory(pHookDescriptor->OriginalBytes, sizeof(pHookDescriptor->OriginalBytes));
    RtlSecureZeroMemory(pHookDescriptor->PatchBytes, sizeof(pHookDescriptor->PatchBytes));
    RtlSecureZeroMemory(pHookDescriptor->IntegrityHash, sizeof(pHookDescriptor->IntegrityHash));
    RtlSecureZeroMemory(pHookDescriptor->UserData, sizeof(pHookDescriptor->UserData));

    // ���������Ϣ
    pHookDescriptor->Signature = 0;
    pHookDescriptor->TargetFunction = NULL;
    pHookDescriptor->HookFunction = NULL;
    pHookDescriptor->OriginalFunction = NULL;
    pHookDescriptor->UserContext = NULL;
}

/*****************************************************
 * ���ܣ�����Hookͳ����Ϣ
 * ������pHookDescriptor - Hook��riptor
 *       ExecutionTime - ִ��ʱ��
 *       IsSuccessful - �Ƿ�ɹ�
 * ���أ���
 * ��ע������Hook��ͳ����Ϣ
*****************************************************/
VOID
HookUpdateStatistics(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
)
{
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;

    if (pHookDescriptor == NULL)
    {
        return;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return;
    }

    KeQuerySystemTime(&currentTime);

    KeAcquireSpinLock(&pHookDescriptor->HookSpinLock, &oldIrql);

    // ���µ���ͳ��
    InterlockedIncrement64(&pHookDescriptor->Statistics.TotalCalls);

    if (IsSuccessful)
    {
        InterlockedIncrement64(&pHookDescriptor->Statistics.SuccessfulCalls);
    }
    else
    {
        InterlockedIncrement64(&pHookDescriptor->Statistics.FailedCalls);
    }

    // ����ʱ��ͳ��
    if (ExecutionTime > 0)
    {
        pHookDescriptor->Statistics.TotalExecutionTime += ExecutionTime;

        if (ExecutionTime > pHookDescriptor->Statistics.MaxExecutionTime)
        {
            pHookDescriptor->Statistics.MaxExecutionTime = ExecutionTime;
        }

        if (ExecutionTime < pHookDescriptor->Statistics.MinExecutionTime)
        {
            pHookDescriptor->Statistics.MinExecutionTime = ExecutionTime;
        }

        // ����ƽ��ִ��ʱ��
        if (pHookDescriptor->Statistics.TotalCalls > 0)
        {
            pHookDescriptor->Statistics.AverageExecutionTime =
                pHookDescriptor->Statistics.TotalExecutionTime /
                pHookDescriptor->Statistics.TotalCalls;
        }
    }

    // ����ʱ���
    if (pHookDescriptor->Statistics.FirstCallTime.QuadPart == 0)
    {
        pHookDescriptor->Statistics.FirstCallTime = currentTime;
    }
    pHookDescriptor->Statistics.LastCallTime = currentTime;

    KeReleaseSpinLock(&pHookDescriptor->HookSpinLock, oldIrql);
}

/*****************************************************
 * ���ܣ���֤Hook������
 * ������pHookDescriptor - Hook������
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע����֤Hook���ݵ�������
*****************************************************/
BOOLEAN
HookVerifyIntegrity(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    UCHAR currentHash[32] = { 0 };
    NTSTATUS status;

    if (pHookDescriptor == NULL)
    {
        return FALSE;
    }

    // ���ǩ��
    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        DPRINT("Hook������ǩ����Ч: 0x%08X\n", pHookDescriptor->Signature);
        return FALSE;
    }

    // ���״̬
    if (pHookDescriptor->State == HOOK_STATE_ERROR)
    {
        return FALSE;
    }

    // ���㵱ǰ��ϣ
    status = HookCalculateHash(
        pHookDescriptor,
        FIELD_OFFSET(HOOK_DESCRIPTOR, IntegrityHash),
        currentHash
    );

    if (!NT_SUCCESS(status))
    {
        DPRINT("����Hook��������ϣʧ��: 0x%08X\n", status);
        return FALSE;
    }

    // �ȽϹ�ϣֵ
    if (RtlCompareMemory(pHookDescriptor->IntegrityHash, currentHash, sizeof(currentHash)) != sizeof(currentHash))
    {
        DPRINT("Hook��������������֤ʧ�� [ID: %u]\n", pHookDescriptor->HookId);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************
 * ���ܣ�����Hook��ϣ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������ݵĹ�ϣֵ���������Լ��
*****************************************************/
NTSTATUS
HookCalculateHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ����ʹ��BCrypt����SHA-256��ϣ
        status = BCryptOpenAlgorithmProvider(
            &hAlgorithm,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0
        );

        if (NT_SUCCESS(status))
        {
            status = BCryptCreateHash(
                hAlgorithm,
                &hHash,
                NULL,
                0,
                NULL,
                0,
                0
            );

            if (NT_SUCCESS(status))
            {
                status = BCryptHashData(hHash, (PUCHAR)pData, Size, 0);
                if (NT_SUCCESS(status))
                {
                    status = BCryptFinishHash(hHash, pHash, 32, 0);
                }
            }
        }

        if (!NT_SUCCESS(status))
        {
            // ʹ�ü򻯵Ĺ�ϣ�㷨��Ϊ��ѡ
            status = HookCalculateSimpleHash(pData, Size, pHash);
        }

    }
    __finally
    {
        if (hHash != NULL)
        {
            BCryptDestroyHash(hHash);
        }

        if (hAlgorithm != NULL)
        {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�����򻯹�ϣ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����BCrypt������ʱ�ı�ѡ��ϣ�㷨
*****************************************************/
NTSTATUS
HookCalculateSimpleHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    PUCHAR pBytes = (PUCHAR)pData;
    ULONG hash1 = 0x811C9DC5; // FNV-1a��ʼֵ
    ULONG hash2 = 0;
    ULONG hash3 = 0;
    ULONG hash4 = 0;
    ULONG i;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ʹ�ö��ֹ�ϣ�㷨���
        for (i = 0; i < Size; i++)
        {
            // FNV-1a
            hash1 ^= pBytes[i];
            hash1 *= 0x01000193;

            // ���ۼ�
            hash2 += pBytes[i];
            hash2 = (hash2 << 1) | (hash2 >> 31);

            // CRC���
            hash3 = (hash3 >> 1) ^ ((hash3 & 1) ? 0xEDB88320 : 0) ^ pBytes[i];

            // �����λ
            hash4 ^= pBytes[i];
            hash4 = (hash4 << 3) | (hash4 >> 29);
        }

        // ����ϣֵд�����������
        *(PULONG)(pHash + 0) = hash1;
        *(PULONG)(pHash + 4) = hash2;
        *(PULONG)(pHash + 8) = hash3;
        *(PULONG)(pHash + 12) = hash4;
        *(PULONG)(pHash + 16) = hash1 ^ hash2;
        *(PULONG)(pHash + 20) = hash3 ^ hash4;
        *(PULONG)(pHash + 24) = Size;
        *(PULONG)(pHash + 28) = hash1 ^ hash3;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����Hook ID
 * ��������
 * ���أ�ULONG - �µ�Hook ID
 * ��ע������Ψһ��Hook��ʶ��
*****************************************************/
ULONG
HookAllocateId(
    VOID
)
{
    return (ULONG)InterlockedIncrement(&g_NextHookId);
}

/*****************************************************
 * ���ܣ����Hook��ͻ
 * ������pTargetFunction - Ŀ�꺯��
 *       Size - ����С
 * ���أ�BOOLEAN - TRUE�г�ͻ��FALSE�޳�ͻ
 * ��ע������Ƿ�������Hook������ͻ
*****************************************************/
BOOLEAN
HookCheckConflict(
    _In_ PVOID pTargetFunction,
    _In_ ULONG Size
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PHOOK_DESCRIPTOR pHookDescriptor = NULL;
    ULONG_PTR targetStart, targetEnd;
    ULONG_PTR hookStart, hookEnd;
    BOOLEAN hasConflict = FALSE;

    if (pTargetFunction == NULL || Size == 0)
    {
        return FALSE;
    }

    if (!g_HookCommonInitialized)
    {
        return FALSE;
    }

    targetStart = (ULONG_PTR)pTargetFunction;
    targetEnd = targetStart + Size;

    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    pListEntry = g_GlobalHookList.Flink;
    while (pListEntry != &g_GlobalHookList)
    {
        pHookDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pHookDescriptor->TargetFunction != NULL && pHookDescriptor->TargetSize > 0)
        {
            hookStart = (ULONG_PTR)pHookDescriptor->TargetFunction;
            hookEnd = hookStart + pHookDescriptor->TargetSize;

            // ����ַ��Χ�Ƿ��ص�
            if (!(targetEnd <= hookStart || targetStart >= hookEnd))
            {
                DPRINT("��⵽Hook��ͻ: ��Hook[%p-%p] ������Hook[ID:%u, %p-%p]�ص�\n",
                       (PVOID)targetStart, (PVOID)targetEnd,
                       pHookDescriptor->HookId, (PVOID)hookStart, (PVOID)hookEnd);
                hasConflict = TRUE;
                break;
            }
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    return hasConflict;
}

/*****************************************************
 * ���ܣ�ע��Hook��������ȫ������
 * ������pHookDescriptor - Hook������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����Hook��������ӵ�ȫ�������Խ��г�ͻ���
*****************************************************/
NTSTATUS
HookRegisterDescriptor(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    KIRQL oldIrql;

    if (pHookDescriptor == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_HookCommonInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);
    InsertTailList(&g_GlobalHookList, &pHookDescriptor->ListEntry);
    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    DPRINT("Hook������ע��ɹ� [ID: %u]\n", pHookDescriptor->HookId);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȫ������ע��Hook������
 * ������pHookDescriptor - Hook������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȫ���������Ƴ�Hook������
*****************************************************/
NTSTATUS
HookUnregisterDescriptor(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    PLIST_ENTRY pListEntry = NULL;
    PHOOK_DESCRIPTOR pCurrentDescriptor = NULL;

    if (pHookDescriptor == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_HookCommonInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    // �������в��Ҳ��Ƴ�
    pListEntry = g_GlobalHookList.Flink;
    while (pListEntry != &g_GlobalHookList)
    {
        pCurrentDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pCurrentDescriptor == pHookDescriptor)
        {
            RemoveEntryList(&pCurrentDescriptor->ListEntry);
            found = TRUE;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    if (found)
    {
        DPRINT("Hook������ע���ɹ� [ID: %u]\n", pHookDescriptor->HookId);
        return STATUS_SUCCESS;
    }
    else
    {
        DPRINT("Hook������ע��ʧ�ܣ�δ�ҵ�ָ�������� [ID: %u]\n", pHookDescriptor->HookId);
        return STATUS_NOT_FOUND;
    }
}

/*****************************************************
 * ���ܣ�����Hook���������ü���
 * ������pHookDescriptor - Hook������
 * ���أ�LONG - �µ����ü���
 * ��ע������Hook�����������ü���
*****************************************************/
LONG
HookAddReference(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    if (pHookDescriptor == NULL)
    {
        return 0;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return 0;
    }

    return InterlockedIncrement(&pHookDescriptor->ReferenceCount);
}

/*****************************************************
 * ���ܣ�����Hook���������ü���
 * ������pHookDescriptor - Hook������
 * ���أ�LONG - �µ����ü���
 * ��ע������Hook�����������ü���
*****************************************************/
LONG
HookRemoveReference(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
)
{
    LONG newCount;

    if (pHookDescriptor == NULL)
    {
        return 0;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return 0;
    }

    newCount = InterlockedDecrement(&pHookDescriptor->ReferenceCount);

    if (newCount == 0)
    {
        // ���ü������㣬���԰�ȫ����
        DPRINT("Hook���������ü������㣬���԰�ȫ���� [ID: %u]\n", pHookDescriptor->HookId);
    }

    return newCount;
}

/*****************************************************
 * ���ܣ�����Hook�û�����
 * ������pHookDescriptor - Hook������
 *       pUserData - �û�����
 *       DataSize - ���ݴ�С
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Hook���������û��Զ�������
*****************************************************/
NTSTATUS
HookSetUserData(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_opt_ PVOID pUserData,
    _In_ ULONG DataSize
)
{
    KIRQL oldIrql;

    if (pHookDescriptor == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize > sizeof(pHookDescriptor->UserData))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&pHookDescriptor->HookSpinLock, &oldIrql);

    // �����û���������
    RtlZeroMemory(pHookDescriptor->UserData, sizeof(pHookDescriptor->UserData));

    if (pUserData != NULL && DataSize > 0)
    {
        RtlCopyMemory(pHookDescriptor->UserData, pUserData, DataSize);
    }

    pHookDescriptor->UserDataSize = DataSize;

    // �����޸�ʱ��
    KeQuerySystemTime(&pHookDescriptor->LastModifyTime);

    KeReleaseSpinLock(&pHookDescriptor->HookSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡHook�û�����
 * ������pHookDescriptor - Hook������
 *       pUserData - ����û����ݻ�����
 *       BufferSize - ��������С
 *       pDataSize - ���ʵ�����ݴ�С
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡHook���������û��Զ�������
*****************************************************/
NTSTATUS
HookGetUserData(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _Out_opt_ PVOID pUserData,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG pDataSize
)
{
    KIRQL oldIrql;
    ULONG copySize;

    if (pHookDescriptor == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&pHookDescriptor->HookSpinLock, &oldIrql);

    if (pDataSize != NULL)
    {
        *pDataSize = pHookDescriptor->UserDataSize;
    }

    if (pUserData != NULL && BufferSize > 0)
    {
        copySize = min(BufferSize, pHookDescriptor->UserDataSize);
        if (copySize > 0)
        {
            RtlCopyMemory(pUserData, pHookDescriptor->UserData, copySize);
        }
    }

    KeReleaseSpinLock(&pHookDescriptor->HookSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ö������Hook������
 * ������pHookArray - Hook����������
 *       ArraySize - �����С
 *       pReturnedCount - ���ص�Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ö�ٵ�ǰ���е�Hook������
*****************************************************/
NTSTATUS
HookEnumerateDescriptors(
    _Out_ PHOOK_DESCRIPTOR* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PHOOK_DESCRIPTOR pHookDescriptor = NULL;
    ULONG count = 0;

    if (pHookArray == NULL || pReturnedCount == NULL || ArraySize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_HookCommonInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    *pReturnedCount = 0;

    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    pListEntry = g_GlobalHookList.Flink;
    while (pListEntry != &g_GlobalHookList && count < ArraySize)
    {
        pHookDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pHookDescriptor->Signature == HOOK_SIGNATURE)
        {
            pHookArray[count] = pHookDescriptor;
            count++;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    *pReturnedCount = count;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����Hook������
 * ������HookId - Hook ID
 * ���أ�PHOOK_DESCRIPTOR - Hook��������δ�ҵ�����NULL
 * ��ע������Hook ID����Hook������
*****************************************************/
PHOOK_DESCRIPTOR
HookFindDescriptorById(
    _In_ ULONG HookId
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PHOOK_DESCRIPTOR pHookDescriptor = NULL;
    PHOOK_DESCRIPTOR pFoundDescriptor = NULL;

    if (HookId == 0)
    {
        return NULL;
    }

    if (!g_HookCommonInitialized)
    {
        return NULL;
    }

    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    pListEntry = g_GlobalHookList.Flink;
    while (pListEntry != &g_GlobalHookList)
    {
        pHookDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pHookDescriptor->Signature == HOOK_SIGNATURE &&
            pHookDescriptor->HookId == HookId)
        {
            pFoundDescriptor = pHookDescriptor;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    return pFoundDescriptor;
}