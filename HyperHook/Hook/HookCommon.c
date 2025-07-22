/*****************************************************
 * 文件：HookCommon.c
 * 功能：Hook引擎通用功能实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供所有Hook类型共用的功能和工具函数
*****************************************************/

#include "HookCommon.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"
#include <bcrypt.h>

// 全局Hook ID计数器
static volatile LONG g_NextHookId = 1;

// 全局Hook冲突检测链表
static LIST_ENTRY g_GlobalHookList = { 0 };
static KSPIN_LOCK g_GlobalHookListLock = { 0 };
static BOOLEAN g_HookCommonInitialized = FALSE;

/*****************************************************
 * 功能：初始化Hook通用模块
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：初始化Hook通用功能的全局状态
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

    // 初始化全局Hook链表和锁
    InitializeListHead(&g_GlobalHookList);
    KeInitializeSpinLock(&g_GlobalHookListLock);

    g_HookCommonInitialized = TRUE;

    DPRINT("Hook通用模块初始化成功\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：清理Hook通用模块
 * 参数：无
 * 返回：无
 * 备注：清理Hook通用功能的全局资源
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

    // 清理全局Hook链表
    KeAcquireSpinLock(&g_GlobalHookListLock, &oldIrql);

    while (!IsListEmpty(&g_GlobalHookList))
    {
        pListEntry = RemoveHeadList(&g_GlobalHookList);
        pHookDescriptor = CONTAINING_RECORD(pListEntry, HOOK_DESCRIPTOR, ListEntry);

        if (pHookDescriptor != NULL)
        {
            // 这里只是从全局链表中移除，不释放内存
            // 内存由各自的Hook引擎负责释放
            cleanupCount++;
        }
    }

    KeReleaseSpinLock(&g_GlobalHookListLock, oldIrql);

    g_HookCommonInitialized = FALSE;

    DPRINT("Hook通用模块清理完成，移除了%u个Hook描述符\n", cleanupCount);
}

/*****************************************************
 * 功能：初始化Hook描述符
 * 参数：pHookDescriptor - Hook描述符
 *       Type - Hook类型
 *       Method - Hook方法
 * 返回：NTSTATUS - 状态码
 * 备注：初始化Hook描述符的基本信息
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
        // 清零描述符
        RtlZeroMemory(pHookDescriptor, sizeof(HOOK_DESCRIPTOR));

        // 设置基本信息
        pHookDescriptor->HookId = HookAllocateId();
        pHookDescriptor->Signature = HOOK_SIGNATURE;
        pHookDescriptor->Type = Type;
        pHookDescriptor->Method = Method;
        pHookDescriptor->State = HOOK_STATE_INITIALIZED;
        pHookDescriptor->Priority = HOOK_PRIORITY_NORMAL;
        pHookDescriptor->Flags = HookFlagNone;

        // 初始化时间
        KeQuerySystemTime(&pHookDescriptor->CreateTime);
        pHookDescriptor->EnableTime.QuadPart = 0;
        pHookDescriptor->LastModifyTime = pHookDescriptor->CreateTime;

        // 初始化统计信息
        RtlZeroMemory(&pHookDescriptor->Statistics, sizeof(HOOK_STATISTICS));
        pHookDescriptor->Statistics.FirstCallTime.QuadPart = 0;
        pHookDescriptor->Statistics.LastCallTime.QuadPart = 0;
        pHookDescriptor->Statistics.MinExecutionTime = MAXULONG64;

        // 初始化同步对象
        KeInitializeSpinLock(&pHookDescriptor->HookSpinLock);
        pHookDescriptor->ReferenceCount = 1;

        // 设置安全信息
        pHookDescriptor->SecurityFlags = 0;
        pHookDescriptor->CreatingProcess = PsGetCurrentProcess();

        // 计算完整性哈希
        status = HookCalculateHash(
            pHookDescriptor,
            FIELD_OFFSET(HOOK_DESCRIPTOR, IntegrityHash),
            pHookDescriptor->IntegrityHash
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("计算Hook描述符哈希失败: 0x%08X\n", status);
            // 非致命错误，继续执行
        }

        DPRINT("Hook描述符初始化成功 [ID: %u, 类型: %d, 方法: %d]\n",
               pHookDescriptor->HookId, Type, Method);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("初始化Hook描述符时发生异常: 0x%08X\n", GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * 功能：清理Hook描述符
 * 参数：pHookDescriptor - Hook描述符
 * 返回：无
 * 备注：清理Hook描述符并释放相关资源
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
        DPRINT("Hook描述符签名无效: 0x%08X\n", pHookDescriptor->Signature);
        return;
    }

    DPRINT("清理Hook描述符 [ID: %u]\n", pHookDescriptor->HookId);

    // 设置状态为错误，防止继续使用
    pHookDescriptor->State = HOOK_STATE_ERROR;

    // 从全局链表中移除
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

    // 清零敏感数据
    RtlSecureZeroMemory(pHookDescriptor->OriginalBytes, sizeof(pHookDescriptor->OriginalBytes));
    RtlSecureZeroMemory(pHookDescriptor->PatchBytes, sizeof(pHookDescriptor->PatchBytes));
    RtlSecureZeroMemory(pHookDescriptor->IntegrityHash, sizeof(pHookDescriptor->IntegrityHash));
    RtlSecureZeroMemory(pHookDescriptor->UserData, sizeof(pHookDescriptor->UserData));

    // 清零基本信息
    pHookDescriptor->Signature = 0;
    pHookDescriptor->TargetFunction = NULL;
    pHookDescriptor->HookFunction = NULL;
    pHookDescriptor->OriginalFunction = NULL;
    pHookDescriptor->UserContext = NULL;
}

/*****************************************************
 * 功能：更新Hook统计信息
 * 参数：pHookDescriptor - Hook描riptor
 *       ExecutionTime - 执行时间
 *       IsSuccessful - 是否成功
 * 返回：无
 * 备注：更新Hook的统计信息
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

    // 更新调用统计
    InterlockedIncrement64(&pHookDescriptor->Statistics.TotalCalls);

    if (IsSuccessful)
    {
        InterlockedIncrement64(&pHookDescriptor->Statistics.SuccessfulCalls);
    }
    else
    {
        InterlockedIncrement64(&pHookDescriptor->Statistics.FailedCalls);
    }

    // 更新时间统计
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

        // 计算平均执行时间
        if (pHookDescriptor->Statistics.TotalCalls > 0)
        {
            pHookDescriptor->Statistics.AverageExecutionTime =
                pHookDescriptor->Statistics.TotalExecutionTime /
                pHookDescriptor->Statistics.TotalCalls;
        }
    }

    // 更新时间戳
    if (pHookDescriptor->Statistics.FirstCallTime.QuadPart == 0)
    {
        pHookDescriptor->Statistics.FirstCallTime = currentTime;
    }
    pHookDescriptor->Statistics.LastCallTime = currentTime;

    KeReleaseSpinLock(&pHookDescriptor->HookSpinLock, oldIrql);
}

/*****************************************************
 * 功能：验证Hook完整性
 * 参数：pHookDescriptor - Hook描述符
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：验证Hook数据的完整性
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

    // 检查签名
    if (pHookDescriptor->Signature != HOOK_SIGNATURE)
    {
        DPRINT("Hook描述符签名无效: 0x%08X\n", pHookDescriptor->Signature);
        return FALSE;
    }

    // 检查状态
    if (pHookDescriptor->State == HOOK_STATE_ERROR)
    {
        return FALSE;
    }

    // 计算当前哈希
    status = HookCalculateHash(
        pHookDescriptor,
        FIELD_OFFSET(HOOK_DESCRIPTOR, IntegrityHash),
        currentHash
    );

    if (!NT_SUCCESS(status))
    {
        DPRINT("计算Hook描述符哈希失败: 0x%08X\n", status);
        return FALSE;
    }

    // 比较哈希值
    if (RtlCompareMemory(pHookDescriptor->IntegrityHash, currentHash, sizeof(currentHash)) != sizeof(currentHash))
    {
        DPRINT("Hook描述符完整性验证失败 [ID: %u]\n", pHookDescriptor->HookId);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************
 * 功能：计算Hook哈希
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：计算数据的哈希值用于完整性检查
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
        // 尝试使用BCrypt计算SHA-256哈希
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
            // 使用简化的哈希算法作为备选
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
 * 功能：计算简化哈希
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：当BCrypt不可用时的备选哈希算法
*****************************************************/
NTSTATUS
HookCalculateSimpleHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    PUCHAR pBytes = (PUCHAR)pData;
    ULONG hash1 = 0x811C9DC5; // FNV-1a初始值
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
        // 使用多种哈希算法组合
        for (i = 0; i < Size; i++)
        {
            // FNV-1a
            hash1 ^= pBytes[i];
            hash1 *= 0x01000193;

            // 简单累加
            hash2 += pBytes[i];
            hash2 = (hash2 << 1) | (hash2 >> 31);

            // CRC风格
            hash3 = (hash3 >> 1) ^ ((hash3 & 1) ? 0xEDB88320 : 0) ^ pBytes[i];

            // 异或移位
            hash4 ^= pBytes[i];
            hash4 = (hash4 << 3) | (hash4 >> 29);
        }

        // 将哈希值写入输出缓冲区
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
 * 功能：分配Hook ID
 * 参数：无
 * 返回：ULONG - 新的Hook ID
 * 备注：分配唯一的Hook标识符
*****************************************************/
ULONG
HookAllocateId(
    VOID
)
{
    return (ULONG)InterlockedIncrement(&g_NextHookId);
}

/*****************************************************
 * 功能：检查Hook冲突
 * 参数：pTargetFunction - 目标函数
 *       Size - 检查大小
 * 返回：BOOLEAN - TRUE有冲突，FALSE无冲突
 * 备注：检查是否与现有Hook发生冲突
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

            // 检查地址范围是否重叠
            if (!(targetEnd <= hookStart || targetStart >= hookEnd))
            {
                DPRINT("检测到Hook冲突: 新Hook[%p-%p] 与现有Hook[ID:%u, %p-%p]重叠\n",
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
 * 功能：注册Hook描述符到全局链表
 * 参数：pHookDescriptor - Hook描述符
 * 返回：NTSTATUS - 状态码
 * 备注：将Hook描述符添加到全局链表以进行冲突检测
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

    DPRINT("Hook描述符注册成功 [ID: %u]\n", pHookDescriptor->HookId);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：从全局链表注销Hook描述符
 * 参数：pHookDescriptor - Hook描述符
 * 返回：NTSTATUS - 状态码
 * 备注：从全局链表中移除Hook描述符
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

    // 在链表中查找并移除
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
        DPRINT("Hook描述符注销成功 [ID: %u]\n", pHookDescriptor->HookId);
        return STATUS_SUCCESS;
    }
    else
    {
        DPRINT("Hook描述符注销失败，未找到指定描述符 [ID: %u]\n", pHookDescriptor->HookId);
        return STATUS_NOT_FOUND;
    }
}

/*****************************************************
 * 功能：增加Hook描述符引用计数
 * 参数：pHookDescriptor - Hook描述符
 * 返回：LONG - 新的引用计数
 * 备注：增加Hook描述符的引用计数
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
 * 功能：减少Hook描述符引用计数
 * 参数：pHookDescriptor - Hook描述符
 * 返回：LONG - 新的引用计数
 * 备注：减少Hook描述符的引用计数
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
        // 引用计数归零，可以安全清理
        DPRINT("Hook描述符引用计数归零，可以安全清理 [ID: %u]\n", pHookDescriptor->HookId);
    }

    return newCount;
}

/*****************************************************
 * 功能：设置Hook用户数据
 * 参数：pHookDescriptor - Hook描述符
 *       pUserData - 用户数据
 *       DataSize - 数据大小
 * 返回：NTSTATUS - 状态码
 * 备注：设置Hook描述符的用户自定义数据
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

    // 清零用户数据区域
    RtlZeroMemory(pHookDescriptor->UserData, sizeof(pHookDescriptor->UserData));

    if (pUserData != NULL && DataSize > 0)
    {
        RtlCopyMemory(pHookDescriptor->UserData, pUserData, DataSize);
    }

    pHookDescriptor->UserDataSize = DataSize;

    // 更新修改时间
    KeQuerySystemTime(&pHookDescriptor->LastModifyTime);

    KeReleaseSpinLock(&pHookDescriptor->HookSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取Hook用户数据
 * 参数：pHookDescriptor - Hook描述符
 *       pUserData - 输出用户数据缓冲区
 *       BufferSize - 缓冲区大小
 *       pDataSize - 输出实际数据大小
 * 返回：NTSTATUS - 状态码
 * 备注：获取Hook描述符的用户自定义数据
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
 * 功能：枚举所有Hook描述符
 * 参数：pHookArray - Hook描述符数组
 *       ArraySize - 数组大小
 *       pReturnedCount - 返回的Hook数量
 * 返回：NTSTATUS - 状态码
 * 备注：枚举当前所有的Hook描述符
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
 * 功能：查找Hook描述符
 * 参数：HookId - Hook ID
 * 返回：PHOOK_DESCRIPTOR - Hook描述符，未找到返回NULL
 * 备注：根据Hook ID查找Hook描述符
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