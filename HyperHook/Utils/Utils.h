#pragma once
#include <ntifs.h>

/*****************************************************
 * 函数名：VirtualProtectNonpagedMemory
 * 功能：
 *     修改非分页内存区访问权限（如读、写、执行），用于驱动或虚拟化场景。
 * 参数：
 *     lpAddress    - 非分页内存首地址
 *     dwSize       - 需要修改权限的字节数
 *     flNewProtect - 新的内存保护属性（如 PAGE_READWRITE）
 * 返回：
 *     操作成功返回 STATUS_SUCCESS，否则返回 STATUS_UNSUCCESSFUL 或具体错误码
 * 备注：
 *     - 仅适用于 NonPagedPool 非分页内存
 *     - 内部通过 MDL 封装并调用 MmProtectMdlSystemAddress 完成保护属性修改
 *     - 不会阻塞，修改权限后立即释放 MDL
*****************************************************/
NTSTATUS VirtualProtectNonpagedMemory(_In_ PVOID lpAddress,
									  _In_ SIZE_T dwSize,
									  _In_ ULONG flNewProtect);

/// <summary>
/// Get ntoskrnl base address
/// </summary>
/// <param name="pSize">Size of module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID UtilKernelBase(OUT PULONG pSize);

/// <summary>
/// Gets SSDT base - KiSystemServiceTable
/// </summary>
/// <returns>SSDT base, NULL if not found</returns>
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* UtilSSDTBase();

/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID UtilSSDTEntry(IN ULONG index);

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS UtilSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

/// <summary>
/// Find pattern in kernel PE section
/// </summary>
/// <param name="section">Section name</param>
/// <param name="pattern">Pattern data</param>
/// <param name="wildcard">Pattern wildcard symbol</param>
/// <param name="len">Pattern length</param>
/// <param name="ppFound">Found address</param>
/// <returns>Status code</returns>
NTSTATUS UtilScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);