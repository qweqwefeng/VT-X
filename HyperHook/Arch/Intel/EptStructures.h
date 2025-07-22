/*****************************************************
 * �ļ���EptStructures.h
 * ���ܣ�Intel EPT(��չҳ��)������ݽṹ����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������EPT���⻯�ڴ������ص��������ݽṹ�ͳ���
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// EPT������������
#define EPT_PML4_ENTRY_COUNT            512         // PML4��Ŀ����
#define EPT_PDPT_ENTRY_COUNT            512         // PDPT��Ŀ����
#define EPT_PD_ENTRY_COUNT              512         // PD��Ŀ����
#define EPT_PT_ENTRY_COUNT              512         // PT��Ŀ����
#define EPT_PAGE_SIZE                   4096        // ҳ���С
#define EPT_LARGE_PAGE_SIZE             0x200000    // ��ҳ���С(2MB)
#define EPT_HUGE_PAGE_SIZE              0x40000000  // ��ҳ���С(1GB)

// EPTȨ�޶���
#define EPT_ACCESS_NONE                 0           // �޷���Ȩ��
#define EPT_ACCESS_READ                 1           // ��Ȩ��
#define EPT_ACCESS_WRITE                2           // дȨ��
#define EPT_ACCESS_EXEC                 4           // ִ��Ȩ��
#define EPT_ACCESS_RW                   (EPT_ACCESS_READ | EPT_ACCESS_WRITE)
#define EPT_ACCESS_RX                   (EPT_ACCESS_READ | EPT_ACCESS_EXEC)
#define EPT_ACCESS_WX                   (EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)
#define EPT_ACCESS_ALL                  (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)

// EPT�ڴ����Ͷ���
#define EPT_MEMORY_TYPE_UNCACHEABLE     0           // ���ɻ���
#define EPT_MEMORY_TYPE_WRITE_COMBINING 1           // д�ϲ�
#define EPT_MEMORY_TYPE_WRITE_THROUGH   4           // дͨ
#define EPT_MEMORY_TYPE_WRITE_PROTECTED 5           // д����
#define EPT_MEMORY_TYPE_WRITE_BACK      6           // д��
#define EPT_MEMORY_TYPE_UNCACHED        7           // ������

// EPTΥ�����Ͷ���
#define EPT_VIOLATION_READ              0x01        // ��ȡΥ��
#define EPT_VIOLATION_WRITE             0x02        // д��Υ��
#define EPT_VIOLATION_EXECUTE           0x04        // ִ��Υ��
#define EPT_VIOLATION_READABLE          0x08        // ҳ��ɶ�
#define EPT_VIOLATION_WRITABLE          0x10        // ҳ���д
#define EPT_VIOLATION_EXECUTABLE        0x20        // ҳ���ִ��
#define EPT_VIOLATION_GLA_VALID         0x80        // �ͻ������Ե�ַ��Ч

/*****************************************************
 * ö�٣�EPT_ACCESS
 * ���ܣ�EPT����Ȩ��ö��
 * ˵��������EPTҳ����Ŀ�ķ���Ȩ������
*****************************************************/
typedef enum _EPT_ACCESS
{
    EptAccessNone = EPT_ACCESS_NONE,               // �޷���Ȩ��
    EptAccessRead = EPT_ACCESS_READ,               // ��Ȩ��
    EptAccessWrite = EPT_ACCESS_WRITE,             // дȨ��
    EptAccessExecute = EPT_ACCESS_EXEC,            // ִ��Ȩ��
    EptAccessReadWrite = EPT_ACCESS_RW,            // ��дȨ��
    EptAccessReadExecute = EPT_ACCESS_RX,          // ��ִ��Ȩ��
    EptAccessWriteExecute = EPT_ACCESS_WX,         // дִ��Ȩ��
    EptAccessAll = EPT_ACCESS_ALL                  // ȫ��Ȩ��
} EPT_ACCESS, * PEPT_ACCESS;

/*****************************************************
 * ö�٣�PAGE_HOOK_TYPE
 * ���ܣ�ҳ��Hook����ö��
 * ˵�������岻ͬ���͵�ҳ��Hook����
*****************************************************/
typedef enum _PAGE_HOOK_TYPE
{
    PageHookTypeExecute = 0,                       // ִ��Hook
    PageHookTypeRead = 1,                          // ��ȡHook
    PageHookTypeWrite = 2,                         // д��Hook
    PageHookTypeReadWrite = 3,                     // ��дHook
    PageHookTypeMax                                // ���ֵ���
} PAGE_HOOK_TYPE, * PPAGE_HOOK_TYPE;

/*****************************************************
 * ���ϣ�EPT_PML4_ENTRY
 * ���ܣ�EPT PML4����Ŀ�ṹ
 * ˵��������EPTҳӳ�伶��4����Ŀ��λ�ֶ�
*****************************************************/
typedef union _EPT_PML4_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // ��Ȩ��
        ULONG64 Write : 1;                         // дȨ��
        ULONG64 Execute : 1;                       // ִ��Ȩ��
        ULONG64 Reserved1 : 5;                     // ����λ
        ULONG64 Accessed : 1;                      // ����λ
        ULONG64 Ignored1 : 1;                      // ����λ
        ULONG64 ExecuteForUserMode : 1;            // �û�ģʽִ��Ȩ��
        ULONG64 Ignored2 : 1;                      // ����λ
        ULONG64 PhysicalAddress : 40;              // �����ַ(bits 51:12)
        ULONG64 Ignored3 : 12;                     // ����λ
    } Fields;
    ULONG64 All;
} EPT_PML4_ENTRY, * PEPT_PML4_ENTRY;

/*****************************************************
 * ���ϣ�EPT_PDPT_ENTRY
 * ���ܣ�EPT PDPT����Ŀ�ṹ
 * ˵��������EPTҳĿ¼ָ�����Ŀ��λ�ֶ�
*****************************************************/
typedef union _EPT_PDPT_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // ��Ȩ��
        ULONG64 Write : 1;                         // дȨ��
        ULONG64 Execute : 1;                       // ִ��Ȩ��
        ULONG64 MemoryType : 3;                    // �ڴ�����
        ULONG64 IgnorePat : 1;                     // ����PAT
        ULONG64 LargePage : 1;                     // ��ҳ���־
        ULONG64 Accessed : 1;                      // ����λ
        ULONG64 Dirty : 1;                         // ��λ
        ULONG64 ExecuteForUserMode : 1;            // �û�ģʽִ��Ȩ��
        ULONG64 Ignored1 : 1;                      // ����λ
        ULONG64 PhysicalAddress : 40;              // �����ַ(bits 51:12)
        ULONG64 Ignored2 : 12;                     // ����λ
    } Fields;
    ULONG64 All;
} EPT_PDPT_ENTRY, * PEPT_PDPT_ENTRY;

/*****************************************************
 * ���ϣ�EPT_PD_ENTRY
 * ���ܣ�EPT PD����Ŀ�ṹ
 * ˵��������EPTҳĿ¼����Ŀ��λ�ֶ�
*****************************************************/
typedef union _EPT_PD_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // ��Ȩ��
        ULONG64 Write : 1;                         // дȨ��
        ULONG64 Execute : 1;                       // ִ��Ȩ��
        ULONG64 MemoryType : 3;                    // �ڴ�����
        ULONG64 IgnorePat : 1;                     // ����PAT
        ULONG64 LargePage : 1;                     // ��ҳ���־(2MB)
        ULONG64 Accessed : 1;                      // ����λ
        ULONG64 Dirty : 1;                         // ��λ
        ULONG64 ExecuteForUserMode : 1;            // �û�ģʽִ��Ȩ��
        ULONG64 Ignored1 : 1;                      // ����λ
        ULONG64 PhysicalAddress : 40;              // �����ַ(bits 51:12)
        ULONG64 Ignored2 : 12;                     // ����λ
    } Fields;
    ULONG64 All;
} EPT_PD_ENTRY, * PEPT_PD_ENTRY;

/*****************************************************
 * ���ϣ�EPT_PT_ENTRY
 * ���ܣ�EPT PT����Ŀ�ṹ
 * ˵��������EPTҳ����Ŀ��λ�ֶ�
*****************************************************/
typedef union _EPT_PT_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // ��Ȩ��
        ULONG64 Write : 1;                         // дȨ��
        ULONG64 Execute : 1;                       // ִ��Ȩ��
        ULONG64 MemoryType : 3;                    // �ڴ�����
        ULONG64 IgnorePat : 1;                     // ����PAT
        ULONG64 Ignored1 : 1;                      // ����λ
        ULONG64 Accessed : 1;                      // ����λ
        ULONG64 Dirty : 1;                         // ��λ
        ULONG64 ExecuteForUserMode : 1;            // �û�ģʽִ��Ȩ��
        ULONG64 Ignored2 : 1;                      // ����λ
        ULONG64 PhysicalAddress : 40;              // �����ַ(bits 51:12)
        ULONG64 Ignored3 : 12;                     // ����λ
    } Fields;
    ULONG64 All;
} EPT_PT_ENTRY, * PEPT_PT_ENTRY;

/*****************************************************
 * ���ϣ�EPT_VIOLATION_QUALIFICATION
 * ���ܣ�EPTΥ���޶���Ϣ
 * ˵��������EPTΥ�����ϸ�޶���Ϣ
*****************************************************/
typedef union _EPT_VIOLATION_QUALIFICATION
{
    struct
    {
        ULONG64 ReadAccess : 1;                    // �Ƿ�������ʵ���
        ULONG64 WriteAccess : 1;                   // �Ƿ���д���ʵ���
        ULONG64 ExecuteAccess : 1;                 // �Ƿ���ִ�з��ʵ���
        ULONG64 EptReadable : 1;                   // EPT��Ŀ�Ƿ�ɶ�
        ULONG64 EptWritable : 1;                   // EPT��Ŀ�Ƿ��д
        ULONG64 EptExecutable : 1;                 // EPT��Ŀ�Ƿ��ִ��
        ULONG64 EptExecutableForUserMode : 1;      // EPT��Ŀ�û�ģʽ��ִ��
        ULONG64 ValidGuestLinearAddress : 1;       // �ͻ������Ե�ַ�Ƿ���Ч
        ULONG64 CausedByTranslation : 1;           // �Ƿ��ɵ�ַת������
        ULONG64 UserModeLinearAddress : 1;         // �Ƿ�Ϊ�û�ģʽ���Ե�ַ
        ULONG64 ReadableWritablePage : 1;          // ҳ���Ƿ�ɶ�д
        ULONG64 ExecuteDisablePage : 1;            // ҳ���Ƿ�ִ�н���
        ULONG64 NmiUnblocking : 1;                 // NMI�������
        ULONG64 Reserved1 : 51;                    // ����λ
    } Fields;
    ULONG64 All;
} EPT_VIOLATION_QUALIFICATION, * PEPT_VIOLATION_QUALIFICATION;

/*****************************************************
 * �ṹ��EPT_PML4_TABLE
 * ���ܣ�EPT PML4��ṹ
 * ˵��������512��PML4��Ŀ��������
*****************************************************/
typedef struct _EPT_PML4_TABLE
{
    EPT_PML4_ENTRY          Entry[EPT_PML4_ENTRY_COUNT];
} EPT_PML4_TABLE, * PEPT_PML4_TABLE;

/*****************************************************
 * �ṹ��EPT_PDPT_TABLE
 * ���ܣ�EPT PDPT��ṹ
 * ˵��������512��PDPT��Ŀ��������
*****************************************************/
typedef struct _EPT_PDPT_TABLE
{
    EPT_PDPT_ENTRY          Entry[EPT_PDPT_ENTRY_COUNT];
} EPT_PDPT_TABLE, * PEPT_PDPT_TABLE;

/*****************************************************
 * �ṹ��EPT_PD_TABLE
 * ���ܣ�EPT PD��ṹ
 * ˵��������512��PD��Ŀ��������
*****************************************************/
typedef struct _EPT_PD_TABLE
{
    EPT_PD_ENTRY            Entry[EPT_PD_ENTRY_COUNT];
} EPT_PD_TABLE, * PEPT_PD_TABLE;

/*****************************************************
 * �ṹ��EPT_PT_TABLE
 * ���ܣ�EPT PT��ṹ
 * ˵��������512��PT��Ŀ��������
*****************************************************/
typedef struct _EPT_PT_TABLE
{
    EPT_PT_ENTRY            Entry[EPT_PT_ENTRY_COUNT];
} EPT_PT_TABLE, * PEPT_PT_TABLE;

/*****************************************************
 * �ṹ��EPT_TABLE_CONTEXT
 * ���ܣ�EPT��������
 * ˵��������EPTҳ���������νṹ
*****************************************************/
typedef struct _EPT_TABLE_CONTEXT
{
    // ��ָ��
    PEPT_PML4_TABLE         Pml4Table;             // PML4��ָ��
    PHYSICAL_ADDRESS        Pml4TablePhysical;     // PML4�������ַ

    // Ԥ����ı��
    PEPT_PDPT_TABLE         PdptTables;            // PDPT���
    PEPT_PD_TABLE           PdTables;              // PD���
    PEPT_PT_TABLE           PtTables;              // PT���

    // �����ַ
    PHYSICAL_ADDRESS        PdptTablesPhysical;    // PDPT��������ַ
    PHYSICAL_ADDRESS        PdTablesPhysical;      // PD��������ַ
    PHYSICAL_ADDRESS        PtTablesPhysical;      // PT��������ַ

    // �����״̬
    PRTL_BITMAP             PdptAllocationMap;     // PDPT����λͼ
    PRTL_BITMAP             PdAllocationMap;       // PD����λͼ
    PRTL_BITMAP             PtAllocationMap;       // PT����λͼ

    // ͬ��
    KSPIN_LOCK              TableSpinLock;         // �����������

    // ͳ����Ϣ
    ULONG                   TotalTables;           // �ܱ�����
    ULONG                   AllocatedTables;       // �ѷ��������
    ULONG                   MaxTables;             // ��������

} EPT_TABLE_CONTEXT, * PEPT_TABLE_CONTEXT;

/*****************************************************
 * �ṹ��PAGE_HOOK_ENTRY
 * ���ܣ�ҳ��Hook��Ŀ
 * ˵������ʾ����ҳ��Hook����ϸ��Ϣ
*****************************************************/
typedef struct _PAGE_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // ������Ŀ

    // ������Ϣ
    ULONG                   HookId;                // HookΨһ��ʶ
    PAGE_HOOK_TYPE          HookType;              // Hook����
    BOOLEAN                 IsActive;              // �Ƿ��Ծ
    BOOLEAN                 IsTemporary;           // �Ƿ���ʱHook

    // ҳ����Ϣ
    PVOID                   OriginalFunction;      // ԭʼ������ַ
    PVOID                   HookFunction;          // Hook������ַ
    PVOID                   OriginalPageVa;        // ԭʼҳ�������ַ
    ULONG64                 OriginalPagePfn;       // ԭʼҳ��PFN
    PVOID                   HookPageVa;            // Hookҳ�������ַ
    ULONG64                 HookPagePfn;           // Hookҳ��PFN

    // ԭʼ����
    ULONG                   OriginalSize;          // ԭʼ���ݴ�С
    UCHAR                   OriginalBytes[128];    // ԭʼ�ֽ�����
    UCHAR                   ModifiedBytes[128];    // �޸ĺ��ֽ�����

    // EPTȨ��
    EPT_ACCESS              OriginalAccess;        // ԭʼ����Ȩ��
    EPT_ACCESS              HookAccess;            // Hook����Ȩ��
    EPT_ACCESS              CurrentAccess;         // ��ǰ����Ȩ��

    // ʱ���ͳ��
    LARGE_INTEGER           CreateTime;            // ����ʱ��
    LARGE_INTEGER           LastAccessTime;        // ������ʱ��
    ULONG64                 AccessCount;           // ���ʼ���
    ULONG64                 TotalExecutionTime;    // ��ִ��ʱ��
    ULONG64                 AverageExecutionTime;  // ƽ��ִ��ʱ��
    ULONG64                 MinExecutionTime;      // ��Сִ��ʱ��
    ULONG64                 MaxExecutionTime;      // ���ִ��ʱ��

    // ͬ��
    KSPIN_LOCK              EntrySpinLock;         // ��Ŀ������
    LONG                    ReferenceCount;        // ���ü���

    // ��ȫ��Ϣ
    ULONG                   SecurityFlags;         // ��ȫ��־
    PVOID                   CreatingProcess;       // ��������
    UCHAR                   IntegrityHash[32];     // �����Թ�ϣ

    // �û�����
    PVOID                   UserContext;           // �û�������
    ULONG                   UserDataSize;          // �û����ݴ�С
    UCHAR                   UserData[64];          // �û�����

} PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

// EPT������������

/*****************************************************
 * ���ܣ��������ַ��ȡPML4����
 * ������VirtualAddress - �����ַ
 * ���أ�ULONG - PML4����
 * ��ע����ȡ�����ַ��PML4����λ
*****************************************************/
__forceinline ULONG EptGetPml4Index(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 39) & 0x1FF);
}

/*****************************************************
 * ���ܣ��������ַ��ȡPDPT����
 * ������VirtualAddress - �����ַ
 * ���أ�ULONG - PDPT����
 * ��ע����ȡ�����ַ��PDPT����λ
*****************************************************/
__forceinline ULONG EptGetPdptIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 30) & 0x1FF);
}

/*****************************************************
 * ���ܣ��������ַ��ȡPD����
 * ������VirtualAddress - �����ַ
 * ���أ�ULONG - PD����
 * ��ע����ȡ�����ַ��PD����λ
*****************************************************/
__forceinline ULONG EptGetPdIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 21) & 0x1FF);
}

/*****************************************************
 * ���ܣ��������ַ��ȡPT����
 * ������VirtualAddress - �����ַ
 * ���أ�ULONG - PT����
 * ��ע����ȡ�����ַ��PT����λ
*****************************************************/
__forceinline ULONG EptGetPtIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 12) & 0x1FF);
}

/*****************************************************
 * ���ܣ��������ַ��ȡҳ��ƫ��
 * ������VirtualAddress - �����ַ
 * ���أ�ULONG - ҳ��ƫ��
 * ��ע����ȡ�����ַ��ҳ����ƫ��
*****************************************************/
__forceinline ULONG EptGetPageOffset(ULONG64 VirtualAddress)
{
    return (ULONG)(VirtualAddress & 0xFFF);
}

/*****************************************************
 * ���ܣ����EPT��Ŀ�Ƿ����
 * ������Entry - EPT��Ŀֵ
 * ���أ�BOOLEAN - TRUE���ڣ�FALSE������
 * ��ע�����EPT��Ŀ����Ч��
*****************************************************/
__forceinline BOOLEAN EptIsEntryPresent(ULONG64 Entry)
{
    return (Entry & (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)) != 0;
}

/*****************************************************
 * ���ܣ�����EPT��ĿȨ��
 * ������pEntry - EPT��Ŀָ��
 *       Access - ����Ȩ��
 * ���أ���
 * ��ע������EPT��Ŀ�ķ���Ȩ��λ
*****************************************************/
__forceinline VOID EptSetEntryAccess(PULONG64 pEntry, EPT_ACCESS Access)
{
    *pEntry &= ~EPT_ACCESS_ALL;  // �������Ȩ��
    *pEntry |= (Access & EPT_ACCESS_ALL);  // ������Ȩ��
}

/*****************************************************
 * ���ܣ���ȡEPT��ĿȨ��
 * ������Entry - EPT��Ŀֵ
 * ���أ�EPT_ACCESS - ����Ȩ��
 * ��ע����ȡEPT��Ŀ�ĵ�ǰ����Ȩ��
*****************************************************/
__forceinline EPT_ACCESS EptGetEntryAccess(ULONG64 Entry)
{
    return (EPT_ACCESS)(Entry & EPT_ACCESS_ALL);
}

/*****************************************************
 * ���ܣ�����EPT��Ŀ�����ַ
 * ������pEntry - EPT��Ŀָ��
 *       PhysicalAddress - �����ַ
 * ���أ���
 * ��ע������EPT��Ŀָ��������ַ
*****************************************************/
__forceinline VOID EptSetEntryPhysicalAddress(PULONG64 pEntry, ULONG64 PhysicalAddress)
{
    *pEntry &= 0xFFF;  // ������12λ��־λ
    *pEntry |= (PhysicalAddress & 0xFFFFFFFFF000ULL);  // ���������ַ
}

/*****************************************************
 * ���ܣ���ȡEPT��Ŀ�����ַ
 * ������Entry - EPT��Ŀֵ
 * ���أ�ULONG64 - �����ַ
 * ��ע����ȡEPT��Ŀָ��������ַ
*****************************************************/
__forceinline ULONG64 EptGetEntryPhysicalAddress(ULONG64 Entry)
{
    return (Entry & 0xFFFFFFFFF000ULL);
}

// ��������

/*****************************************************
 * ���ܣ���ʼ��EPT��������
 * ������ppEptContext - ���EPT������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��EPTҳ�����������
*****************************************************/
NTSTATUS EptInitializeTableContext(_Out_ PEPT_TABLE_CONTEXT* ppEptContext);

/*****************************************************
 * ���ܣ�����EPT��������
 * ������pEptContext - EPT������ָ��
 * ���أ���
 * ��ע������EPTҳ����������ĺ������Դ
*****************************************************/
VOID EptCleanupTableContext(_In_ PEPT_TABLE_CONTEXT pEptContext);

/*****************************************************
 * ���ܣ�����EPT���ӳ��
 * ������pEptContext - EPT������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��Ϊ���������ڴ潨��1:1ӳ��
*****************************************************/
NTSTATUS EptBuildIdentityMap(_In_ PEPT_TABLE_CONTEXT pEptContext);

/*****************************************************
 * ���ܣ�ӳ�䵥��EPTҳ��
 * ������pEptContext - EPT������ָ��
 *       PhysicalAddress - �����ַ
 *       VirtualAddress - �����ַ
 *       Access - ����Ȩ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����EPT��ӳ�䵥��4KBҳ��
*****************************************************/
NTSTATUS EptMapPage(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 PhysicalAddress,
    _In_ ULONG64 VirtualAddress,
    _In_ EPT_ACCESS Access
);

/*****************************************************
 * ���ܣ�ȡ��EPTҳ��ӳ��
 * ������pEptContext - EPT������ָ��
 *       VirtualAddress - �����ַ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ȡ��EPT��ָ��ҳ���ӳ��
*****************************************************/
NTSTATUS EptUnmapPage(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress
);

/*****************************************************
 * ���ܣ��޸�EPTҳ��Ȩ��
 * ������pEptContext - EPT������ָ��
 *       VirtualAddress - �����ַ
 *       NewAccess - �µķ���Ȩ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע���޸�EPT��ָ��ҳ��ķ���Ȩ��
*****************************************************/
NTSTATUS EptModifyPageAccess(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress,
    _In_ EPT_ACCESS NewAccess
);

/*****************************************************
 * ���ܣ���ȡEPTҳ��Ȩ��
 * ������pEptContext - EPT������ָ��
 *       VirtualAddress - �����ַ
 *       pAccess - �������Ȩ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡEPT��ָ��ҳ��ĵ�ǰ����Ȩ��
*****************************************************/
NTSTATUS EptGetPageAccess(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress,
    _Out_ PEPT_ACCESS pAccess
);

/*****************************************************
 * ���ܣ�����EPT��
 * ������pEptContext - EPT������ָ��
 *       TableType - ������(1=PDPT, 2=PD, 3=PT)
 * ���أ�PVOID - �������ַ��ʧ�ܷ���NULL
 * ��ע����Ԥ������з���EPT��
*****************************************************/
PVOID EptAllocateTable(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG TableType
);

/*****************************************************
 * ���ܣ��ͷ�EPT��
 * ������pEptContext - EPT������ָ��
 *       pTable - �������ַ
 *       TableType - ������(1=PDPT, 2=PD, 3=PT)
 * ���أ���
 * ��ע����EPT���ص�Ԥ�������
*****************************************************/
VOID EptFreeTable(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ PVOID pTable,
    _In_ ULONG TableType
);

/*****************************************************
 * ���ܣ���ȡEPT�������ַ
 * ������pEptContext - EPT������ָ��
 *       pTable - �������ַ
 *       TableType - ������
 * ���أ�ULONG64 - �����ַ
 * ��ע����ȡEPT��������ַ
*****************************************************/
ULONG64 EptGetTablePhysicalAddress(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ PVOID pTable,
    _In_ ULONG TableType
);