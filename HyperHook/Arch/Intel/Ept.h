#pragma once
#include <ntifs.h>

#define VM_VPID             1
#define EPT_TABLE_ORDER     9
#define EPT_TABLE_ENTRIES   512

/*****************************************************
 * ö�٣�EPT_ACCESS
 * ���ܣ�EPTҳ����Ȩ��ö��
*****************************************************/
typedef enum _EPT_ACCESS
{
	EPT_ACCESS_NONE = 0,          // ��Ȩ��
	EPT_ACCESS_READ = 1,          // ��Ȩ��
	EPT_ACCESS_WRITE = 2,         // дȨ��
	EPT_ACCESS_EXEC = 4,          // ִ��Ȩ��
	EPT_ACCESS_RW = EPT_ACCESS_READ | EPT_ACCESS_WRITE,      // ��дȨ��
	EPT_ACCESS_ALL = EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC // ȫ��Ȩ��
} EPT_ACCESS;

/*****************************************************
 * ö�٣�EPT_TABLE_LEVEL
 * ���ܣ�EPTҳ����ö��
*****************************************************/
typedef enum _EPT_TABLE_LEVEL
{
	EPT_LEVEL_PTE = 0,            // ҳ����
	EPT_LEVEL_PDE = 1,            // ҳĿ¼��
	EPT_LEVEL_PDPTE = 2,          // ҳĿ¼ָ����
	EPT_LEVEL_PML4 = 3,           // PML4��
	EPT_TOP_LEVEL = EPT_LEVEL_PML4 // ���
} EPT_TABLE_LEVEL;

#pragma warning(disable: 4214)
#pragma pack(push, 1)

/*****************************************************
 * �����壺EPTP (Extended Page Table Pointer)
 * ���ܣ�EPT��ָ��ṹ�壬����ָ��EPTҳ��ĸ���(PML4)
 * ��ע���ýṹ��ͨ���洢��VMCS��EPT_POINTER�ֶ��У�����Guest�����ַת��
*****************************************************/
typedef union _EPTP
{
	ULONG64 All;                            // ������64λEPT��ָ��ֵ
	struct
	{
		ULONG64 MemoryType : 3;             // [0-2]��EPT��ҳ�ṹ�ڴ����ͣ�0=UC uncacheable��6=WB write-back��
		ULONG64 PageWalkLength : 3;         // [3-5]��ҳ�������ȣ�ͨ��Ϊ3����ʾ4��ҳ��
		ULONG64 DirtyAndAccessEnabled : 1;  // [6]����ҳ�ͷ��ʱ�־����λ��1=����A/Dλ֧�֣�
		ULONG64 Reserved1 : 5;              // [7-11]������λ����������Ϊ0
		ULONG64 PhysicalAddress : 36;              // [12-47]��EPT PML4�������ַ��4KB���룩
		ULONG64 Reserved2 : 16;             // [48-63]������λ����������Ϊ0
	} Fields;
} EPTP, EPT_TABLE_POINTER, * PEPT_TABLE_POINTER;

/*****************************************************
 * �����壺EPT_MMPTE
 * ���ܣ�EPTͨ��ҳ����ṹ�壬�����ڸ���EPTҳ���PML4E��PDPTE��PDE��PTE��
 * ��ע���ֶμ򻯣������ڻ���EPT����
*****************************************************/
typedef union _EPT_MMPTE
{
	ULONG64 All; // 64λ����ҳ����ֵ������ԭ�Ӳ�����������ֵ
	struct
	{
		ULONG64 Present : 1;           // [0]��ҳ����ڱ�־��1=���ڣ�0=�����ڣ�
		ULONG64 Write : 1;             // [1]��дȨ�ޱ�־��1=����д�룬0=ֻ����
		ULONG64 Execute : 1;           // [2]��ִ��Ȩ�ޱ�־��1=����ִ�У�0=����ִ�У�
		ULONG64 Reserved1 : 9;         // [3-11]������λ����������Ϊ0
		ULONG64 PhysicalAddress : 40;  // [12-51]������ҳ���ַ��40λ֧�ָ������ַ����ʵ�ʶ��뷽ʽʹ�ã�
		ULONG64 Reserved2 : 12;        // [52-63]������λ����������Ϊ0
	} Fields;
} EPT_MMPTE, * PEPT_MMPTE;

/*****************************************************
 * �����壺EPT_PML4E (Page Map Level 4 Entry)
 * ���ܣ�EPT��4��ҳ����ṹ�壬ָ��PDPT��
 * ��ע��ÿ��PML4E����512GB�ĵ�ַ�ռ�
*****************************************************/
typedef union _EPT_PML4E
{
	ULONG64 All;                    // 64λ����ҳ����ֵ������ԭ�Ӳ�����������ֵ
	struct
	{
		ULONG64 Read : 1;                   // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		ULONG64 Write : 1;                  // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		ULONG64 Execute : 1;                // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		UINT64 Reserved1 : 5;               // [3-7]������λ����������Ϊ0
		UINT64 Accessed : 1;                // [8]�����ʱ�־λ��Ӳ�����ã���ʾҳ���ѱ����ʣ�
		UINT64 Ignored1 : 1;                // [9]������λ�����������ʹ��
		UINT64 ExecuteForUserMode : 1;      // [10]���û�ģʽִ��Ȩ�ޣ�1=�û�ģʽ��ִ�У�
		UINT64 Ignored2 : 1;                // [11]������λ�����������ʹ��
		ULONG64 PhysicalAddress : 36;       // [12-47]��ָ��PDPT��������ַ��4KB���룩
		UINT64 Reserved2 : 4;               // [48-51]������λ����������Ϊ0
		UINT64 Ignored3 : 12;               // [52-63]������λ�����������ʹ�ã����ǡ����ü����ȣ�
	} Fields;
} EPT_PML4E, EPT_PML4_ENTRY, * PEPT_PML4_ENTRY;

/*****************************************************
 * �����壺EPT_PDPTE (Page Directory Pointer Table Entry)
 * ���ܣ�EPT��3��ҳ����ṹ�壬��ָ��PD���ӳ��1GB��ҳ
 * ��ע��ÿ��PDPTE����1GB�ĵ�ַ�ռ䣬λ7�����Ƿ�Ϊ��ҳ
*****************************************************/
typedef union _EPT_PDPTE
{
	ULONG64 All;                            // 64λ����ҳ����ֵ
	struct
	{
		UINT64 Read : 1;                    // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		UINT64 Write : 1;                   // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		UINT64 Execute : 1;                 // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		UINT64 Reserved1 : 5;               // [3-7]������λ����������Ϊ0
		UINT64 Accessed : 1;                // [8]�����ʱ�־λ��Ӳ�����ã���ʾҳ���ѱ����ʣ�
		UINT64 Ignored1 : 1;                // [9]������λ�����������ʹ��
		UINT64 ExecuteForUserMode : 1;      // [10]���û�ģʽִ��Ȩ�ޣ�1=�û�ģʽ��ִ�У�
		UINT64 Ignored2 : 1;                // [11]������λ�����������ʹ��
		UINT64 PhysicalAddress : 36;        // [12-47]��ָ��PD��������ַ��4KB���룩
		UINT64 Reserved2 : 4;               // [48-51]������λ����������Ϊ0
		UINT64 Ignored3 : 12;               // [52-63]������λ�����������ʹ��
	} Fields;
} EPT_PDPTE, * PEPT_PDPTE;

/*****************************************************
 * �����壺EPT_PDPTE_1GB (1GB��ҳPDPTE)
 * ���ܣ�ӳ��1GB��ҳ��EPTҳĿ¼ָ�����
 * ��ע��λ7����Ϊ1����ʾ����1GB��ҳӳ��
*****************************************************/
typedef union _EPT_PDPTE_1GB
{
	ULONG64 All;                            // 64λ����ҳ����ֵ
	struct
	{
		ULONG64 Read : 1;                   // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		ULONG64 Write : 1;                  // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		ULONG64 Execute : 1;                // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		ULONG64 MemoryType : 3;             // [3-5]��EPT�ڴ����ͣ�0=UC��1=WC��4=WT��6=WB��7=UC-��
		ULONG64 IgnorePat : 1;              // [6]������PAT��־λ��1=����PAT��
		ULONG64 MustBeOne : 1;              // [7]������Ϊ1����ʾ����1GB��ҳ
		ULONG64 Accessed : 1;               // [8]�����ʱ�־λ��Ӳ�����ã�
		ULONG64 Dirty : 1;                  // [9]����ҳ��־λ��Ӳ�����ã���ʾҳ���ѱ�д�룩
		ULONG64 ExecuteForUserMode : 1;     // [10]���û�ģʽִ��Ȩ��
		ULONG64 Ignored1 : 1;               // [11]������λ�����������ʹ��
		ULONG64 Reserved1 : 18;             // [12-29]������λ����������Ϊ0��1GB���룩
		ULONG64 PhysicalAddress : 18;       // [30-47]��1GBҳ����������ַ
		ULONG64 Reserved2 : 4;              // [48-51]������λ����������Ϊ0
		ULONG64 Ignored2 : 11;              // [52-62]������λ�����������ʹ��
		ULONG64 SuppressVE : 1;             // [63]���������⻯�쳣��־λ
	} Fields;
} EPT_PDPTE_1GB, * PEPT_PDPTE_1GB;

/*****************************************************
 * �����壺EPT_PDE (Page Directory Entry)
 * ���ܣ�EPT��2��ҳ����ṹ�壬��ָ��PT���ӳ��2MB��ҳ
 * ��ע��ÿ��PDE����2MB�ĵ�ַ�ռ䣬λ7�����Ƿ�Ϊ��ҳ
*****************************************************/
typedef union _EPT_PDE
{
	ULONG64 All;                            // 64λ����ҳ����ֵ
	struct
	{
		UINT64 Read : 1;                    // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		UINT64 Write : 1;                   // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		UINT64 Execute : 1;                 // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		UINT64 Reserved1 : 5;               // [3-7]������λ����������Ϊ0
		UINT64 Accessed : 1;                // [8]�����ʱ�־λ��Ӳ�����ã�
		UINT64 Ignored1 : 1;                // [9]������λ�����������ʹ��
		UINT64 ExecuteForUserMode : 1;      // [10]���û�ģʽִ��Ȩ��
		UINT64 Ignored2 : 1;                // [11]������λ�����������ʹ��
		UINT64 PhysicalAddress : 36;        // [12-47]��ָ��PT��������ַ��4KB���룩
		UINT64 Reserved2 : 4;               // [48-51]������λ����������Ϊ0
		UINT64 Ignored3 : 12;               // [52-63]������λ�����������ʹ��
	} Fields;
} EPT_PDE, * PEPT_PDE;

/*****************************************************
 * �����壺EPT_PDE_2MB (2MB��ҳPDE)
 * ���ܣ�ӳ��2MB��ҳ��EPTҳĿ¼����
 * ��ע��λ7����Ϊ1����ʾ����2MB��ҳӳ�䣬֧�����µ�Guest��ҳ��֤������
*****************************************************/
typedef union _EPT_PDE_2MB
{
	ULONG64 All;                            // 64λ����ҳ����ֵ
	struct
	{
		ULONG64 Read : 1;                   // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		ULONG64 Write : 1;                  // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		ULONG64 Execute : 1;                // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		ULONG64 MemoryType : 3;             // [3-5]��EPT�ڴ����ͣ�0=UC��1=WC��4=WT��6=WB��7=UC-��
		ULONG64 IgnorePat : 1;              // [6]������PAT��־λ��1=����PAT��
		ULONG64 MustBeOne : 1;              // [7]������Ϊ1����ʾ����2MB��ҳ
		ULONG64 Accessed : 1;               // [8]�����ʱ�־λ��Ӳ�����ã�
		ULONG64 Dirty : 1;                  // [9]����ҳ��־λ��Ӳ�����ã�
		ULONG64 ExecuteForUserMode : 1;     // [10]���û�ģʽִ��Ȩ�ޣ�1=�û�ģʽ��ִ�У�
		ULONG64 Ignored1 : 1;               // [11]������λ�����������ʹ��
		ULONG64 Reserved1 : 9;              // [12-20]������λ����������Ϊ0��2MB���룩
		ULONG64 PhysicalAddress : 27;       // [21-47]��2MBҳ����������ַ
		ULONG64 Reserved2 : 4;              // [48-51]������λ����������Ϊ0
		ULONG64 Ignored2 : 5;               // [52-56]������λ�����������ʹ��
		ULONG64 VerifyGuestPaging : 1;      // [57]����֤Guest��ҳ��־λ����ҪGuest��ҳ��֤����λΪ1��
		ULONG64 PagingWriteAccess : 1;      // [58]����ҳд���ʱ�־λ����ҪEPT��ҳд����λΪ1��
		ULONG64 Ignored3 : 1;               // [59]������λ�����������ʹ��
		ULONG64 SupervisorShadowStack : 1;  // [60]�������û�Ӱ��ջ��־λ����ҪEPTPλ7Ϊ1��
		ULONG64 Ignored4 : 2;               // [61-62]������λ�����������ʹ��
		ULONG64 SuppressVE : 1;             // [63]���������⻯�쳣��־λ��1=����#VE�쳣��
	} Fields;
} EPT_PDE_2MB, EPT_PDE_LARGE_ENTRY, * PEPT_PDE_2MB, * PEPT_PDE_LARGE_ENTRY;

/*****************************************************
 * �����壺EPT_PTE
 * ���ܣ�EPTҳ����ṹ�壬ӳ��4KBҳ��
 * ��ע��֧�����µķô桢ִ�п��ơ���ҳ�����ʱ�־��Ӱ��ջ������
*****************************************************/
typedef union _EPT_PTE
{
	ULONG64 All; // 64λ����EPTҳ����
	struct
	{
		ULONG64 Read : 1;                   // [0]����Ȩ�ޱ�־λ��1=�ɶ���0=���ɶ���
		ULONG64 Write : 1;                  // [1]��дȨ�ޱ�־λ��1=��д��0=ֻ����
		ULONG64 Execute : 1;                // [2]��ִ��Ȩ�ޱ�־λ��1=��ִ�У�0=����ִ�У�
		ULONG64 MemoryType : 3;             // [3-5]��EPT�ڴ����ͣ�0=UC��1=WC��4=WT��6=WB��7=UC-��
		ULONG64 IgnorePat : 1;              // [6]   �Ƿ����PAT����
		ULONG64 Ignored1 : 1;               // [7]   ����λ
		ULONG64 AccessedFlag : 1;           // [8]   ���ʱ�־��EPTP bit6=1ʱ��Ч����ʾ��ҳ�ѱ����ʣ�
		ULONG64 DirtyFlag : 1;              // [9]   ��ҳ��־��EPTP bit6=1ʱ��Ч����ʾ��ҳ�ѱ�д�룩
		ULONG64 ExecuteForUserMode : 1;     // [10]  �û�ģʽִ��Ȩ�ޣ�mode-based execute control=1ʱ��Ч��
		ULONG64 Ignored2 : 1;               // [11]  ����λ
		ULONG64 PhysicalAddress : 36;       // [47:12] �����ַ��4KB���룬ָ��ҳ��
		ULONG64 Reserved : 4;               // [51:48] ����λ������Ϊ0
		ULONG64 Ignored3 : 5;               // [56:52] ����λ
		ULONG64 VerifyGuestPaging : 1;      // [57]  Guest��ҳ��֤��־��VM-exec controlΪ1ʱ��Ч��
		ULONG64 PagingWriteAccess : 1;      // [58]  Pagingд���ʿ��ƣ�VM-exec controlΪ1ʱ��Ч��
		ULONG64 Ignored4 : 1;               // [59]  ����λ
		ULONG64 SupervisorShadowStack : 1;  // [60]  �����û�Ӱ��ջ����EPTP bit7=1ʱ��Ч��
		ULONG64 SubPageWritePermission : 1; // [61]  ��ҳд��Ȩ�ޣ�VM-exec controlΪ1ʱ��Ч������128�ֽ�����д�룩
		ULONG64 Ignored5 : 1;               // [62]  ����λ
		ULONG64 SuppressVE : 1;             // [63]  �������⻯�쳣��EPT-violation #VE����Ϊ1ʱ��Ч��
	} Fields;
} EPT_PTE, EPT_PTE_ENTRY, * PEPT_PTE, * PEPT_PTE_ENTRY;

/*****************************************************
 * �����壺GUEST_PHYSICAL
 * ���ܣ��ͻ��������ַ�����������ַ�ṹ��
*****************************************************/
typedef union _GUEST_PHYSICAL
{
	ULONG64 All;
	struct
	{
		ULONG64 offset : 12;    // [0-11] ƫ��
		ULONG64 pte : 9;        // [12-20] ҳ������
		ULONG64 pde : 9;        // [21-29] ҳĿ¼����
		ULONG64 pdpte : 9;      // [30-38] ҳĿ¼ָ������
		ULONG64 pml4 : 9;       // [39-47] PML4����
		ULONG64 reserved : 16;  // ����
	} Fields;
} GUEST_PHYSICAL, * PGUEST_PHYSICAL;

/*****************************************************
 * �����壺EPT_VIOLATION_DATA
 * ���ܣ�EPTΥ���˳��޶��ṹ��
*****************************************************/
typedef union _EPT_VIOLATION_DATA
{
	ULONG64 All;
	struct
	{
		ULONG64 Read : 1;           // ������Υ��
		ULONG64 Write : 1;          // д����Υ��
		ULONG64 Execute : 1;        // ִ�з���Υ��
		ULONG64 PTERead : 1;        // ҳ�����Ƿ��
		ULONG64 PTEWrite : 1;       // ҳ�����Ƿ�д
		ULONG64 PTEExecute : 1;     // ҳ�����Ƿ�ִ��
		ULONG64 Reserved1 : 1;      // ����
		ULONG64 GuestLinear : 1;    // �ͻ����Ե�ַ�ֶ���Ч
		ULONG64 FailType : 1;       // ʧ������
		ULONG64 Reserved2 : 3;      // ����
		ULONG64 NMIBlock : 1;       // NMI�������
		ULONG64 Reserved3 : 51;     // ����
	} Fields;
} EPT_VIOLATION_DATA, * PEPT_VIOLATION_DATA;

struct _EPT_DATA;
#pragma pack(pop)
#pragma warning(default: 4214)


// EPT��ض���
#define PAGES_PER_ENTRY             ((PAGE_SIZE - sizeof(LIST_ENTRY) - sizeof(ULONG64)) / sizeof(union _EPT_MMPTE*))
#define EPT_PREALLOC_PAGES          512

/*****************************************************
 * �ṹ�壺EPT_PAGES_ENTRY
 * ���ܣ�EPTҳ����������ڴ��EPTҳ
*****************************************************/
typedef struct _EPT_PAGES_ENTRY
{
	LIST_ENTRY link;                                     // ����ָ��
	ULONG64 count;                                       // ҳ����
	union _EPT_MMPTE* pages[PAGES_PER_ENTRY];            // ҳָ������
} EPT_PAGES_ENTRY, * PEPT_PAGES_ENTRY;

/*****************************************************
 * �ṹ�壺EPT_DATA
 * ���ܣ�����VCPU EPT�����Ϣ
*****************************************************/
typedef struct _EPT_DATA
{
	union _EPT_MMPTE* PML4Ptr;                       // EPT PML4ָ��
	LIST_ENTRY PageList;                             // EPT_PAGES_ENTRY����
	union _EPT_MMPTE* Pages[EPT_PREALLOC_PAGES];     // Ԥ����ҳ����
	ULONG Preallocations;                            // ��ʹ�õ�Ԥ����ҳ��
	ULONG TotalPages;                                // EPT��ҳ��
} EPT_DATA, * PEPT_DATA;

/*****************************************************
 * �ṹ�壺PAGE_HOOK_STATE
 * ���ܣ�ҳ��HOOK׷��״̬
*****************************************************/
typedef struct _PAGE_HOOK_STATE
{
	struct _PAGE_HOOK_ENTRY* pEntry;    // HOOK��ָ��
	ULONG64 Rip;                        // ָ��ָ��
} PAGE_HOOK_STATE, * PPAGE_HOOK_STATE;


/*****************************************************
 * ���ܣ����õ�ǰCPU��EPT
 * ������PML4 - EPT PML4ָ��
 * ���أ���
*****************************************************/
VOID EptEnable(IN PEPT_PML4_ENTRY PML4);

/*****************************************************
 * ���ܣ����õ�ǰCPU��EPT
 * ��������
 * ���أ���
*****************************************************/
VOID EptDisable(VOID);

/*****************************************************
 * ���ܣ������ͻ�����������ҳӳ�䣨Identity Map��
 * ������pEPT - ��ǰCPU��EPT���ݽṹָ��
 * ���أ�NTSTATUS״̬��
*****************************************************/
NTSTATUS EptBuildIdentityMap(IN struct _EPT_DATA* pEPT);

/*****************************************************
 * ���ܣ��ͷſͻ�����������ҳӳ��
 * ������pEPT - ��ǰCPU��EPT���ݽṹָ��
 * ���أ�NTSTATUS״̬��
*****************************************************/
NTSTATUS EptFreeIdentityMap(IN struct _EPT_DATA* pEPT);

/*****************************************************
 * ���ܣ��ݹ����EPT����
 * ������
 *   pEPTData - ��ǰCPU��EPT���ݽṹָ��
 *   pTable   - EPT��ָ��
 *   level    - EPT����
 *   pfn      - ҳ֡��
 *   access   - �µķ���Ȩ��
 *   hostPFN  - �µ�����PFN
 *   count    - Ҫ���µ�����
 * ���أ�NTSTATUS״̬��
*****************************************************/
NTSTATUS EptUpdateTableRecursive(
	IN struct _EPT_DATA* pEPTData,
	IN PEPT_MMPTE pTable,
	IN EPT_TABLE_LEVEL level,
	IN ULONG64 pfn,
	IN EPT_ACCESS access,
	IN ULONG64 hostPFN,
	IN ULONG count
);

/*****************************************************
 * ���ܣ���ȡ�ͻ��������ַ��Ӧ��EPT PTE����
 * ������
 *   PML4   - EPT PML4ָ��
 *   phys   - �ͻ��������ַ
 *   pEntry - ����ҵ���EPT PTE����ָ���NULL
 * ���أ�NTSTATUS״̬��
*****************************************************/
NTSTATUS EptGetPTEForPhysical(
	IN PEPT_PML4_ENTRY PML4,
	IN PHYSICAL_ADDRESS phys,
	OUT PEPT_PTE_ENTRY* pEntry
);
