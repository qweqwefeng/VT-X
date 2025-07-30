#pragma once
#include <ntdef.h>
#include <intrin.h>

/*****************************************************
 * ö�����ͣ�VMCS_ENCODING
 * ���ܣ����� VMCS �����ֶΣ�Intel VT-x ���⻯��ؼĴ����ֶα��룩
 * ��ע������ Intel SDM ���壬��Ϊ��ͬ�����ֶΣ�����ơ�״̬��ֻ����
*****************************************************/

// 16 λ�����ֶΣ�16-Bit Control Field��
typedef enum _VMCS_ENCODING
{
    VIRTUAL_PROCESSOR_ID = 0x00000000,  // ���⴦���� ID
    POSTED_INTERRUPT_NOTIFICATION = 0x00000002, // �ѷ����ж�֪ͨ
    EPTP_INDEX = 0x00000004,                     // EPTP ����

    // 16 λ Guest ״̬�ֶΣ�16-Bit Guest-State Fields��
    GUEST_ES_SELECTOR = 0x00000800,     // �ͻ��� ES ��ѡ����
    GUEST_CS_SELECTOR = 0x00000802,     // �ͻ��� CS ��ѡ����
    GUEST_SS_SELECTOR = 0x00000804,     // �ͻ��� SS ��ѡ����
    GUEST_DS_SELECTOR = 0x00000806,     // �ͻ��� DS ��ѡ����
    GUEST_FS_SELECTOR = 0x00000808,     // �ͻ��� FS ��ѡ����
    GUEST_GS_SELECTOR = 0x0000080a,     // �ͻ��� GS ��ѡ����
    GUEST_LDTR_SELECTOR = 0x0000080c,   // �ͻ��� LDTR ��ѡ����
    GUEST_TR_SELECTOR = 0x0000080e,     // �ͻ��� TR ��ѡ����
    GUEST_INTERRUPT_STATUS = 0x00000810,// �ͻ����ж�״̬

    // 16 λ Host ״̬�ֶΣ�16-Bit Host-State Fields��
    HOST_ES_SELECTOR = 0x00000c00,      // ���� ES ��ѡ����
    HOST_CS_SELECTOR = 0x00000c02,      // ���� CS ��ѡ����
    HOST_SS_SELECTOR = 0x00000c04,      // ���� SS ��ѡ����
    HOST_DS_SELECTOR = 0x00000c06,      // ���� DS ��ѡ����
    HOST_FS_SELECTOR = 0x00000c08,      // ���� FS ��ѡ����
    HOST_GS_SELECTOR = 0x00000c0a,      // ���� GS ��ѡ����
    HOST_TR_SELECTOR = 0x00000c0c,      // ���� TR ��ѡ����

    // 64 λ�����ֶΣ�64-Bit Control Fields��
    IO_BITMAP_A = 0x00002000,                   // IO λͼ A ��ַ
    IO_BITMAP_A_HIGH = 0x00002001,              // IO λͼ A �ߵ�ַ
    IO_BITMAP_B = 0x00002002,                   // IO λͼ B ��ַ
    IO_BITMAP_B_HIGH = 0x00002003,              // IO λͼ B �ߵ�ַ
    MSR_BITMAP = 0x00002004,                    // MSR λͼ��ַ
    MSR_BITMAP_HIGH = 0x00002005,               // MSR λͼ�ߵ�ַ
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,        // VM �˳�ʱ MSR ���������ַ
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,   // VM �˳�ʱ MSR ��������ߵ�ַ
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,         // VM �˳�ʱ MSR ���������ַ
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,    // VM �˳�ʱ MSR ��������ߵ�ַ
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,        // VM ����ʱ MSR ���������ַ
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,   // VM ����ʱ MSR ��������ߵ�ַ
    EXECUTIVE_VMCS_POINTER = 0x0000200c,        // ִ�� VMCS ָ��
    EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,   // ִ�� VMCS ָ��ߵ�ַ
    TSC_OFFSET = 0x00002010,                    // TSC ƫ��
    TSC_OFFSET_HIGH = 0x00002011,               // TSC ƫ�Ƹߵ�ַ
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,        // ���� APIC ҳ��ַ
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,   // ���� APIC ҳ�ߵ�ַ
    APIC_ACCESS_ADDR = 0x00002014,              // APIC ���ʵ�ַ
    APIC_ACCESS_ADDR_HIGH = 0x00002015,         // APIC ���ʸߵ�ַ
    EPT_POINTER = 0x0000201a,                   // EPT ָ��
    EPT_POINTER_HIGH = 0x0000201b,              // EPT ָ��ߵ�ַ
    EOI_EXIT_BITMAP_0 = 0x0000201c,             // EOI �˳�λͼ 0
    EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,        // EOI �˳�λͼ 0 �ߵ�ַ
    EOI_EXIT_BITMAP_1 = 0x0000201e,             // EOI �˳�λͼ 1
    EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,        // EOI �˳�λͼ 1 �ߵ�ַ
    EOI_EXIT_BITMAP_2 = 0x00002020,             // EOI �˳�λͼ 2
    EOI_EXIT_BITMAP_2_HIGH = 0x00002021,        // EOI �˳�λͼ 2 �ߵ�ַ
    EOI_EXIT_BITMAP_3 = 0x00002022,             // EOI �˳�λͼ 3
    EOI_EXIT_BITMAP_3_HIGH = 0x00002023,        // EOI �˳�λͼ 3 �ߵ�ַ
    EPTP_LIST_ADDRESS = 0x00002024,             // EPTP �б��ַ
    EPTP_LIST_ADDRESS_HIGH = 0x00002025,        // EPTP �б�ߵ�ַ
    VMREAD_BITMAP_ADDRESS = 0x00002026,         // VMREAD λͼ��ַ
    VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,    // VMREAD λͼ�ߵ�ַ
    VMWRITE_BITMAP_ADDRESS = 0x00002028,        // VMWRITE λͼ��ַ
    VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,   // VMWRITE λͼ�ߵ�ַ
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,      // ���⻯�쳣��Ϣ��ַ
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b, // ���⻯�쳣��Ϣ�ߵ�ַ
    XSS_EXITING_BITMAP = 0x0000202c,            // XSS �˳�λͼ
    XSS_EXITING_BITMAP_HIGH = 0x0000202d,       // XSS �˳�λͼ�ߵ�ַ

    // 64 λֻ�������ֶΣ�64-Bit Read-Only Data Field��
    GUEST_PHYSICAL_ADDRESS = 0x00002400,        // �ͻ��������ַ
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,   // �ͻ��������ַ��λ

    // 64 λ Guest ״̬�ֶΣ�64-Bit Guest-State Fields��
    VMCS_LINK_POINTER = 0x00002800,             // VMCS ����ָ��
    VMCS_LINK_POINTER_HIGH = 0x00002801,        // VMCS ����ָ��ߵ�ַ
    GUEST_IA32_DEBUGCTL = 0x00002802,           // �ͻ��� IA32_DEBUGCTL MSR
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,      // �ͻ��� IA32_DEBUGCTL MSR �ߵ�ַ
    GUEST_IA32_PAT = 0x00002804,                // �ͻ��� IA32_PAT MSR
    GUEST_IA32_PAT_HIGH = 0x00002805,           // �ͻ��� IA32_PAT MSR �ߵ�ַ
    GUEST_IA32_EFER = 0x00002806,               // �ͻ��� IA32_EFER MSR
    GUEST_IA32_EFER_HIGH = 0x00002807,          // �ͻ��� IA32_EFER MSR �ߵ�ַ
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,   // �ͻ��� IA32_PERF_GLOBAL_CTRL MSR
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809, // �ͻ��� IA32_PERF_GLOBAL_CTRL MSR �ߵ�ַ
    GUEST_PDPTR0 = 0x0000280a,                  // �ͻ��� PDPTR0
    GUEST_PDPTR0_HIGH = 0x0000280b,             // �ͻ��� PDPTR0 �ߵ�ַ
    GUEST_PDPTR1 = 0x0000280c,                  // �ͻ��� PDPTR1
    GUEST_PDPTR1_HIGH = 0x0000280d,             // �ͻ��� PDPTR1 �ߵ�ַ
    GUEST_PDPTR2 = 0x0000280e,                  // �ͻ��� PDPTR2
    GUEST_PDPTR2_HIGH = 0x0000280f,             // �ͻ��� PDPTR2 �ߵ�ַ
    GUEST_PDPTR3 = 0x00002810,                  // �ͻ��� PDPTR3
    GUEST_PDPTR3_HIGH = 0x00002811,             // �ͻ��� PDPTR3 �ߵ�ַ

    // 64 λ Host ״̬�ֶΣ�64-Bit Host-State Fields��
    HOST_IA32_PAT = 0x00002c00,                 // ���� IA32_PAT MSR
    HOST_IA32_PAT_HIGH = 0x00002c01,            // ���� IA32_PAT MSR �ߵ�ַ
    HOST_IA32_EFER = 0x00002c02,                // ���� IA32_EFER MSR
    HOST_IA32_EFER_HIGH = 0x00002c03,           // ���� IA32_EFER MSR �ߵ�ַ
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,    // ���� IA32_PERF_GLOBAL_CTRL MSR
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05, // ���� IA32_PERF_GLOBAL_CTRL MSR �ߵ�ַ

    // 32 λ�����ֶΣ�32-Bit Control Fields��
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,     // PIN ���� VM ִ�п���
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,     // CPU ���� VM ִ�п���
    EXCEPTION_BITMAP = 0x00004004,              // �쳣λͼ
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,    // ҳ���ϴ���������
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,   // ҳ���ϴ�����ƥ��
    CR3_TARGET_COUNT = 0x0000400a,              // CR3 Ŀ����
    VM_EXIT_CONTROLS = 0x0000400c,              // VM �˳�����
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,       // VM �˳� MSR �������
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,        // VM �˳� MSR ���ؼ���
    VM_ENTRY_CONTROLS = 0x00004012,             // VM �������
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,       // VM ���� MSR ���ؼ���
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,      // VM �����ж���Ϣ�ֶ�
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018, // VM �����쳣������
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,      // VM ����ָ���
    TPR_THRESHOLD = 0x0000401c,                 // TPR ��ֵ
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,     // ���� VM ִ�п���
    PLE_GAP = 0x00004020,                       // PLE GAP
    PLE_WINDOW = 0x00004022,                    // PLE ����

    // 32 λֻ�������ֶΣ�32-Bit Read-Only Data Fields��
    VM_INSTRUCTION_ERROR = 0x00004400,          // VM ָ�����
    VM_EXIT_REASON = 0x00004402,                // VM �˳�ԭ��
    VM_EXIT_INTR_INFO = 0x00004404,             // VM �˳��ж���Ϣ
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,       // VM �˳��жϴ�����
    IDT_VECTORING_INFO_FIELD = 0x00004408,      // IDT �����ж���Ϣ�ֶ�
    IDT_VECTORING_ERROR_CODE = 0x0000440a,      // IDT �����жϴ�����
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,       // VM �˳�ָ���
    VMX_INSTRUCTION_INFO = 0x0000440e,          // VMX ָ����Ϣ

    // 32 λ Guest ״̬�ֶΣ�32-Bit Guest-State Fields��
    GUEST_ES_LIMIT = 0x00004800,                // �ͻ��� ES �ν���
    GUEST_CS_LIMIT = 0x00004802,                // �ͻ��� CS �ν���
    GUEST_SS_LIMIT = 0x00004804,                // �ͻ��� SS �ν���
    GUEST_DS_LIMIT = 0x00004806,                // �ͻ��� DS �ν���
    GUEST_FS_LIMIT = 0x00004808,                // �ͻ��� FS �ν���
    GUEST_GS_LIMIT = 0x0000480a,                // �ͻ��� GS �ν���
    GUEST_LDTR_LIMIT = 0x0000480c,              // �ͻ��� LDTR �ν���
    GUEST_TR_LIMIT = 0x0000480e,                // �ͻ��� TR �ν���
    GUEST_GDTR_LIMIT = 0x00004810,              // �ͻ��� GDTR �ν���
    GUEST_IDTR_LIMIT = 0x00004812,              // �ͻ��� IDTR �ν���
    GUEST_ES_AR_BYTES = 0x00004814,             // �ͻ��� ES �������ֽ�
    GUEST_CS_AR_BYTES = 0x00004816,             // �ͻ��� CS �������ֽ�
    GUEST_SS_AR_BYTES = 0x00004818,             // �ͻ��� SS �������ֽ�
    GUEST_DS_AR_BYTES = 0x0000481a,             // �ͻ��� DS �������ֽ�
    GUEST_FS_AR_BYTES = 0x0000481c,             // �ͻ��� FS �������ֽ�
    GUEST_GS_AR_BYTES = 0x0000481e,             // �ͻ��� GS �������ֽ�
    GUEST_LDTR_AR_BYTES = 0x00004820,           // �ͻ��� LDTR �������ֽ�
    GUEST_TR_AR_BYTES = 0x00004822,             // �ͻ��� TR �������ֽ�
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,   // �ͻ����ж�������Ϣ
    GUEST_ACTIVITY_STATE = 0x00004826,          // �ͻ��˻״̬
    GUEST_SMBASE = 0x00004828,                  // �ͻ��� SMBASE
    GUEST_SYSENTER_CS = 0x0000482a,             // �ͻ��� SYSENTER_CS
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,    // VMX ��ռ��ʱ��ֵ

    // 32 λ Host ״̬�ֶΣ�32-Bit Host-State Field��
    HOST_IA32_SYSENTER_CS = 0x00004c00,         // ���� IA32_SYSENTER_CS

    // ��Ȼ��ȿ����ֶΣ�Natural-Width Control Fields��
    CR0_GUEST_HOST_MASK = 0x00006000,           // CR0 �ͻ���/��������
    CR4_GUEST_HOST_MASK = 0x00006002,           // CR4 �ͻ���/��������
    CR0_READ_SHADOW = 0x00006004,               // CR0 ��Ӱ��
    CR4_READ_SHADOW = 0x00006006,               // CR4 ��Ӱ��
    CR3_TARGET_VALUE0 = 0x00006008,             // CR3 Ŀ��ֵ0
    CR3_TARGET_VALUE1 = 0x0000600a,             // CR3 Ŀ��ֵ1
    CR3_TARGET_VALUE2 = 0x0000600c,             // CR3 Ŀ��ֵ2
    CR3_TARGET_VALUE3 = 0x0000600e,             // CR3 Ŀ��ֵ3

    // ��Ȼ���ֻ�������ֶΣ�Natural-Width Read-Only Data Fields��
    EXIT_QUALIFICATION = 0x00006400,            // �˳��޶�����
    IO_RCX = 0x00006402,                        // IO RCX
    IO_RSI = 0x00006404,                        // IO RSI
    IO_RDI = 0x00006406,                        // IO RDI
    IO_RIP = 0x00006408,                        // IO RIP
    GUEST_LINEAR_ADDRESS = 0x0000640a,          // �ͻ������Ե�ַ

    // ��Ȼ��� Guest ״̬�ֶΣ�Natural-Width Guest-State Fields��
    GUEST_CR0 = 0x00006800,                     // �ͻ��� CR0
    GUEST_CR3 = 0x00006802,                     // �ͻ��� CR3
    GUEST_CR4 = 0x00006804,                     // �ͻ��� CR4
    GUEST_ES_BASE = 0x00006806,                 // �ͻ��� ES ��ַ
    GUEST_CS_BASE = 0x00006808,                 // �ͻ��� CS ��ַ
    GUEST_SS_BASE = 0x0000680a,                 // �ͻ��� SS ��ַ
    GUEST_DS_BASE = 0x0000680c,                 // �ͻ��� DS ��ַ
    GUEST_FS_BASE = 0x0000680e,                 // �ͻ��� FS ��ַ
    GUEST_GS_BASE = 0x00006810,                 // �ͻ��� GS ��ַ
    GUEST_LDTR_BASE = 0x00006812,               // �ͻ��� LDTR ��ַ
    GUEST_TR_BASE = 0x00006814,                 // �ͻ��� TR ��ַ
    GUEST_GDTR_BASE = 0x00006816,               // �ͻ��� GDTR ��ַ
    GUEST_IDTR_BASE = 0x00006818,               // �ͻ��� IDTR ��ַ
    GUEST_DR7 = 0x0000681a,                     // �ͻ��� DR7
    GUEST_RSP = 0x0000681c,                     // �ͻ��� RSP
    GUEST_RIP = 0x0000681e,                     // �ͻ��� RIP
    GUEST_RFLAGS = 0x00006820,                  // �ͻ��� RFLAGS
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,  // �ͻ��˹�������쳣
    GUEST_SYSENTER_ESP = 0x00006824,            // �ͻ��� SYSENTER_ESP
    GUEST_SYSENTER_EIP = 0x00006826,            // �ͻ��� SYSENTER_EIP

    // ��Ȼ��� Host ״̬�ֶΣ�Natural-Width Host-State Fields��
    HOST_CR0 = 0x00006c00,                      // ���� CR0
    HOST_CR3 = 0x00006c02,                      // ���� CR3
    HOST_CR4 = 0x00006c04,                      // ���� CR4
    HOST_FS_BASE = 0x00006c06,                  // ���� FS ��ַ
    HOST_GS_BASE = 0x00006c08,                  // ���� GS ��ַ
    HOST_TR_BASE = 0x00006c0a,                  // ���� TR ��ַ
    HOST_GDTR_BASE = 0x00006c0c,                // ���� GDTR ��ַ
    HOST_IDTR_BASE = 0x00006c0e,                // ���� IDTR ��ַ
    HOST_IA32_SYSENTER_ESP = 0x00006c10,        // ���� IA32_SYSENTER_ESP
    HOST_IA32_SYSENTER_EIP = 0x00006c12,        // ���� IA32_SYSENTER_EIP
    HOST_RSP = 0x00006c14,                      // ���� RSP
    HOST_RIP = 0x00006c16                       // ���� RIP
} VMCS_ENCODING;


/*****************************************************
 * ��������VmcsRead
 * ���ܣ���ȡ VMCS ָ���ֶε�ֵ
 * ������
 *    VmcsFieldId - VMCS �ֶα��루size_t ���ͣ�
 * ���أ�
 *    �ֶ�ֵ��size_t ���ͣ�
 * ��ע��
 *    ʹ�� Intel �ڲ�ָ�� __vmx_vmread ʵ�֡��ú������ڴӵ�ǰ VMCS �ж�ȡָ���ֶε�ֵ��
 *    ��Ҫ���� VT-x ���⻯�����¶������״̬�Ϳ����ֶν��з��ʡ�
*****************************************************/
inline size_t VmcsRead(IN size_t VmcsFieldId)
{
    size_t FieldData = 0;      // ���ڴ洢��ȡ�����ֶ�ֵ
    __vmx_vmread(VmcsFieldId, &FieldData); // ���õײ�ָ���ȡ�ֶ�
    return FieldData;             // �����ֶ�ֵ
}