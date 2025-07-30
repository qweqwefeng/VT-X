#pragma once
#include <ntdef.h>
#include <intrin.h>

/*****************************************************
 * ���ܣ�Intel VT-x VMCS�ֶα���ö�ٶ���
 * ��ע����ѭIntel�ֲ�淶��Windows/Google����Լ��
 *      �ֶα��밴λ��͹��ܷ�����֯
*****************************************************/
typedef enum _VMCS_FIELD_ENCODING
{
	// ===================== 16λ�����ֶΣ�16-Bit Control Fields�� =====================
	VMCS_CTRL_VPID = 0x0000,                                          // ���⴦������ʶ�� (Virtual Processor ID)
	VMCS_CTRL_POSTED_INTERRUPTION_NOTIFICATION_VECTOR = 0x0002,               // Posted�ж�֪ͨ����
	VMCS_CTRL_EPTP_INDEX = 0x0004,                                    // ��չҳ��ָ������ (Extended Page Table Pointer Index)

	// ===================== 16λ�ͻ���״̬�ֶΣ�16-Bit Guest State Fields�� =====================
	VMCS_GUEST_ES_SELECTOR = 0x0800,                                  // �ͻ���ES��ѡ����
	VMCS_GUEST_CS_SELECTOR = 0x0802,                                  // �ͻ���CS��ѡ����
	VMCS_GUEST_SS_SELECTOR = 0x0804,                                  // �ͻ���SS��ѡ����
	VMCS_GUEST_DS_SELECTOR = 0x0806,                                  // �ͻ���DS��ѡ����
	VMCS_GUEST_FS_SELECTOR = 0x0808,                                  // �ͻ���FS��ѡ����
	VMCS_GUEST_GS_SELECTOR = 0x080A,                                  // �ͻ���GS��ѡ����
	VMCS_GUEST_LDTR_SELECTOR = 0x080C,                                // �ͻ����ֲ���������Ĵ���ѡ����
	VMCS_GUEST_TR_SELECTOR = 0x080E,                                  // �ͻ�������Ĵ���ѡ����
	VMCS_GUEST_INTERRUPT_STATUS = 0x0810,                             // �ͻ����ж�״̬�ֶ�
	VMCS_GUEST_PML_INDEX = 0x0812,                                    // �ͻ���ҳ�޸���־����

	// ===================== 16λ����״̬�ֶΣ�16-Bit Host State Fields�� =====================
	VMCS_HOST_ES_SELECTOR = 0x0C00,                                   // ����ES��ѡ����
	VMCS_HOST_CS_SELECTOR = 0x0C02,                                   // ����CS��ѡ����
	VMCS_HOST_SS_SELECTOR = 0x0C04,                                   // ����SS��ѡ����
	VMCS_HOST_DS_SELECTOR = 0x0C06,                                   // ����DS��ѡ����
	VMCS_HOST_FS_SELECTOR = 0x0C08,                                   // ����FS��ѡ����
	VMCS_HOST_GS_SELECTOR = 0x0C0A,                                   // ����GS��ѡ����
	VMCS_HOST_TR_SELECTOR = 0x0C0C,                                   // ��������Ĵ���ѡ����

	// ===================== 64λ�����ֶΣ�64-Bit Control Fields�� =====================
	VMCS_CTRL_IO_BITMAP_A_ADDR = 0x2000,                              // I/OλͼA�����ַ����32λ��
	VMCS_CTRL_IO_BITMAP_A_ADDR_HIGH = 0x2001,                         // I/OλͼA�����ַ����32λ��
	VMCS_CTRL_IO_BITMAP_B_ADDR = 0x2002,                              // I/OλͼB�����ַ����32λ��
	VMCS_CTRL_IO_BITMAP_B_ADDR_HIGH = 0x2003,                         // I/OλͼB�����ַ����32λ��
	VMCS_CTRL_MSR_BITMAP_ADDR = 0x2004,                               // MSRλͼ�����ַ����32λ��
	VMCS_CTRL_MSR_BITMAP_ADDR_HIGH = 0x2005,                          // MSRλͼ�����ַ����32λ��
	VMCS_CTRL_VMEXIT_MSR_STORE_ADDR = 0x2006,                         // VM�˳�MSR�洢����ַ����32λ��
	VMCS_CTRL_VMEXIT_MSR_STORE_ADDR_HIGH = 0x2007,                    // VM�˳�MSR�洢����ַ����32λ��
	VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR = 0x2008,                          // VM�˳�MSR��������ַ����32λ��
	VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR_HIGH = 0x2009,                     // VM�˳�MSR��������ַ����32λ��
	VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR = 0x200A,                         // VM����MSR��������ַ����32λ��
	VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR_HIGH = 0x200B,                    // VM����MSR��������ַ����32λ��
	VMCS_CTRL_EXECUTIVE_VMCS_PTR = 0x200C,                            // ִ��VMCSָ�루��32λ��
	VMCS_CTRL_EXECUTIVE_VMCS_PTR_HIGH = 0x200D,                       // ִ��VMCSָ�루��32λ��
	VMCS_CTRL_PML_ADDR = 0x200E,                                      // ҳ�޸���־��ַ����32λ��
	VMCS_CTRL_PML_ADDR_HIGH = 0x200F,                                 // ҳ�޸���־��ַ����32λ��
	VMCS_CTRL_TSC_OFFSET = 0x2010,                                    // ʱ���������ƫ�ƣ���32λ��
	VMCS_CTRL_TSC_OFFSET_HIGH = 0x2011,                               // ʱ���������ƫ�ƣ���32λ��
	VMCS_CTRL_VIRTUAL_APIC_PAGE_ADDR = 0x2012,                        // ����APICҳ���ַ����32λ��
	VMCS_CTRL_VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x2013,                   // ����APICҳ���ַ����32λ��
	VMCS_CTRL_APIC_ACCESS_ADDR = 0x2014,                              // APIC����ҳ���ַ����32λ��
	VMCS_CTRL_APIC_ACCESS_ADDR_HIGH = 0x2015,                         // APIC����ҳ���ַ����32λ��
	VMCS_CTRL_POSTED_INTERRUPTION_DESC_ADDR = 0x2016,                 // Posted�ж���������ַ����32λ��
	VMCS_CTRL_POSTED_INTERRUPTION_DESC_ADDR_HIGH = 0x2017,            // Posted�ж���������ַ����32λ��
	VMCS_CTRL_VM_FUNCTION_CONTROLS = 0x2018,                          // VM���ܿ����ֶΣ���32λ��
	VMCS_CTRL_VM_FUNCTION_CONTROLS_HIGH = 0x2019,                     // VM���ܿ����ֶΣ���32λ��
	VMCS_CTRL_EPT_PTR = 0x201A,                                       // ��չҳ��ָ�루��32λ��
	VMCS_CTRL_EPT_PTR_HIGH = 0x201B,                                  // ��չҳ��ָ�루��32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_0 = 0x201C,                             // EOI�˳�λͼ0����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_0_HIGH = 0x201D,                        // EOI�˳�λͼ0����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_1 = 0x201E,                             // EOI�˳�λͼ1����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_1_HIGH = 0x201F,                        // EOI�˳�λͼ1����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_2 = 0x2020,                             // EOI�˳�λͼ2����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_2_HIGH = 0x2021,                        // EOI�˳�λͼ2����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_3 = 0x2022,                             // EOI�˳�λͼ3����32λ��
	VMCS_CTRL_EOI_EXIT_BITMAP_3_HIGH = 0x2023,                        // EOI�˳�λͼ3����32λ��
	VMCS_CTRL_EPTP_LIST_ADDR = 0x2024,                                // EPTP�б��ַ����32λ��
	VMCS_CTRL_EPTP_LIST_ADDR_HIGH = 0x2025,                           // EPTP�б��ַ����32λ��
	VMCS_CTRL_VMREAD_BITMAP_ADDR = 0x2026,                            // VMREADλͼ��ַ����32λ��
	VMCS_CTRL_VMREAD_BITMAP_ADDR_HIGH = 0x2027,                       // VMREADλͼ��ַ����32λ��
	VMCS_CTRL_VMWRITE_BITMAP_ADDR = 0x2028,                           // VMWRITEλͼ��ַ����32λ��
	VMCS_CTRL_VMWRITE_BITMAP_ADDR_HIGH = 0x2029,                      // VMWRITEλͼ��ַ����32λ��
	VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR = 0x202A,                      // ���⻯�쳣��Ϣ��ַ����32λ��
	VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR_HIGH = 0x202B,                 // ���⻯�쳣��Ϣ��ַ����32λ��
	VMCS_CTRL_XSS_EXITING_BITMAP = 0x202C,                            // XSS�˳�λͼ����32λ��
	VMCS_CTRL_XSS_EXITING_BITMAP_HIGH = 0x202D,                       // XSS�˳�λͼ����32λ��
	VMCS_CTRL_ENCLS_EXITING_BITMAP = 0x202E,                          // ENCLS�˳�λͼ����32λ��
	VMCS_CTRL_ENCLS_EXITING_BITMAP_HIGH = 0x202F,                     // ENCLS�˳�λͼ����32λ��
	VMCS_CTRL_SPP_TABLE_PTR = 0x2030,                                 // ��ҳȨ�ޱ�ָ�루��32λ��
	VMCS_CTRL_SPP_TABLE_PTR_HIGH = 0x2031,                            // ��ҳȨ�ޱ�ָ�루��32λ��
	VMCS_CTRL_TSC_MULTIPLIER = 0x2032,                                // TSC��������32λ��
	VMCS_CTRL_TSC_MULTIPLIER_HIGH = 0x2033,                           // TSC��������32λ��

	// ===================== 64λֻ�������ֶΣ�64-Bit Read-Only Data Fields�� =====================
	VMCS_GUEST_PHYSICAL_ADDR = 0x2400,                                // �ͻ��������ַ����32λ��
	VMCS_GUEST_PHYSICAL_ADDR_HIGH = 0x2401,                           // �ͻ��������ַ����32λ��

	// ===================== 64λ�ͻ���״̬�ֶΣ�64-Bit Guest State Fields�� =====================
	VMCS_GUEST_VMCS_LINK_PTR = 0x2800,                                // VMCS����ָ�루��32λ��
	VMCS_GUEST_VMCS_LINK_PTR_HIGH = 0x2801,                           // VMCS����ָ�루��32λ��
	VMCS_GUEST_IA32_DEBUGCTL = 0x2802,                                // �ͻ���IA32_DEBUGCTL MSR����32λ��
	VMCS_GUEST_IA32_DEBUGCTL_HIGH = 0x2803,                           // �ͻ���IA32_DEBUGCTL MSR����32λ��
	VMCS_GUEST_IA32_PAT = 0x2804,                                     // �ͻ���IA32_PAT MSR����32λ��
	VMCS_GUEST_IA32_PAT_HIGH = 0x2805,                                // �ͻ���IA32_PAT MSR����32λ��
	VMCS_GUEST_IA32_EFER = 0x2806,                                    // �ͻ���IA32_EFER MSR����32λ��
	VMCS_GUEST_IA32_EFER_HIGH = 0x2807,                               // �ͻ���IA32_EFER MSR����32λ��
	VMCS_GUEST_IA32_PERF_GLOBAL_CTRL = 0x2808,                        // �ͻ���IA32_PERF_GLOBAL_CTRL MSR����32λ��
	VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x2809,                   // �ͻ���IA32_PERF_GLOBAL_CTRL MSR����32λ��
	VMCS_GUEST_PDPTE0 = 0x280A,                                       // �ͻ���ҳĿ¼ָ�����0����32λ��
	VMCS_GUEST_PDPTE0_HIGH = 0x280B,                                  // �ͻ���ҳĿ¼ָ�����0����32λ��
	VMCS_GUEST_PDPTE1 = 0x280C,                                       // �ͻ���ҳĿ¼ָ�����1����32λ��
	VMCS_GUEST_PDPTE1_HIGH = 0x280D,                                  // �ͻ���ҳĿ¼ָ�����1����32λ��
	VMCS_GUEST_PDPTE2 = 0x280E,                                       // �ͻ���ҳĿ¼ָ�����2����32λ��
	VMCS_GUEST_PDPTE2_HIGH = 0x280F,                                  // �ͻ���ҳĿ¼ָ�����2����32λ��
	VMCS_GUEST_PDPTE3 = 0x2810,                                       // �ͻ���ҳĿ¼ָ�����3����32λ��
	VMCS_GUEST_PDPTE3_HIGH = 0x2811,                                  // �ͻ���ҳĿ¼ָ�����3����32λ��
	VMCS_GUEST_IA32_BNDCFGS = 0x2812,                                 // �ͻ���IA32_BNDCFGS MSR����32λ��
	VMCS_GUEST_IA32_BNDCFGS_HIGH = 0x2813,                            // �ͻ���IA32_BNDCFGS MSR����32λ��
	VMCS_GUEST_IA32_RTIT_CTL = 0x2814,                                // �ͻ���IA32_RTIT_CTL MSR����32λ��
	VMCS_GUEST_IA32_RTIT_CTL_HIGH = 0x2815,                           // �ͻ���IA32_RTIT_CTL MSR����32λ��

	// ===================== 64λ����״̬�ֶΣ�64-Bit Host State Fields�� =====================
	VMCS_HOST_IA32_PAT = 0x2C00,                                      // ����IA32_PAT MSR����32λ��
	VMCS_HOST_IA32_PAT_HIGH = 0x2C01,                                 // ����IA32_PAT MSR����32λ��
	VMCS_HOST_IA32_EFER = 0x2C02,                                     // ����IA32_EFER MSR����32λ��
	VMCS_HOST_IA32_EFER_HIGH = 0x2C03,                                // ����IA32_EFER MSR����32λ��
	VMCS_HOST_IA32_PERF_GLOBAL_CTRL = 0x2C04,                         // ����IA32_PERF_GLOBAL_CTRL MSR����32λ��
	VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x2C05,                    // ����IA32_PERF_GLOBAL_CTRL MSR����32λ��

	// ===================== 32λ�����ֶΣ�32-Bit Control Fields�� =====================
	VMCS_CTRL_PIN_BASED_VM_EXEC_CONTROLS = 0x4000,                    // �������ŵ�VMִ�п���
	VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS = 0x4002,                   // ����CPU��VMִ�п���
	VMCS_CTRL_EXCEPTION_BITMAP = 0x4004,                              // �쳣λͼ
	VMCS_CTRL_PAGE_FAULT_ERROR_CODE_MASK = 0x4006,                    // ҳ�������������
	VMCS_CTRL_PAGE_FAULT_ERROR_CODE_MATCH = 0x4008,                   // ҳ���������ƥ��ֵ
	VMCS_CTRL_CR3_TARGET_COUNT = 0x400A,                              // CR3Ŀ��ֵ����
	VMCS_CTRL_VMEXIT_CONTROLS = 0x400C,                               // VM�˳�����
	VMCS_CTRL_VMEXIT_MSR_STORE_COUNT = 0x400E,                        // VM�˳�MSR�洢����
	VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT = 0x4010,                         // VM�˳�MSR���ؼ���
	VMCS_CTRL_VMENTRY_CONTROLS = 0x4012,                              // VM�������
	VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT = 0x4014,                        // VM����MSR���ؼ���
	VMCS_CTRL_VMENTRY_INTERRUPTION_INFO_FIELD = 0x4016,               // VM�����ж���Ϣ�ֶ�
	VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE = 0x4018,                  // VM�����쳣������
	VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH = 0x401A,                    // VM����ָ���
	VMCS_CTRL_TPR_THRESHOLD = 0x401C,                                 // �������ȼ��Ĵ�����ֵ
	VMCS_CTRL_SECONDARY_VM_EXEC_CONTROLS = 0x401E,                    // ����VMִ�п���
	VMCS_CTRL_PLE_GAP = 0x4020,                                       // ��ͣѭ���˳����
	VMCS_CTRL_PLE_WINDOW = 0x4022,                                    // ��ͣѭ���˳�����

	// ===================== 32λֻ�������ֶΣ�32-Bit Read-Only Data Fields�� =====================
	VMCS_VM_INSTRUCTION_ERROR = 0x4400,                               // VMָ������
	VMCS_VMEXIT_REASON = 0x4402,                                      // VM�˳�ԭ��
	VMCS_VMEXIT_INTERRUPTION_INFO = 0x4404,                           // VM�˳��ж���Ϣ
	VMCS_VMEXIT_INTERRUPTION_ERROR_CODE = 0x4406,                     // VM�˳��жϴ�����
	VMCS_VMEXIT_IDT_VECTORING_INFO = 0x4408,                          // VM�˳�IDT��������Ϣ
	VMCS_VMEXIT_IDT_VECTORING_ERROR_CODE = 0x440A,                    // VM�˳�IDT������������
	VMCS_VMEXIT_INSTRUCTION_LENGTH = 0x440C,                          // VM�˳�ָ���
	VMCS_VMEXIT_INSTRUCTION_INFO = 0x440E,                            // VM�˳�ָ����Ϣ

	// ===================== 32λ�ͻ���״̬�ֶΣ�32-Bit Guest State Fields�� =====================
	VMCS_GUEST_ES_LIMIT = 0x4800,                                     // �ͻ���ES���޳�
	VMCS_GUEST_CS_LIMIT = 0x4802,                                     // �ͻ���CS���޳�
	VMCS_GUEST_SS_LIMIT = 0x4804,                                     // �ͻ���SS���޳�
	VMCS_GUEST_DS_LIMIT = 0x4806,                                     // �ͻ���DS���޳�
	VMCS_GUEST_FS_LIMIT = 0x4808,                                     // �ͻ���FS���޳�
	VMCS_GUEST_GS_LIMIT = 0x480A,                                     // �ͻ���GS���޳�
	VMCS_GUEST_LDTR_LIMIT = 0x480C,                                   // �ͻ���LDTR���޳�
	VMCS_GUEST_TR_LIMIT = 0x480E,                                     // �ͻ���TR���޳�
	VMCS_GUEST_GDTR_LIMIT = 0x4810,                                   // �ͻ���GDTR�޳�
	VMCS_GUEST_IDTR_LIMIT = 0x4812,                                   // �ͻ���IDTR�޳�
	VMCS_GUEST_ES_ACCESS_RIGHTS = 0x4814,                             // �ͻ���ES�η���Ȩ��
	VMCS_GUEST_CS_ACCESS_RIGHTS = 0x4816,                             // �ͻ���CS�η���Ȩ��
	VMCS_GUEST_SS_ACCESS_RIGHTS = 0x4818,                             // �ͻ���SS�η���Ȩ��
	VMCS_GUEST_DS_ACCESS_RIGHTS = 0x481A,                             // �ͻ���DS�η���Ȩ��
	VMCS_GUEST_FS_ACCESS_RIGHTS = 0x481C,                             // �ͻ���FS�η���Ȩ��
	VMCS_GUEST_GS_ACCESS_RIGHTS = 0x481E,                             // �ͻ���GS�η���Ȩ��
	VMCS_GUEST_LDTR_ACCESS_RIGHTS = 0x4820,                           // �ͻ���LDTR�η���Ȩ��
	VMCS_GUEST_TR_ACCESS_RIGHTS = 0x4822,                             // �ͻ���TR�η���Ȩ��
	VMCS_GUEST_INTERRUPTIBILITY_STATE = 0x4824,                       // �ͻ����ж�����״̬
	VMCS_GUEST_ACTIVITY_STATE = 0x4826,                               // �ͻ����״̬
	VMCS_GUEST_SMBASE = 0x4828,                                       // �ͻ���ϵͳ����ģʽ��ַ
	VMCS_GUEST_IA32_SYSENTER_CS = 0x482A,                             // �ͻ���IA32_SYSENTER_CS MSR
	VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE = 0x482E,                   // �ͻ���VMX��ռ��ʱ��ֵ

	// ===================== 32λ����״̬�ֶΣ�32-Bit Host State Fields�� =====================
	VMCS_HOST_IA32_SYSENTER_CS = 0x4C00,                              // ����IA32_SYSENTER_CS MSR

	// ===================== ��Ȼ��ȿ����ֶΣ�Natural-Width Control Fields�� =====================
	VMCS_CTRL_CR0_GUEST_HOST_MASK = 0x6000,                           // CR0�ͻ���/��������
	VMCS_CTRL_CR4_GUEST_HOST_MASK = 0x6002,                           // CR4�ͻ���/��������
	VMCS_CTRL_CR0_READ_SHADOW = 0x6004,                               // CR0��ȡӰ��
	VMCS_CTRL_CR4_READ_SHADOW = 0x6006,                               // CR4��ȡӰ��
	VMCS_CTRL_CR3_TARGET_VALUE_0 = 0x6008,                            // CR3Ŀ��ֵ0
	VMCS_CTRL_CR3_TARGET_VALUE_1 = 0x600A,                            // CR3Ŀ��ֵ1
	VMCS_CTRL_CR3_TARGET_VALUE_2 = 0x600C,                            // CR3Ŀ��ֵ2
	VMCS_CTRL_CR3_TARGET_VALUE_3 = 0x600E,                            // CR3Ŀ��ֵ3

	// ===================== ��Ȼ���ֻ�������ֶΣ�Natural-Width Read-Only Data Fields�� =====================
	VMCS_VMEXIT_QUALIFICATION = 0x6400,                               // VM�˳��޶���Ϣ
	VMCS_IO_RCX = 0x6402,                                             // I/Oָ��RCX�Ĵ���ֵ
	VMCS_IO_RSI = 0x6404,                                             // I/Oָ��RSI�Ĵ���ֵ
	VMCS_IO_RDI = 0x6406,                                             // I/Oָ��RDI�Ĵ���ֵ
	VMCS_IO_RIP = 0x6408,                                             // I/Oָ��RIP�Ĵ���ֵ
	VMCS_GUEST_LINEAR_ADDR = 0x640A,                                  // �ͻ������Ե�ַ

	// ===================== ��Ȼ��ȿͻ���״̬�ֶΣ�Natural-Width Guest State Fields�� =====================
	VMCS_GUEST_CR0 = 0x6800,                                          // �ͻ���CR0���ƼĴ���
	VMCS_GUEST_CR3 = 0x6802,                                          // �ͻ���CR3���ƼĴ���
	VMCS_GUEST_CR4 = 0x6804,                                          // �ͻ���CR4���ƼĴ���
	VMCS_GUEST_ES_BASE = 0x6806,                                      // �ͻ���ES�λ�ַ
	VMCS_GUEST_CS_BASE = 0x6808,                                      // �ͻ���CS�λ�ַ
	VMCS_GUEST_SS_BASE = 0x680A,                                      // �ͻ���SS�λ�ַ
	VMCS_GUEST_DS_BASE = 0x680C,                                      // �ͻ���DS�λ�ַ
	VMCS_GUEST_FS_BASE = 0x680E,                                      // �ͻ���FS�λ�ַ
	VMCS_GUEST_GS_BASE = 0x6810,                                      // �ͻ���GS�λ�ַ
	VMCS_GUEST_LDTR_BASE = 0x6812,                                    // �ͻ���LDTR�λ�ַ
	VMCS_GUEST_TR_BASE = 0x6814,                                      // �ͻ���TR�λ�ַ
	VMCS_GUEST_GDTR_BASE = 0x6816,                                    // �ͻ���GDTR��ַ
	VMCS_GUEST_IDTR_BASE = 0x6818,                                    // �ͻ���IDTR��ַ
	VMCS_GUEST_DR7 = 0x681A,                                          // �ͻ���DR7���ԼĴ���
	VMCS_GUEST_RSP = 0x681C,                                          // �ͻ���RSPջָ��
	VMCS_GUEST_RIP = 0x681E,                                          // �ͻ���RIPָ��ָ��
	VMCS_GUEST_RFLAGS = 0x6820,                                       // �ͻ���RFLAGS��־�Ĵ���
	VMCS_GUEST_PENDING_DBG_EXCEPTIONS = 0x6822,                       // �ͻ�������ĵ����쳣
	VMCS_GUEST_IA32_SYSENTER_ESP = 0x6824,                            // �ͻ���IA32_SYSENTER_ESP MSR
	VMCS_GUEST_IA32_SYSENTER_EIP = 0x6826,                            // �ͻ���IA32_SYSENTER_EIP MSR

	// ===================== ��Ȼ�������״̬�ֶΣ�Natural-Width Host State Fields�� =====================
	VMCS_HOST_CR0 = 0x6C00,                                           // ����CR0���ƼĴ���
	VMCS_HOST_CR3 = 0x6C02,                                           // ����CR3���ƼĴ���
	VMCS_HOST_CR4 = 0x6C04,                                           // ����CR4���ƼĴ���
	VMCS_HOST_FS_BASE = 0x6C06,                                       // ����FS�λ�ַ
	VMCS_HOST_GS_BASE = 0x6C08,                                       // ����GS�λ�ַ
	VMCS_HOST_TR_BASE = 0x6C0A,                                       // ����TR�λ�ַ
	VMCS_HOST_GDTR_BASE = 0x6C0C,                                     // ����GDTR��ַ
	VMCS_HOST_IDTR_BASE = 0x6C0E,                                     // ����IDTR��ַ
	VMCS_HOST_IA32_SYSENTER_ESP = 0x6C10,                             // ����IA32_SYSENTER_ESP MSR
	VMCS_HOST_IA32_SYSENTER_EIP = 0x6C12,                             // ����IA32_SYSENTER_EIP MSR
	VMCS_HOST_RSP = 0x6C14,                                           // ����RSPջָ��
	VMCS_HOST_RIP = 0x6C16                                            // ����RIPָ��ָ��
} VMCS_FIELD_ENCODING, * PVMCS_FIELD_ENCODING;

/*****************************************************
 * ö�����ͣ�VmcsAccessType
 * ���ܣ�����VMCS�ֶεķ���ģʽ
*****************************************************/
typedef enum _VmcsAccessType
{
	VmcsAccessFull = 0,    // �������ʣ���д��
	VmcsAccessHigh = 1     // ��λ����
} VmcsAccessType;

/*****************************************************
 * ö�����ͣ�VmcsFieldType
 * ���ܣ�����VMCS�ֶ����ڵ�������
*****************************************************/
typedef enum _VmcsFieldType
{
	VmcsFieldControl = 0,  // ������
	VmcsFieldVmExit,       // VM�˳���Ϣ��
	VmcsFieldGuest,        // �ͻ�״̬��
	VmcsFieldHost          // ����״̬��
} VmcsFieldType;

/*****************************************************
 * ö�����ͣ�VmcsFieldWidth
 * ���ܣ�����VMCS�ֶε����ݿ��
*****************************************************/
typedef enum _VmcsFieldWidth
{
	VmcsFieldWidthWord = 0,      // 16λ
	VmcsFieldWidthQuadword,      // 64λ
	VmcsFieldWidthDoubleword,    // 32λ
	VmcsFieldWidthNatural        // ��Ȼ��ȣ�ƽ̨��أ�
} VmcsFieldWidth;

/*****************************************************
 * �깦�ܣ�ʹ�ø���������VMCS�ֶα���
 * ������
 *     access   - �������ͣ�VmcsAccessTypeö�٣�
 *     type     - �ֶ����ͣ�VmcsFieldTypeö�٣�
 *     width    - �ֶο�ȣ�VmcsFieldWidthö�٣�
 *     index    - �ֶ�����
 * ���أ�VMCS�ֶα��루unsigned��
 * ��ע�����뷽ʽ��ѭIntel SDM�淶
*****************************************************/
#define VMCS_ENCODE_COMPONENT(access, type, width, index) \
    ((unsigned)((unsigned short)(access) | \
                ((unsigned short)(index) << 1) | \
                ((unsigned short)(type) << 10) | \
                ((unsigned short)(width) << 13)))

/*****************************************************
 * �깦�ܣ������������ʵ�VMCS�ֶα���
 * ������
 *     type  - �ֶ�����
 *     width - �ֶο��
 *     index - �ֶ�����
 * ���أ�VMCS�ֶα��루unsigned��
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL(type, width, index) \
    VMCS_ENCODE_COMPONENT(VmcsAccessFull, type, width, index)

/*****************************************************
 * �깦�ܣ�����16λ����ֶα���
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_16(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthWord, index)

/*****************************************************
 * �깦�ܣ�����32λ����ֶα���
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_32(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthDoubleword, index)

/*****************************************************
 * �깦�ܣ�����64λ����ֶα���
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_64(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthQuadword, index)

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