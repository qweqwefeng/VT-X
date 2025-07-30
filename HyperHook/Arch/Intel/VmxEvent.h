#pragma once
#include <ntdef.h>

/*****************************************************
 * �����壺INTERRUPT_INFO_FIELD
 * ���ܣ����� VMCS �� VM_EXIT_INTR_INFO��IDT_VECTORING_INFO �ֶνṹ
 * ��������
 * ���أ���
 * ��ע�����ڱ�ʾ���⻯�����з������жϻ��쳣��Ϣ
*****************************************************/
typedef union _INTERRUPT_INFO_FIELD
{
    ULONG32 All;  // ����λ���������
    struct
    {
        ULONG32 Vector : 8;           // �ж�/�쳣������
        ULONG32 Type : 3;             // �ж�����
        ULONG32 ErrorCodeValid : 1;   // �������Ƿ���Ч
        ULONG32 NMIUnblocking : 1;    // NMI ����
        ULONG32 Reserved : 18;        // ����λ
        ULONG32 Valid : 1;            // �Ƿ���Ч
    } Fields;
} INTERRUPT_INFO_FIELD, * PINTERRUPT_INFO_FIELD;

/*****************************************************
 * �����壺INTERRUPT_INJECT_INFO_FIELD
 * ���ܣ����� VMCS �� VM_ENTRY_INTR_INFO �ֶνṹ
 * ��������
 * ���أ���
 * ��ע�����ڱ�ʾ��ע����жϻ��쳣��Ϣ
*****************************************************/
typedef union _INTERRUPT_INJECT_INFO_FIELD
{
    ULONG32 All;  // ����λ���������
    struct
    {
        ULONG32 Vector : 8;           // �ж�/�쳣������
        ULONG32 Type : 3;             // �ж�����
        ULONG32 DeliverErrorCode : 1; // �Ƿ���Ҫ���ݴ�����
        ULONG32 Reserved : 19;        // ����λ
        ULONG32 Valid : 1;            // �Ƿ���Ч
    } Fields;
} INTERRUPT_INJECT_INFO_FIELD, * PINTERRUPT_INJECT_INFO_FIELD;

/*****************************************************
 * ö�����ͣ�INTERRUPT_TYPE
 * ���ܣ������ж����ͣ���Ӧ Intel SDM �� VMCS �ֶ����ͣ�
 * ��������
 * ���أ���
 * ��ע������ VMCS ע�뼰��������ж�/�쳣
*****************************************************/
typedef enum _INTERRUPT_TYPE
{
    INTERRUPT_EXTERNAL = 0,             // �ⲿ�ж�
    INTERRUPT_RESERVED1 = 1,            // ����
    INTERRUPT_NMI = 2,                  // NMI �ж�
    INTERRUPT_HARDWARE_EXCEPTION = 3,   // Ӳ���쳣
    INTERRUPT_SOFTWARE_INTERRUPT = 4,   // ����жϣ�INTָ�
    INTERRUPT_PRIVILEGED_EXCEPTION = 5, // ��Ȩ�쳣
    INTERRUPT_SOFTWARE_EXCEPTION = 6,   // ����쳣
    INTERRUPT_OTHER_EVENT = 7           // �����¼�
} INTERRUPT_TYPE;

/*****************************************************
 * ö�����ͣ�VECTOR_EXCEPTION
 * ���ܣ����峣���쳣�������ţ�IDT ������
 * ��������
 * ���أ���
 * ��ע������ VMCS �쳣ע�뼰����
*****************************************************/
typedef enum _VECTOR_EXCEPTION
{
    VECTOR_DIVIDE_ERROR_EXCEPTION = 0,          // #DE �������
    VECTOR_DEBUG_EXCEPTION = 1,                 // #DB �����쳣
    VECTOR_NMI_INTERRUPT = 2,                   // NMI �ж�
    VECTOR_BREAKPOINT_EXCEPTION = 3,            // #BP �ϵ��쳣
    VECTOR_OVERFLOW_EXCEPTION = 4,              // #OF ����쳣
    VECTOR_BOUND_EXCEPTION = 5,                 // #BR ��Χ����쳣
    VECTOR_INVALID_OPCODE_EXCEPTION = 6,        // #UD ��Ч������
    VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION = 7,  // #NM �豸������
    VECTOR_DOUBLE_FAULT_EXCEPTION = 8,          // #DF ˫�ع���
    VECTOR_COPROCESSOR_SEGMENT_OVERRUN = 9,     // Э�������γ���
    VECTOR_INVALID_TSS_EXCEPTION = 10,          // #TS ��Ч TSS
    VECTOR_SEGMENT_NOT_PRESENT = 11,            // #NP �β�����
    VECTOR_STACK_FAULT_EXCEPTION = 12,          // #SS ��ջ����
    VECTOR_GENERAL_PROTECTION_EXCEPTION = 13,   // #GP һ�㱣���쳣
    VECTOR_PAGE_FAULT_EXCEPTION = 14,           // #PF ҳ����
    VECTOR_X87_FLOATING_POINT_ERROR = 16,       // #MF x87 �������
    VECTOR_ALIGNMENT_CHECK_EXCEPTION = 17,      // #AC ������
    VECTOR_MACHINE_CHECK_EXCEPTION = 18,        // #MC �������
    VECTOR_SIMD_FLOATING_POINT_EXCEPTION = 19,  // #XM SIMD �����쳣
    VECTOR_VIRTUALIZATION_EXCEPTION = 20        // ���⻯�쳣
} VECTOR_EXCEPTION;

/*****************************************************
 * ��������VmxInjectEvent
 * ���ܣ��� Guest ע���жϻ��쳣�¼�
 * ������
 *    InterruptType - �ж����ͣ�INTERRUPT_TYPE ö�٣�
 *    Vector        - �ж�/�쳣�����ţ�VECTOR_EXCEPTION ö�٣�
 *    WriteLength   - ָ��ȣ�����������Ӧָ�
 * ���أ���
 * ��ע������ VMX ���⻯������ע���¼����ͻ�����Guest��
*****************************************************/
inline VOID VmxInjectEvent(INTERRUPT_TYPE InterruptType, VECTOR_EXCEPTION Vector, ULONG WriteLength)
{
	INTERRUPT_INJECT_INFO_FIELD InjectEvent = { 0 }; // ����ע����Ϣ�ṹ�岢����

	InjectEvent.Fields.Vector = Vector;               // �����жϻ��쳣������
	InjectEvent.Fields.Type = InterruptType;          // �����ж�����
	InjectEvent.Fields.DeliverErrorCode = 0;          // �����ݴ�����
	InjectEvent.Fields.Valid = 1;                     // ���Ϊ��Ч

	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, InjectEvent.All); // д�� VMCS ע���ж���Ϣ�ֶ�
	if (WriteLength > 0)
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, WriteLength); // д��ָ��ȣ���������ָ�
}