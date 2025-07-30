#pragma once
#include "../Arch/Intel/Vmx.h"

// VMX��س�������
#define VMX_TAG							'VMXF'
#define VMX_MSR_BITMAP_SIZE             4096        // MSRλͼ��С��4KB��
#define VMX_MAX_PROCESSOR_COUNT         256         // ���֧�ִ���������
#define VMM_STACK_SIZE                  0x6000      // VMM��ջ��С


/*****************************************************
 * �ṹ��VMX_ENGINE_CONTEXT
 * ���ܣ�VMX����ȫ��������
 * ˵������������VMX���⻯�����״̬����Դ
*****************************************************/
typedef struct _VMX_ENGINE_CONTEXT
{
	// ͬ������
	KSPIN_LOCK              VmxSpinLock;            // VMX����������

	PVCPU* VcpuArray;								// VCPU����ָ��
	ULONG                   ProcessorCount;         // ����������

	// VMX��Դ
	PUCHAR                  MsrBitmap;              // MSR����λͼ
	PHYSICAL_ADDRESS        MsrBitmapPhysical;      // MSRλͼ�����ַ

} VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * �ṹ��VMX_INITIALIZATION_CONTEXT
 * ���ܣ�VMX��ʼ��ͬ��������
 * ˵�������ڶ�CPU���г�ʼ����ͬ������
*****************************************************/
typedef struct _VMX_INITIALIZATION_CONTEXT
{
	PVMX_ENGINE_CONTEXT     VmxContext;            // VMX����������
	ULONG64                 SystemCr3;             // ϵͳCR3ֵ
	volatile LONG           SuccessCount;          // �ɹ���ʼ����CPU����
	volatile LONG           FailureCount;          // ʧ�ܵ�CPU����
	NTSTATUS                Status;                // ��ʼ��״̬
	KEVENT                  CompletionEvent;       // ����¼�
	BOOLEAN                 ForceInitialization;   // ǿ�Ƴ�ʼ����־
} VMX_INITIALIZATION_CONTEXT, * PVMX_INITIALIZATION_CONTEXT;

/*****************************************************
 * ���ܣ���ʼ��VMX����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����Ӳ��֧�ֲ���ʼ��VMX����
*****************************************************/
NTSTATUS VmxInitializeEngineContext(PVMX_ENGINE_CONTEXT* ppVmxContext);

/*****************************************************
 * ���ܣ�����VMX����������
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע���ͷ�VMX������ص�������Դ
*****************************************************/
VOID VmxCleanupEngineContext(_In_opt_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * ���ܣ����VMXӲ��֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע��ȫ����CPU��BIOS��VMX��֧�����
*****************************************************/
BOOLEAN VmxCheckHardwareSupport(VOID);

/*****************************************************
 * ���ܣ�����MSRλͼ
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����䲢��ʼ��MSR���ʿ���λͼ
*****************************************************/
NTSTATUS VmxAllocateMsrBitmap(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * ���ܣ���ʼ��VMX MSRλͼ�����ùؼ�MSR����
 * ������pMsrBitmap - ָ��4KB MSRλͼ�ڴ棨��4KB���룩
 * ���أ���
 * ��ע��
 *     - ��Intel SDM�淶��Ϊ���͡����ߡ�д�͡�д��������
 *     - �ɸ�����������/�������ص�MSR
*****************************************************/
VOID VmxInitializeMsrBitmap(_In_ PUCHAR pMsrBitmap);

/*****************************************************
 * ���ܣ������д�����������VMX
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ��г�ʼ��VMX
*****************************************************/
NTSTATUS VmxStartOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * ���ܣ�VMX��ʼ��DPC����
 * ������Dpc - DPC����
 *       Context - ��ʼ��������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMX��ʼ����ʵ�ʹ���
*****************************************************/
VOID VmxInitializationDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);

/*****************************************************
 * ���ܣ������д�������ֹͣVMX
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ���ֹͣVMX
*****************************************************/
VOID VmxStopOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext);

/*****************************************************
 * ���ܣ�VMXֹͣDPC����
 * ������Dpc - DPC����
 *       Context - VMX����������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMXֹͣ����
*****************************************************/
VOID VmxStopDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);
