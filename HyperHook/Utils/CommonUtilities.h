#pragma once

#include <ntifs.h>
#include "../Definitions/SystemDefinitions.h"

/*****************************************************
 * ���ܣ�ͨ�ù��ߺ���ͷ�ļ�
 * ��ע���ṩϵͳ��ʼ����DPC���ȵ�ͨ�ù���
*****************************************************/

/*****************************************************
 * ���ܣ��������⻯DPC�ص�����
 * ������Dpc - DPC����ָ��
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU����������VMX���⻯
*****************************************************/
VOID CommonStartVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * ���ܣ�ֹͣ���⻯DPC�ص�����
 * ������Dpc - DPC����ָ��
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU������ֹͣVMX���⻯
*****************************************************/
VOID CommonStopVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);