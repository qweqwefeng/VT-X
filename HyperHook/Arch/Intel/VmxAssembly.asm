extern VmxExitHandler:proc
extern RtlCaptureContext:proc

.CODE

;/*****************************************************
; * ��������VmRestoreContext
; * ���ܣ��� CONTEXT �ṹ�ָ� CPU �Ĵ���״̬
; * ������rcx - ָ�� CONTEXT �ṹ���ָ��
; * ���أ��ޣ�ͨ�� iretq ��ת���ָ���� RIP��
; * ��ע������ RtlCaptureContext������ RtlRestoreContext ���µ�����
;*****************************************************/
VmRestoreContext PROC
    push rbp
    push rsi
    push rdi
    sub rsp, 30h
    mov rbp, rsp

    ; �ָ� XMM �Ĵ���
    movaps  xmm0, xmmword ptr [rcx+1A0h]
    movaps  xmm1, xmmword ptr [rcx+1B0h]
    movaps  xmm2, xmmword ptr [rcx+1C0h]
    movaps  xmm3, xmmword ptr [rcx+1D0h]
    movaps  xmm4, xmmword ptr [rcx+1E0h]
    movaps  xmm5, xmmword ptr [rcx+1F0h]
    movaps  xmm6, xmmword ptr [rcx+200h]
    movaps  xmm7, xmmword ptr [rcx+210h]
    movaps  xmm8, xmmword ptr [rcx+220h]
    movaps  xmm9, xmmword ptr [rcx+230h]
    movaps  xmm10, xmmword ptr [rcx+240h]
    movaps  xmm11, xmmword ptr [rcx+250h]
    movaps  xmm12, xmmword ptr [rcx+260h]
    movaps  xmm13, xmmword ptr [rcx+270h]
    movaps  xmm14, xmmword ptr [rcx+280h]
    movaps  xmm15, xmmword ptr [rcx+290h]
    ldmxcsr dword ptr [rcx+34h]

    ; �ָ��μĴ��������ƼĴ���
    mov     ax, [rcx+42h]            ; �ָ� CS
    mov     [rsp+20h], ax
    mov     rax, [rcx+98h]           ; �ָ� RSP
    mov     [rsp+18h], rax
    mov     eax, [rcx+44h]           ; �ָ� EFLAGS
    mov     [rsp+10h], eax
    mov     ax, [rcx+38h]            ; �ָ� SS
    mov     [rsp+08h], ax
    mov     rax, [rcx+0F8h]          ; �ָ� RIP
    mov     [rsp+00h], rax           ; ����Ϊ���ص�ַ

    ; �ָ�ͨ�üĴ���
    mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]
    cli                             ; �ر��ж�
    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]
    mov     rcx, [rcx+80h]
    iretq                           ; ��ת���ָ���� RIP
VmRestoreContext ENDP

;/*****************************************************
; * ��������VmxVMEntry
; * ���ܣ����浱ǰ CPU �����Ĳ���ת�� VM �˳�������
; * �������ޣ�ʹ�� RCX ���������ģ�
; * ���أ��ޣ���ת�� VmxExitHandler��
; * ��ע������ RtlCaptureContext�������� VM �˳�����
;*****************************************************/
VmxVMEntry PROC
    push    rcx                         ; ���� RCX
    lea     rcx, [rsp+8h]               ; ��ȡ��ǰջ�ϵ�������ָ��
    call    RtlCaptureContext           ; ����ǰ�Ĵ���״̬
    ; RtlCaptureContext ������Ⱦ RCX
    jmp     VmxExitHandler             ; ��ת�� C ���봦��
VmxVMEntry ENDP

;/*****************************************************
; * ��������VmxVMCleanup
; * ���ܣ��ָ��μĴ���
; * ������
; *   cx - DS/ES ֵ
; *   dx - FS ֵ
; * ���أ���
;*****************************************************/
VmxVMCleanup PROC
    mov     ds, cx              ; �ָ� DS
    mov     es, cx              ; �ָ� ES
    mov     fs, dx              ; �ָ� FS
    ret
VmxVMCleanup ENDP

;/*****************************************************
; * ��������VmxResume
; * ���ܣ�ִ�� VMX resume ָ��
; * ��������
; * ���أ���
;*****************************************************/
VmxResume PROC 
    vmresume
    ret
VmxResume ENDP

;/*****************************************************
; * ��������__vmx_vmcall
; * ���ܣ�ִ�� VMX VMCALL ָ��
; * ��������
; * ���أ���
;*****************************************************/
__vmx_vmcall PROC
    vmcall
    ret
__vmx_vmcall ENDP

;/*****************************************************
; * ��������__invept
; * ���ܣ�ִ�� INVEPT ָ���Ч�� EPT ���棩
; * ������
; *   rcx - ����
; *   rdx - ָ����������ָ��
; * ���أ���
;*****************************************************/
__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

;/*****************************************************
; * ��������__invvpid
; * ���ܣ�ִ�� INVVPID ָ���Ч�� VPID ӳ�仺�棩
; * ������
; *   rcx - ����
; *   rdx - ָ����������ָ��
; * ���أ���
;*****************************************************/
__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

END