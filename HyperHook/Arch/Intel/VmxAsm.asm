;*****************************************************
; �ļ���VmxAsm.asm
; ���ܣ�VMX��ػ�ຯ��ʵ��
; ���ߣ�HyperHook Team
; �汾��2.0
; ˵����ʵ��VMX�����ĵײ������
;*****************************************************

.code

;*****************************************************
; ���ܣ�VM�˳����������ڵ�
; �������ޣ�ͨ����ջ�ͼĴ������ݣ�
; ���أ���
; ��ע�����ʵ�ֵ�VM�˳��������
;*****************************************************
VmxVmExitHandler PROC
    ; ��������ͨ�üĴ���
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; ����μĴ���
    mov ax, es
    push rax
    mov ax, ds
    push rax
    mov ax, fs
    push rax
    mov ax, gs
    push rax
    
    ; ���������μĴ���
    mov ax, 10h     ; ���ݶ�ѡ����
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; ΪC��������׼����ջ����
    sub rsp, 28h    ; ����Լ��Ҫ���Ӱ�ӿռ�
    
    ; ��ȡ��ǰVCPUָ�루�洢��GS�λ�ַ�У�
    mov rcx, gs:[0] ; VCPUָ����Ϊ��һ������
    
    ; ����C���Ե�VM�˳�������
    call VmExitMainHandler
    
    ; �ָ���ջ
    add rsp, 28h
    
    ; ��鷵��ֵ�������Ƿ�������⻯
    test al, al
    jz vm_exit_terminate
    
    ; �ָ��μĴ���
    pop rax
    mov gs, ax
    pop rax
    mov fs, ax
    pop rax
    mov ds, ax
    pop rax
    mov es, ax
    
    ; �ָ�ͨ�üĴ���
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    
    ; �ָ������ִ��
    vmresume
    
    ; ���vmresumeʧ�ܣ�����vmlaunch
    vmlaunch
    
    ; �����ʧ�ܣ���ת��������
    jmp vm_exit_error

vm_exit_terminate:
    ; ��ֹ���⻯���ָ�����״̬
    ; �ָ��μĴ���
    pop rax
    mov gs, ax
    pop rax
    mov fs, ax
    pop rax
    mov ds, ax
    pop rax
    mov es, ax
    
    ; �ָ�ͨ�üĴ���
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    
    ; �ر�VMX
    vmxoff
    
    ; �ָ�ԭʼRFLAGS
    pushfq
    pop rax
    or rax, 200h    ; ����IFλ
    push rax
    popfq
    
    ; ��ת��ԭʼ�������ִ��
    ret

vm_exit_error:
    ; VM�˳�������
    ; ����Ӧ�ý��д���ָ���ϵͳ����
    int 3           ; ���Զϵ�
    hlt             ; ͣ��
    jmp vm_exit_error

VmxVmExitHandler ENDP

;*****************************************************
; ���ܣ���������״̬
; ������rcx = ����״̬�ṹָ��
; ���أ���
; ��ע����������CPU״̬���ṹ��
;*****************************************************
VmxSaveHostState PROC
    ; ����ͨ�üĴ���
    mov [rcx + 00h], rax
    mov [rcx + 08h], rbx
    mov [rcx + 10h], rdx
    mov [rcx + 18h], rsi
    mov [rcx + 20h], rdi
    mov [rcx + 28h], rbp
    mov [rcx + 30h], r8
    mov [rcx + 38h], r9
    mov [rcx + 40h], r10
    mov [rcx + 48h], r11
    mov [rcx + 50h], r12
    mov [rcx + 58h], r13
    mov [rcx + 60h], r14
    mov [rcx + 68h], r15
    
    ; ������ƼĴ���
    mov rax, cr0
    mov [rcx + 70h], rax
    mov rax, cr3
    mov [rcx + 78h], rax
    mov rax, cr4
    mov [rcx + 80h], rax
    
    ; �����־�Ĵ���
    pushfq
    pop rax
    mov [rcx + 88h], rax
    
    ; ����μĴ���
    mov ax, cs
    mov [rcx + 90h], ax
    mov ax, ds
    mov [rcx + 92h], ax
    mov ax, es
    mov [rcx + 94h], ax
    mov ax, fs
    mov [rcx + 96h], ax
    mov ax, gs
    mov [rcx + 98h], ax
    mov ax, ss
    mov [rcx + 9Ah], ax
    
    ret
VmxSaveHostState ENDP

;*****************************************************
; ���ܣ��ָ�����״̬
; ������rcx = ����״̬�ṹָ��
; ���أ���
; ��ע���ӽṹ�ָ�����CPU״̬
;*****************************************************
VmxRestoreHostState PROC
    ; �ָ��μĴ���
    mov ax, [rcx + 92h]
    mov ds, ax
    mov ax, [rcx + 94h]
    mov es, ax
    mov ax, [rcx + 96h]
    mov fs, ax
    mov ax, [rcx + 98h]
    mov gs, ax
    mov ax, [rcx + 9Ah]
    mov ss, ax
    
    ; �ָ����ƼĴ���
    mov rax, [rcx + 70h]
    mov cr0, rax
    mov rax, [rcx + 78h]
    mov cr3, rax
    mov rax, [rcx + 80h]
    mov cr4, rax
    
    ; �ָ���־�Ĵ���
    mov rax, [rcx + 88h]
    push rax
    popfq
    
    ; �ָ�ͨ�üĴ���
    mov rax, [rcx + 00h]
    mov rbx, [rcx + 08h]
    mov rdx, [rcx + 10h]
    mov rsi, [rcx + 18h]
    mov rdi, [rcx + 20h]
    mov rbp, [rcx + 28h]
    mov r8,  [rcx + 30h]
    mov r9,  [rcx + 38h]
    mov r10, [rcx + 40h]
    mov r11, [rcx + 48h]
    mov r12, [rcx + 50h]
    mov r13, [rcx + 58h]
    mov r14, [rcx + 60h]
    mov r15, [rcx + 68h]
    
    ret
VmxRestoreHostState ENDP

;*****************************************************
; ���ܣ���ȡ��������
; ������rcx = ��ѡ����, rdx = ���������
; ���أ���
; ��ע����ȡָ����ѡ��������������Ϣ
;*****************************************************
VmxGetSegmentDescriptor PROC
    ; ����Ĵ���
    push rax
    push rbx
    push rcx
    push rdx
    
    ; ��ȡGDT��Ϣ
    sub rsp, 10
    sgdt [rsp]
    
    ; ������������ַ
    mov rax, [rsp + 2]      ; GDT����ַ
    and rcx, 0FFF8h         ; ���RPL��TIλ
    add rax, rcx            ; ��������ַ
    
    ; ��ȡ������
    mov rbx, [rax]          ; ��8�ֽ�
    mov [rdx], rbx
    mov rbx, [rax + 8]      ; ��8�ֽ�
    mov [rdx + 8], rbx
    
    ; �ָ���ջ�ͼĴ���
    add rsp, 10
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ret
VmxGetSegmentDescriptor ENDP

;*****************************************************
; ���ܣ�ˢ��TLB
; ��������
; ���أ���
; ��ע��ˢ�´�����TLB
;*****************************************************
VmxFlushTlb PROC
    mov rax, cr3
    mov cr3, rax
    ret
VmxFlushTlb ENDP

;*****************************************************
; ���ܣ���Ч��ָ��ҳ��
; ������rcx = �����ַ
; ���أ���
; ��ע����Ч��ָ�������ַ��TLB��Ŀ
;*****************************************************
VmxInvalidatePage PROC
    invlpg [rcx]
    ret
VmxInvalidatePage ENDP

;*****************************************************
; ���ܣ���ȡ��ǰ������ID
; ��������
; ���أ�rax = ������ID
; ��ע����ȡ��ǰ�߼�������ID
;*****************************************************
VmxGetCurrentProcessorId PROC
    mov eax, 1
    cpuid
    shr ebx, 24
    movzx rax, bl
    ret
VmxGetCurrentProcessorId ENDP

;*****************************************************
; ���ܣ�ִ��CPUIDָ��
; ������rcx = EAX����ֵ, rdx = ECX����ֵ, r8 = ���������
; ���أ���
; ��ע��ִ��CPUID�����ؽ��
;*****************************************************
VmxExecuteCpuid PROC
    push rbx
    push rdi
    
    mov eax, ecx        ; EAX = ���ܺ�
    mov ecx, edx        ; ECX = �ӹ��ܺ�
    mov rdi, r8         ; ���������
    
    cpuid
    
    mov [rdi], eax      ; �洢EAX
    mov [rdi + 4], ebx  ; �洢EBX
    mov [rdi + 8], ecx  ; �洢ECX
    mov [rdi + 12], edx ; �洢EDX
    
    pop rdi
    pop rbx
    ret
VmxExecuteCpuid ENDP

;*****************************************************
; ���ܣ���ȡʱ���������
; ��������
; ���أ�rax = TSCֵ
; ��ע����ȡ������ʱ���������
;*****************************************************
VmxReadTsc PROC
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
VmxReadTsc ENDP

;*****************************************************
; ���ܣ���ȡʱ����������ʹ�����ID
; ������rcx = ���AUXֵ�ĵ�ַ
; ���أ�rax = TSCֵ
; ��ע����ȡTSC�ʹ�����ID
;*****************************************************
VmxReadTscp PROC
    rdtscp
    mov [rcx], ecx      ; �洢AUXֵ��������ID��
    shl rdx, 32
    or rax, rdx
    ret
VmxReadTscp ENDP

;*****************************************************
; ���ܣ�ϵͳ����Hook�������
; �������ޣ���ϵͳ����Լ����
; ���أ���
; ��ע������ϵͳ���õĻ�ദ�����
;*****************************************************
SheSystemCallHookHandlerAsm PROC
    ; �������мĴ���
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; ����ϵͳ���úţ���RAX�У�
    mov r12, rax
    
    ; ׼����������
    sub rsp, 40h        ; Ϊ�����������ռ�
    mov [rsp], rcx      ; ����1
    mov [rsp + 8], rdx  ; ����2
    mov [rsp + 16], r8  ; ����3
    mov [rsp + 24], r9  ; ����4
    mov rax, [rsp + 108h] ; �Ӷ�ջ��ȡ����5�������ѱ���ļĴ�����
    mov [rsp + 32], rax
    
    ; ����C��������ϵͳ����
    mov rcx, r12        ; ϵͳ���ú�
    mov rdx, rsp        ; ��������
    mov r8, 5           ; ��������
    call SheDispatchSystemCall
    
    ; ���淵��ֵ
    mov r12, rax
    
    ; �ָ���ջ
    add rsp, 40h
    
    ; �ָ��Ĵ���������RAX������������ֵ��
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax             ; ����ԭʼRAX
    
    ; ���÷���ֵ
    mov rax, r12
    
    ; ���ص��û�ģʽ
    sysret
    
SheSystemCallHookHandlerAsm ENDP

END