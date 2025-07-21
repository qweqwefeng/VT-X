extern VmxExitHandler:proc
extern RtlCaptureContext:proc

.CODE

;/*****************************************************
; * 函数名：VmRestoreContext
; * 功能：从 CONTEXT 结构恢复 CPU 寄存器状态
; * 参数：rcx - 指向 CONTEXT 结构体的指针
; * 返回：无（通过 iretq 跳转到恢复后的 RIP）
; * 备注：兼容 RtlCaptureContext，避免 RtlRestoreContext 导致的蓝屏
;*****************************************************/
VmRestoreContext PROC
    push rbp
    push rsi
    push rdi
    sub rsp, 30h
    mov rbp, rsp

    ; 恢复 XMM 寄存器
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

    ; 恢复段寄存器及控制寄存器
    mov     ax, [rcx+42h]            ; 恢复 CS
    mov     [rsp+20h], ax
    mov     rax, [rcx+98h]           ; 恢复 RSP
    mov     [rsp+18h], rax
    mov     eax, [rcx+44h]           ; 恢复 EFLAGS
    mov     [rsp+10h], eax
    mov     ax, [rcx+38h]            ; 恢复 SS
    mov     [rsp+08h], ax
    mov     rax, [rcx+0F8h]          ; 恢复 RIP
    mov     [rsp+00h], rax           ; 设置为返回地址

    ; 恢复通用寄存器
    mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]
    cli                             ; 关闭中断
    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]
    mov     rcx, [rcx+80h]
    iretq                           ; 跳转到恢复后的 RIP
VmRestoreContext ENDP

;/*****************************************************
; * 函数名：VmxVMEntry
; * 功能：保存当前 CPU 上下文并跳转到 VM 退出处理函数
; * 参数：无（使用 RCX 传递上下文）
; * 返回：无（跳转到 VmxExitHandler）
; * 备注：兼容 RtlCaptureContext，适用于 VM 退出场景
;*****************************************************/
VmxVMEntry PROC
    push    rcx                         ; 保存 RCX
    lea     rcx, [rsp+8h]               ; 获取当前栈上的上下文指针
    call    RtlCaptureContext           ; 捕获当前寄存器状态
    ; RtlCaptureContext 不会污染 RCX
    jmp     VmxExitHandler             ; 跳转到 C 代码处理
VmxVMEntry ENDP

;/*****************************************************
; * 函数名：VmxVMCleanup
; * 功能：恢复段寄存器
; * 参数：
; *   cx - DS/ES 值
; *   dx - FS 值
; * 返回：无
;*****************************************************/
VmxVMCleanup PROC
    mov     ds, cx              ; 恢复 DS
    mov     es, cx              ; 恢复 ES
    mov     fs, dx              ; 恢复 FS
    ret
VmxVMCleanup ENDP

;/*****************************************************
; * 函数名：VmxResume
; * 功能：执行 VMX resume 指令
; * 参数：无
; * 返回：无
;*****************************************************/
VmxResume PROC 
    vmresume
    ret
VmxResume ENDP

;/*****************************************************
; * 函数名：__vmx_vmcall
; * 功能：执行 VMX VMCALL 指令
; * 参数：无
; * 返回：无
;*****************************************************/
__vmx_vmcall PROC
    vmcall
    ret
__vmx_vmcall ENDP

;/*****************************************************
; * 函数名：__invept
; * 功能：执行 INVEPT 指令（无效化 EPT 缓存）
; * 参数：
; *   rcx - 类型
; *   rdx - 指向描述符的指针
; * 返回：无
;*****************************************************/
__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

;/*****************************************************
; * 函数名：__invvpid
; * 功能：执行 INVVPID 指令（无效化 VPID 映射缓存）
; * 参数：
; *   rcx - 类型
; *   rdx - 指向描述符的指针
; * 返回：无
;*****************************************************/
__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

END