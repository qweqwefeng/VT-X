;*****************************************************
; 文件：VmxAsm.asm
; 功能：VMX相关汇编函数实现
; 作者：HyperHook Team
; 版本：2.0
; 说明：实现VMX操作的底层汇编代码
;*****************************************************

.code

;*****************************************************
; 功能：VM退出处理程序入口点
; 参数：无（通过堆栈和寄存器传递）
; 返回：无
; 备注：汇编实现的VM退出处理程序
;*****************************************************
VmxVmExitHandler PROC
    ; 保存所有通用寄存器
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
    
    ; 保存段寄存器
    mov ax, es
    push rax
    mov ax, ds
    push rax
    mov ax, fs
    push rax
    mov ax, gs
    push rax
    
    ; 设置主机段寄存器
    mov ax, 10h     ; 数据段选择器
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; 为C函数调用准备堆栈对齐
    sub rsp, 28h    ; 调用约定要求的影子空间
    
    ; 获取当前VCPU指针（存储在GS段基址中）
    mov rcx, gs:[0] ; VCPU指针作为第一个参数
    
    ; 调用C语言的VM退出处理函数
    call VmExitMainHandler
    
    ; 恢复堆栈
    add rsp, 28h
    
    ; 检查返回值，决定是否继续虚拟化
    test al, al
    jz vm_exit_terminate
    
    ; 恢复段寄存器
    pop rax
    mov gs, ax
    pop rax
    mov fs, ax
    pop rax
    mov ds, ax
    pop rax
    mov es, ax
    
    ; 恢复通用寄存器
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
    
    ; 恢复虚拟机执行
    vmresume
    
    ; 如果vmresume失败，尝试vmlaunch
    vmlaunch
    
    ; 如果都失败，跳转到错误处理
    jmp vm_exit_error

vm_exit_terminate:
    ; 终止虚拟化，恢复主机状态
    ; 恢复段寄存器
    pop rax
    mov gs, ax
    pop rax
    mov fs, ax
    pop rax
    mov ds, ax
    pop rax
    mov es, ax
    
    ; 恢复通用寄存器
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
    
    ; 关闭VMX
    vmxoff
    
    ; 恢复原始RFLAGS
    pushfq
    pop rax
    or rax, 200h    ; 设置IF位
    push rax
    popfq
    
    ; 跳转到原始代码继续执行
    ret

vm_exit_error:
    ; VM退出错误处理
    ; 这里应该进行错误恢复或系统重启
    int 3           ; 调试断点
    hlt             ; 停机
    jmp vm_exit_error

VmxVmExitHandler ENDP

;*****************************************************
; 功能：保存主机状态
; 参数：rcx = 主机状态结构指针
; 返回：无
; 备注：保存主机CPU状态到结构中
;*****************************************************
VmxSaveHostState PROC
    ; 保存通用寄存器
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
    
    ; 保存控制寄存器
    mov rax, cr0
    mov [rcx + 70h], rax
    mov rax, cr3
    mov [rcx + 78h], rax
    mov rax, cr4
    mov [rcx + 80h], rax
    
    ; 保存标志寄存器
    pushfq
    pop rax
    mov [rcx + 88h], rax
    
    ; 保存段寄存器
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
; 功能：恢复主机状态
; 参数：rcx = 主机状态结构指针
; 返回：无
; 备注：从结构恢复主机CPU状态
;*****************************************************
VmxRestoreHostState PROC
    ; 恢复段寄存器
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
    
    ; 恢复控制寄存器
    mov rax, [rcx + 70h]
    mov cr0, rax
    mov rax, [rcx + 78h]
    mov cr3, rax
    mov rax, [rcx + 80h]
    mov cr4, rax
    
    ; 恢复标志寄存器
    mov rax, [rcx + 88h]
    push rax
    popfq
    
    ; 恢复通用寄存器
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
; 功能：获取段描述符
; 参数：rcx = 段选择器, rdx = 输出缓冲区
; 返回：无
; 备注：获取指定段选择器的描述符信息
;*****************************************************
VmxGetSegmentDescriptor PROC
    ; 保存寄存器
    push rax
    push rbx
    push rcx
    push rdx
    
    ; 获取GDT信息
    sub rsp, 10
    sgdt [rsp]
    
    ; 计算描述符地址
    mov rax, [rsp + 2]      ; GDT基地址
    and rcx, 0FFF8h         ; 清除RPL和TI位
    add rax, rcx            ; 描述符地址
    
    ; 读取描述符
    mov rbx, [rax]          ; 低8字节
    mov [rdx], rbx
    mov rbx, [rax + 8]      ; 高8字节
    mov [rdx + 8], rbx
    
    ; 恢复堆栈和寄存器
    add rsp, 10
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ret
VmxGetSegmentDescriptor ENDP

;*****************************************************
; 功能：刷新TLB
; 参数：无
; 返回：无
; 备注：刷新处理器TLB
;*****************************************************
VmxFlushTlb PROC
    mov rax, cr3
    mov cr3, rax
    ret
VmxFlushTlb ENDP

;*****************************************************
; 功能：无效化指定页面
; 参数：rcx = 虚拟地址
; 返回：无
; 备注：无效化指定虚拟地址的TLB条目
;*****************************************************
VmxInvalidatePage PROC
    invlpg [rcx]
    ret
VmxInvalidatePage ENDP

;*****************************************************
; 功能：获取当前处理器ID
; 参数：无
; 返回：rax = 处理器ID
; 备注：获取当前逻辑处理器ID
;*****************************************************
VmxGetCurrentProcessorId PROC
    mov eax, 1
    cpuid
    shr ebx, 24
    movzx rax, bl
    ret
VmxGetCurrentProcessorId ENDP

;*****************************************************
; 功能：执行CPUID指令
; 参数：rcx = EAX输入值, rdx = ECX输入值, r8 = 输出缓冲区
; 返回：无
; 备注：执行CPUID并返回结果
;*****************************************************
VmxExecuteCpuid PROC
    push rbx
    push rdi
    
    mov eax, ecx        ; EAX = 功能号
    mov ecx, edx        ; ECX = 子功能号
    mov rdi, r8         ; 输出缓冲区
    
    cpuid
    
    mov [rdi], eax      ; 存储EAX
    mov [rdi + 4], ebx  ; 存储EBX
    mov [rdi + 8], ecx  ; 存储ECX
    mov [rdi + 12], edx ; 存储EDX
    
    pop rdi
    pop rbx
    ret
VmxExecuteCpuid ENDP

;*****************************************************
; 功能：读取时间戳计数器
; 参数：无
; 返回：rax = TSC值
; 备注：读取处理器时间戳计数器
;*****************************************************
VmxReadTsc PROC
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
VmxReadTsc ENDP

;*****************************************************
; 功能：读取时间戳计数器和处理器ID
; 参数：rcx = 输出AUX值的地址
; 返回：rax = TSC值
; 备注：读取TSC和处理器ID
;*****************************************************
VmxReadTscp PROC
    rdtscp
    mov [rcx], ecx      ; 存储AUX值（处理器ID）
    shl rdx, 32
    or rax, rdx
    ret
VmxReadTscp ENDP

;*****************************************************
; 功能：系统调用Hook处理程序
; 参数：无（按系统调用约定）
; 返回：无
; 备注：拦截系统调用的汇编处理程序
;*****************************************************
SheSystemCallHookHandlerAsm PROC
    ; 保存所有寄存器
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
    
    ; 保存系统调用号（在RAX中）
    mov r12, rax
    
    ; 准备参数数组
    sub rsp, 40h        ; 为参数数组分配空间
    mov [rsp], rcx      ; 参数1
    mov [rsp + 8], rdx  ; 参数2
    mov [rsp + 16], r8  ; 参数3
    mov [rsp + 24], r9  ; 参数4
    mov rax, [rsp + 108h] ; 从堆栈获取参数5（考虑已保存的寄存器）
    mov [rsp + 32], rax
    
    ; 调用C函数处理系统调用
    mov rcx, r12        ; 系统调用号
    mov rdx, rsp        ; 参数数组
    mov r8, 5           ; 参数数量
    call SheDispatchSystemCall
    
    ; 保存返回值
    mov r12, rax
    
    ; 恢复堆栈
    add rsp, 40h
    
    ; 恢复寄存器（除了RAX，它包含返回值）
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
    pop rax             ; 丢弃原始RAX
    
    ; 设置返回值
    mov rax, r12
    
    ; 返回到用户模式
    sysret
    
SheSystemCallHookHandlerAsm ENDP

END