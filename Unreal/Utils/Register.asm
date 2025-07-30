
.code

__readrax PROC
    mov rax, rax
    ret
__readrax ENDP

__readrbx PROC
    mov rax, rbx
    ret
__readrbx ENDP

__readrcx PROC
    mov rax, rcx
    ret
__readrcx ENDP

__readrdx PROC
    mov rax, rdx
    ret
__readrdx ENDP

__readrsi PROC
    mov rax, rsi
    ret
__readrsi ENDP

__readrdi PROC
    mov rax, rdi
    ret
__readrdi ENDP

__readrsp PROC
    mov rax, rsp
    ret
__readrsp ENDP

__readrbp PROC
    mov rax, rbp
    ret
__readrbp ENDP

__readr8 PROC
    mov rax, r8
    ret
__readr8 ENDP

__readr9 PROC
    mov rax, r9
    ret
__readr9 ENDP

__readr10 PROC
    mov rax, r10
    ret
__readr10 ENDP

__readr11 PROC
    mov rax, r11
    ret
__readr11 ENDP

__readr12 PROC
    mov rax, r12
    ret
__readr12 ENDP

__readr13 PROC
    mov rax, r13
    ret
__readr13 ENDP

__readr14 PROC
    mov rax, r14
    ret
__readr14 ENDP

__readr15 PROC
    mov rax, r15
    ret
__readr15 ENDP

__readcs PROC
    mov ax, cs
    ret
__readcs ENDP

__readds PROC
    mov ax, ds
    ret
__readds ENDP

__reades PROC
    mov ax, es
    ret
__reades ENDP

__readfs PROC
    mov ax, fs
    ret
__readfs ENDP

__readgs PROC
    mov ax, gs
    ret
__readgs ENDP

__readss PROC
    mov ax, ss
    ret
__readss ENDP

__readldtr PROC
    sldt    ax
    ret
__readldtr ENDP

__readtr PROC
    str     ax
    ret
__readtr ENDP

END