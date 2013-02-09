BITS 16
CPU 386

SEGMENT CODE

GLOBAL _enterpm
EXTERN _gdt
       
_enterpm:       cli
                
                push ebp
                mov ebp, esp

                sub esp, 12

                push eax
                push ebx
                push ecx
                push edx
                push esi
                push edi
                push ds
                push es
                push fs
                push gs

                ; save old stack in registers
                xor ebx, ebx
                mov bx, ss
                mov esi, esp

                ; enable protected mode and paging
                mov eax, cr0
                or eax, 0x80000001
                mov cr0, eax

                jmp short .flushin
.flushin:       nop

                ; linearize ebp into edi
                xor edi, edi
                mov di, ss
                shl edi, 4
                and ebp, dword 0xffff
                add edi, ebp

                ; load linear 4GB data segments
                mov ax, 0x08
                mov ds, ax
                mov es, ax
                mov fs, ax
                mov gs, ax
                mov ss, ax

                ; set new stack
                mov esp, [edi+12]

                ; store entry far pointer for jump
                mov eax, [edi+8]
                mov word [edi-2], 0x10
                mov dword [edi-6], eax

                ; push old stack far pointer
                push ebx         ; ss
                push esi         ; sp 

                ; push real mode epilog far pointer,
                ; needed after switch back to real mode
                push word cs
                push word _exitreal
                
                push edi
                
                ; push arguments
                push word cs            ; rendezvous CS
                push word _exitreal     ; rendezvous exit
                push dword [edi+16]     ; stack_len
                push dword [edi+12]     ; stack_end
                push dword 0xb0002000   ; magic

                ; push linearized _exitpm as return address
                mov eax, cs
                shl eax, 4
                add eax, _exitpm32
                push eax

                ; and jump into the kernel!
                jmp dword far [ds:edi-6]

                
BITS 32
_exitpm32:      nop     ; kernel returns here
                
                add esp, 4*4
                pop edi

                ; disable paging
                mov eax, cr0
                and eax, 0x7fffffff
                mov cr0, eax

                ; flush TLB
                xor eax, eax
                ; mov cr3, eax

                ; load GDT address
                sgdt [ds:edi-6]
                mov ebx, [ds:edi-4]

                ; load old real-mode CS
                xor eax, eax
                mov ax, [esp + 2]

                ; set 16bit code segment base
                mov ecx, eax
                shr ecx, 12
                shl eax, 4
                mov word [ebx+0x22], ax
                or dword [ebx+0x24], ecx

                ; set 16bit stack segment base
                mov eax, esp
                mov ecx, esp
                shr ecx, 16
                and ecx, 0xf
                mov word [ebx+0x2a], ax
                or dword [ebx+0x2c], ecx

                ; transfer to 16bit code
                push dword 0x20
                push dword _exitpm16
                retf

BITS 16            
_exitpm16:      ; load 64k-limit data segments
                mov ax, 0x18
                mov ds, ax
                mov es, ax
                mov fs, ax
                mov gs, ax

                ; load 64k-limit stack
                mov ax, 0x28
                mov ss, ax
                xor esp, esp

                ;  disable protected mode
                mov eax, cr0
                and eax, 0xfffffffe
                mov cr0, eax

                ; flush and restore old CS
                jmp word far [esp]
                
_exitreal:      ; restore old stack
                mov eax, [esp + 4]      ; sp
                mov ebx, [esp + 8]      ; ss
                xor esp, esp
                mov esp, eax
                mov ss, bx

                ; and exit.
                
                pop gs
                pop fs
                pop es
                pop ds
                pop edi
                pop esi
                pop edx
                pop ecx
                pop ebx
                pop eax                

                mov esp, ebp
                pop ebp

                sti
                retf
