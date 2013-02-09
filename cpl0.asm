BITS 16
CPU 386

GLOBAL _cli
GLOBAL _stri
GLOBAL _sgdt
GLOBAL _lgdt
GLOBAL _sidt
GLOBAL _lidt
GLOBAL _getcr3
GLOBAL _setcr3

_cli:           cli
                retf

_sti:           sti
                retf            
               
_sgdt:          push bp
                mov bp, sp
                push ds
                mov ax, [bp+8]
                mov ds, ax
                xor eax, eax
                mov ax, [bp+6]
                sgdt [ds:eax]
                pop ds
                pop bp
                retf

_lgdt:          push bp
                mov bp, sp
                push ds
                mov ax, [bp+8]
                mov ds, ax
                xor eax, eax
                mov ax, [bp+6]
                lgdt [ds:eax]
                pop ds
                pop bp
                retf

_sidt:          push bp
                mov bp, sp
                push ds
                mov ax, [bp+8]
                mov ds, ax
                xor eax, eax
                mov ax, [bp+6]
                sidt [ds:eax]
                pop ds
                pop bp
                retf

_lidt:          push bp
                mov bp, sp
                push ds
                mov ax, [bp+8]
                mov ds, ax
                xor eax, eax
                mov ax, [bp+6]
                lidt [ds:eax]
                pop ds
                pop bp
                retf

_getcr3:        push bp
                mov bp, sp
                push ds
                push di
                mov ax, [bp+8]
                mov ds, ax
                mov di, [bp+6]
                mov eax, cr3
                mov dword [ds:di], eax
                pop di
                pop ds
                pop bp
                retf

_setcr3:        push bp
                mov bp, sp
                push ds
                push di
                mov ax, [bp+8]
                mov ds, ax
                mov di, [bp+6]
                mov eax, dword [ds:di]
                mov cr3, eax
                pop di
                pop ds
                pop bp
                retf


                
