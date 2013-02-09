bits 16
cpu 386

        ; org 0x100

segment stack stack class=stack
                resb 0x200
stacktop:       
            
segment code

..start:        mov ax, data
                mov ds, ax
                mov ax, stack
                mov ss, ax
                mov sp, stacktop

                mov dx, rmodestr
                xor cl, cl
                mov eax, cr0
                and eax, 1
                setz cl
                jz .output
.pmode:         mov dx, pmodestr
.output:        mov ah, 0x09
                int 0x21

exitdos:        mov ah, 0x4c
                mov al, cl
                int 0x21

segment data

pmodestr:       db      'Running in Protected Mode.$'
rmodestr:       db      'Running in Real Mode.$'
