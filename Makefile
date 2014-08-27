ELF_CFLAGS = -m32
CFLAGS = -g -Wall -Werror -ansi -ffreestanding -std=c99
ELF_LDFLAGS = -melf_i386
LDFLAGS = 
ELFCC = /usr/local/gcc-4.8.1-for-linux64/bin/x86_64-pc-linux-gcc
ELFLD = /usr/local/gcc-4.8.1-for-linux64/bin/x86_64-pc-linux-ld
NASM = /usr/local/bin/nasm

FLOPPY = ~/VirtualBox\ VMs/vm86/vm86-floppy.img
FLOPPY_TARGETS = loadelf.c stupid elfgate.obj cpl0.obj check.obj \
	make.bat run.bat fetch.bat empty

ELF_OBJECTS = stupid.o fbsd_printf.o empty.o cpl0.o
ELF_BINARIES = stupid empty
TARGETS = loadelf stupid empty elfgate.obj

all: $(TARGETS)

%.obj: %.asm
	$(NASM) -f obj -o $@ $<

$(ELF_OBJECTS): %.o: %.c
	$(ELFCC) $(ELF_CFLAGS) $(CFLAGS) -o $@ -c $<

stupid:	stupid.o fbsd_printf.o
	$(ELFLD) $(ELF_LDFLAGS) $(LDFLAGS) -o $@ $^

empty:	empty.o
	$(ELFLD) $(ELF_LDFLAGS) $(LDFLAGS) -o $@ $^

printf.o: CFLAGS += -DPRINTF_LONG_SUPPORT

.PHONY: clean

clean:
	rm -f *.o *.obj $(TARGETS)

copysite: all $(FLOPPY_TARGETS)
	zip ~/Sites/vm86/vm86.zip $(FLOPPY_TARGETS)

copydisk: all $(FLOPPY_TARGETS)
	mformat -f 1440 -i $(FLOPPY) '::*.*'
	mcopy -o -i $(FLOPPY) $(FLOPPY_TARGETS) ::
