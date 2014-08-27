#include <stdarg.h>
#include <stdint.h>

#include "fbsd_printf.h"

static char nucleus[] = "Nucleus";
char alive[] = "protected mode kernel entered.";

#define NULL ((void*)0)

#define VIRT(addr) ((uint32_t)addr)
#define MK_FP(seg, off) ((void *)((seg) << 4 | (uint32_t)(off)))
#define SEG_LIN(x) ((uint16_t)((x) >> 4))
#define SEG_OFF(x) ((uint16_t)((x) & 0xf))

register unsigned int *esp __asm__ ("esp");


/*** Paging ***/

typedef uint32_t pt_entry;

#define PSIZE           4096

#define P_DIR_MASK      0xffc00000
#define P_PAGE_MASK     0x007ff000
#define P_OFF_MASK      0x00000fff

#define P_FRAME_MASK    0xfffff000

#define PT_PRESENT      0x001
#define PT_WRITE        0x002
#define PT_USER         0x004
#define PT_ACCESS       0x020
#define PT_DIRTY        0x040

typedef uint32_t phys_addr;

static pt_entry *pdir;

void *get_cr3 (void) {
    void *cr3;
    __asm__("movl %%cr3, %0" : "=r" (cr3));
    return cr3;
}

phys_addr lookup_phys (void *vaddr) {
    uint32_t addr = (uint32_t)vaddr;
    uint32_t pd_num = (addr & P_DIR_MASK) >> 22;
    uint32_t pt_num = (addr & P_PAGE_MASK) >> 12;
    uint32_t p_off = addr & P_OFF_MASK;

    pt_entry *pt = (pt_entry*)((uint32_t)pdir[pd_num] & P_FRAME_MASK);
    pt_entry p = pt[pt_num];

    return (phys_addr)((p & P_FRAME_MASK) + p_off);
}

/*** GDT ***/

uint32_t gdt[] __attribute__((aligned(8))) = {
  0, 0,                         /* Empty */
  0x0000ffff, 0x00cf9200,       /* CPL0 4GB writable data */
  0x0000ffff, 0x00cf9a00,       /* CPL0 4GB readable code */
  0x0000ffff, 0x00009200,       /* CPL0 64kb writable data 16bit */
  0x0000ffff, 0x00009a00,       /* CPL0 64kb readable code 16bit */
  0x0000ffff, 0x00009200,       /* CPL0 64kb writable data 16bit (stack) */

#define VM86_TSS_GD 0x30

  0x00000000, 0x0000e900,       /* CPL3 TSS (not filled out) */
  0x00000000, 0x0000e900,       /* CPL3 TSS (not filled out) */
};

struct gdtr {
  uint16_t limit;
  uint32_t const *base;
} __attribute__((packed, aligned(8)));

void lgdt (struct gdtr *gdtr) {
    __asm__("lgdt (%0)" : : "r" (gdtr));
}

void sgdt (struct gdtr *gdtr) {
    __asm__("sgdt (%0)" : "=r" (gdtr));
}

void setup_gdt (const uint32_t *gdt, uint16_t len) {
  struct gdtr new_gdtr;

  new_gdtr.limit = len;
  new_gdtr.base = gdt;

  lgdt(&new_gdtr);
}

/*** Video ***/

static unsigned short volatile * const video = (void*)0xb8000;

static unsigned char * const col_num = (void*)0x44a;
static unsigned char * const cursor_active_page = (void*)0x44e;
static unsigned char * const cursor_pages = (void*)0x450;

#define ROWS 25
#define VATTR 0x0400
#define FILLATTR 0x0400

void putchar (char c, void *arg) {
  int act = *cursor_active_page;
  int col = cursor_pages[2*act];
  int row = cursor_pages[2*act+1];

  if (c == '\n') {
    col = 0;
    row++;
  } else {
    video[(*col_num)*row+(col++)] = VATTR | c;

    if (col >= 80) {
      col = 0;
      row++;
    }
  }

  while (row >= ROWS) {
    int sr, sc;
    
    for (sr = 1; sr < ROWS; sr++)
      for (sc = 0; sc < *col_num; sc++)
        video[(*col_num)*(sr-1)+sc] = video[(*col_num)*sr+sc];

    for (sc = 0; sc < *col_num; sc++)
      video[(*col_num)*(ROWS-1)+sc] = FILLATTR;

    row--;
  }

  cursor_pages[2*act] = col;
  cursor_pages[2*act+1] = row;
}

/*** Task ***/

struct tss {
    uint16_t prev_task;
    uint16_t res4;

    uint32_t esp0;
    uint16_t ss0;
    uint16_t res10;

    uint32_t esp1;
    uint16_t ss1;
    uint16_t res18;

    uint32_t esp2;
    uint16_t ss2;
    uint16_t res26;

    pt_entry *pdir;
    void *eip;

    uint32_t eflags;
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;

    uint16_t es;
    uint16_t res74;
    uint16_t cs;
    uint16_t res78;
    uint16_t ss;
    uint16_t res82;
    uint16_t ds;
    uint16_t res86;
    uint16_t fs;
    uint16_t res90;
    uint16_t gs;
    uint16_t res94;

    uint16_t ldt;
    uint16_t res98;

    uint16_t debug_trap;
    uint16_t io_map_base;
} __attribute__((aligned(8)));

static struct tss start_tss = { };

static struct tss vm86_tss = {
    .prev_task = 0,
    .eflags = 0x2 | (3 << 12) | (1 << 17), // IOPL=3, VM86
};

/*** Start ***/

void _start (unsigned int magic,
             unsigned int *stack_end, unsigned int stack_len,
             unsigned short rendezvous, unsigned short rendezvous_cs) {
    struct gdtr old_gdtr;

    printf("%s %s\n", nucleus, alive);

    if (magic != 0xb0002000)
        printf("\n\n*** WARNING: wrong magic %08x ***\n\n", magic);
    printf("stack at %p, size %u, esp %p (%i).\n",
           stack_end, stack_len, esp, stack_end-esp);

    pdir = get_cr3();

    printf("page directory is at %p (phys 0x%x).\n",
           pdir, lookup_phys(pdir));
    printf("I am at %p (phys 0x%x).\n",
           _start, lookup_phys(_start));

    gdt[VM86_TSS_GD/4+0] |= sizeof(vm86_tss) & 0x0000ffff;
    gdt[VM86_TSS_GD/4+1] |= sizeof(vm86_tss) & 0x00ff0000;
    gdt[VM86_TSS_GD/4+0] |= (VIRT(&vm86_tss) & 0x0000ffff) << 16;
    gdt[VM86_TSS_GD/4+1] |= (VIRT(&vm86_tss) & 0x00ff0000) >> 16;
    gdt[VM86_TSS_GD/4+1] |= (VIRT(&vm86_tss) & 0xff000000);

    gdt[0x38/4+0] |= sizeof(start_tss) & 0x0000ffff;
    gdt[0x38/4+1] |= sizeof(start_tss) & 0x00ff0000;
    gdt[0x38/4+0] |= (VIRT(&start_tss) & 0x0000ffff) << 16;
    gdt[0x38/4+1] |= (VIRT(&start_tss) & 0x00ff0000) >> 16;
    gdt[0x38/4+1] |= (VIRT(&start_tss) & 0xff000000);

    vm86_tss.pdir = pdir;
    vm86_tss.cs = rendezvous_cs;
    vm86_tss.eip = (void*)VIRT(rendezvous);

    sgdt(&old_gdtr);
    setup_gdt(gdt, sizeof(gdt));

    unsigned short taskr = 0x38;
    __asm__("ltr (%0)" : : "r" (&taskr));

    printf("\nrendezvous will be at %04x:%04x (phys 0x%x).\n",
           (unsigned int)rendezvous_cs,
           (unsigned int)rendezvous,
           lookup_phys(MK_FP(rendezvous_cs,rendezvous))
        );

    __asm__("ljmp $0x30,$0");

    // exit

    lgdt(&old_gdtr);
}
