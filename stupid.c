#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "udis86.h"

#include "fbsd_printf.h"

#define CLI() __asm__("cli")
#define STI() __asm__("sti")
#define HLT() __asm__("hlt")
#define OUTB(port,data) __asm__("outb %b0, %w1" : : "a"(data), "Nd"(port))
#define OUTW(port,data) __asm__("outw %w0, %w1" : : "a"(data), "Nd"(port))
#define OUTD(port,data) __asm__("outl %0, %w1" : : "a"(data), "Nd"(port))
#define INB(dest,port) __asm__("inb %w1, %b0" : "=a"(dest) : "Nd"(port))
#define INW(dest,port) __asm__("inw %w1, %w0" : "=a"(dest) : "Nd"(port))
#define IND(dest,port) __asm__("inl %w1, %0" : "=a"(dest) : "Nd"(port))

__attribute__((always_inline))
inline uint8_t inb(uint16_t port) {
    uint8_t data;
    INB(data, port);
    return data;
}

__attribute__((always_inline))
inline uint16_t inw(uint16_t port) {
    uint16_t data;
    INW(data, port);
    return data;
}

__attribute__((always_inline))
inline uint32_t ind(uint16_t port) {
    uint32_t data;
    IND(data, port);
    return data;
}

static char nucleus[] = "Nucleus";
char alive[] = "protected mode kernel entered.";

#define NULL ((void*)0)

#define VIRT(addr) ((uint32_t)(addr))
#define MK_FP(seg, off) ((void *)(((seg) << 4) + (uint32_t)(off)))
#define FP_SEG(x) ((uint16_t)(((x) & 0xffff0000) >> 16))
#define FP_OFF(x) ((uint16_t)(((x) & 0x0000ffff)))

typedef uint32_t farp;

register unsigned int *nucleus_esp __asm__ ("esp");

/*** Support ***/

void *memset(void *s, int c, size_t n) {
    for (size_t i = 0; i < n; i++) ((uint8_t*)s)[i] = c;
    return s;
}

void __stack_chk_fail(void) {
    printf("Stack Overflow.\n");
    CLI(); HLT();
};

FILE *stdin, *stdout, *stderr;

int fgetc(FILE *stream) {
    printf("fgetc unimplemented.\n");
    CLI(); HLT();
    return 0; // unreached
}

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
typedef uint32_t lin_addr;

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
  0, 0,                         /* 0x00 Empty */
  0x0000ffff, 0x00cf9200,       /* 0x08 CPL0 4GB writable data */
  0x0000ffff, 0x00cf9a00,       /* 0x10 CPL0 4GB readable code */
  0x0000ffff, 0x00009200,       /* 0x18 CPL0 64kb writable data 16bit */
  0x0000ffff, 0x00009a00,       /* 0x20 CPL0 64kb readable code 16bit */
  0x0000ffff, 0x00009200,       /* 0x28 CPL0 64kb writable data 16bit (stack) */

#define NUCLEUS_TSS_GD  0x50
#define VM86_TSS_GD     0x58

  0x00000000, 0x00008900,       /* 0x30 CPL0 TSS (not filled out) */
  0x00000000, 0x00008900,       /* 0x30 CPL0 TSS (not filled out) */
  0x00000000, 0x00008900,       /* 0x30 CPL0 TSS (not filled out) */
  0x00000000, 0x00008900,       /* 0x30 CPL0 TSS (not filled out) */
  0x00000000, 0x00008900,       /* 0x30 CPL0 TSS (not filled out) */
  0x00000000, 0x0000e900,       /* 0x38 CPL3 TSS (not filled out) */
};

struct gdtr {
  uint16_t limit;
  uint32_t const *base;
} __attribute__((packed, aligned(8)));

__attribute__((always_inline))
void lgdt (struct gdtr *gdtr) {
    __asm__("lgdt (%0)" : : "r" (gdtr));
}

__attribute__((always_inline))
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

#define SERIAL 0x3f8

void init_serial (void) {
    OUTB(SERIAL + 1, 0x00);    // Disable all interrupts
    OUTB(SERIAL + 3, 0x80);    // Enable DLAB (set baud rate divisor)
    OUTB(SERIAL + 0, 0x01);    // Set divisor to 3 (lo byte) 115200 baud
    OUTB(SERIAL + 1, 0x00);    //                  (hi byte)
    OUTB(SERIAL + 3, 0x03);    // 8 bits, no parity, one stop bit
    OUTB(SERIAL + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
    // outb(SERIAL + 4, 0x0B);    // IRQs enabled, RTS/DSR set
}

void serialout (char c) {
    for (int i = 0; i < 100000; i++)
        if (inb(SERIAL + 0x5) & 0x20)
            break;

    OUTB(SERIAL, c);
}

#define ROWS 25
#define VATTR 0x0400
#define FILLATTR 0x0400

void nputchar (char c, void *arg) {
    serialout(c);

    int act = *cursor_active_page;
    int col = cursor_pages[2*act];
    int row = cursor_pages[2*act+1];

    switch (c) {
    case '\n':
        row++;

    case '\r':
        col = 0;

        break;

    case '\t':
        col = (col/8+1)*8;
        break;

    default:
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

#define EFLAGS_CF (1UL << 0)
#define EFLAGS_R1 (1UL << 1)
#define EFLAGS_PF (1UL << 2)
#define EFLAGS_R3 (1UL << 3)
#define EFLAGS_AF (1UL << 4)
#define EFLAGS_R5 (1UL << 5)
#define EFLAGS_ZF (1UL << 6)
#define EFLAGS_SF (1UL << 7)
#define EFLAGS_TF (1UL << 8)
#define EFLAGS_IF (1UL << 9)
#define EFLAGS_DF (1UL << 10)
#define EFLAGS_OF (1UL << 11)
#define EFLAGS_IOPL0 (1UL << 12)
#define EFLAGS_IOPL1 (1UL << 13)
#define EFLAGS_NT (1UL << 14)
#define EFLAGS_R15 (1UL << 15)
#define EFLAGS_RF (1UL << 16)
#define EFLAGS_VM (1UL << 17)

#define EFLAGS_IOPL_SHIFT 12

static struct tss vm86_tss = {
    .prev_task = 0,
    .eflags = EFLAGS_R1 | (0 << EFLAGS_IOPL_SHIFT) | EFLAGS_VM,
};

static struct tss nucleus_tss = { };

/*** PIC ***/

#define PIC1_CMD    0x0020
#define PIC1_DATA   0x0021
#define PIC2_CMD     0x00a0
#define PIC2_DATA    0x00a1

#define PIC_EOI         0x20

#define ICW1_ICW4	0x01		/* ICW4 (not) needed */
#define ICW1_SINGLE	0x02		/* Single (cascade) mode */
#define ICW1_INTERVAL4	0x04		/* Call address interval 4 (8) */
#define ICW1_LEVEL	0x08		/* Level triggered (edge) mode */
#define ICW1_INIT	0x10		/* Initialization - required! */

#define ICW4_8086	0x01		/* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO	0x02		/* Auto (normal) EOI */
#define ICW4_BUF_SLAVE	0x08		/* Buffered mode/slave */
#define ICW4_BUF_MASTER	0x0C		/* Buffered mode/master */
#define ICW4_SFNM	0x10		/* Special fully nested (not) */


inline void irq_ack (uint8_t irq) {
    if (irq >= 8) {
        OUTB(PIC2_CMD, PIC_EOI);
    }
    OUTB(PIC1_CMD, PIC_EOI);
}

void init8259 (void) {
    uint8_t mask1 = inb(PIC1_DATA);
    uint8_t mask2 = inb(PIC2_DATA);

    nprintf("8259 initialization, masks: %02x %02x\n", mask1, mask2);

    OUTB(PIC1_CMD, ICW1_ICW4 | ICW1_INIT);
    OUTB(PIC1_DATA, 0x20);
    OUTB(PIC1_DATA, 4);
    OUTB(PIC1_DATA, ICW4_8086);

    OUTB(PIC2_CMD, ICW1_ICW4 | ICW1_INIT);
    OUTB(PIC2_DATA, 0x28);
    OUTB(PIC2_DATA, 2);
    OUTB(PIC2_DATA, ICW4_8086);

    for (int i = 0; i < 1000; i++);

    OUTB(PIC1_DATA, mask1);
    OUTB(PIC2_DATA, mask2);
}

void irq_unmask (uint16_t unmask) {
    uint8_t mask1, mask2;

    INB(mask1, PIC1_DATA);
    INB(mask2, PIC2_DATA);

    uint16_t mask = ((mask2 << 8) | mask1) & ~unmask;

    OUTB(PIC2_DATA, mask >> 8);
    OUTB(PIC1_DATA, mask & 0xff);
}

void irq_mask (uint16_t maskirqs) {
    uint8_t mask1, mask2;

    INB(mask1, PIC1_DATA);
    INB(mask2, PIC2_DATA);

    uint16_t mask = ((mask2 << 8) | mask1) | maskirqs;

    OUTB(PIC2_DATA, mask >> 8);
    OUTB(PIC1_DATA, mask & 0xff);
}

/*** Interrupts ***/

struct pushad {
    uint32_t edi, esi, ebp, original_esp, ebx, edx, ecx, eax;
} __attribute__((packed));

struct trapstack {
    uint32_t gs, fs, es, ds;

    struct pushad pushad;

    uint32_t errorcode;
    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t esp;
    uint32_t ss;

} __attribute__((packed));

volatile farp *vm86_ivt = (farp*)0;

extern void dftrap(void);
extern void udtrap(void);
extern void tsstrap(void);
extern void gpftrap(void);
extern void pftrap(void);

static inline void print_eflags(uint32_t eflags) {
    nprintf("<%08x", eflags);

    if (eflags & EFLAGS_CF) {
        nprintf(" CF");
    }

    if (eflags & EFLAGS_R1) {
        nprintf(" R1");
    }

    if (eflags & EFLAGS_PF) {
        nprintf(" PF");
    }

    if (eflags & EFLAGS_R3) {
        nprintf(" R3");
    }

    if (eflags & EFLAGS_AF) {
        nprintf(" AF");
    }

    if (eflags & EFLAGS_R5) {
        nprintf(" R5");
    }

    if (eflags & EFLAGS_ZF) {
        nprintf(" ZF");
    }

    if (eflags & EFLAGS_SF) {
        nprintf(" SF");
    }

    if (eflags & EFLAGS_TF) {
        nprintf(" TF");
    }

    if (eflags & EFLAGS_IF) {
        nprintf(" IF");
    }

    if (eflags & EFLAGS_DF) {
        nprintf(" DF");
    }

    if (eflags & EFLAGS_OF) {
        nprintf(" OF");
    }

    nprintf(" IOPL%d", (eflags >> EFLAGS_IOPL_SHIFT) & 0x3);

    if (eflags & EFLAGS_NT) {
        nprintf(" NT");
    }

    if (eflags & EFLAGS_R15) {
        nprintf(" R15");
    }

    if (eflags & EFLAGS_RF) {
        nprintf(" RF");
    }

    if (eflags & EFLAGS_VM) {
        nprintf(" VM");
    }

    nprintf("> ");
}

#define X(source) ((source) & 0xffff)

#define LOADX(dest,source) ((dest) = ((uint32_t)(dest) & 0xffff0000) | (uint16_t)(source))
#define LOADL(dest,source) ((dest) = ((uint32_t)(dest) & 0xffffff00) | (uint8_t)(source))
#define LOADH(dest,source) ((dest) = ((uint32_t)(dest) & 0xffff00ff) | ((uint8_t)(source) << 8))

#define ADDX(val,inc) LOADX((val), (val) + (inc))

#define MK16(seg,off) ((uint16_t*)MK_FP((seg),(off) & 0xffff))

uint32_t unhandled(char const * name, unsigned int num, struct trapstack *ts) {
    uint8_t *flat_ip = (uint8_t*)MK16(ts->cs, ts->eip);

    nprintf("Unhandled %s (%d)\n", name, num);
    nprintf("errorcode: %08x, CS:EIP: %04x:%08x, SS:ESP: %04x:%08x\nEFLAGS: ",
           ts->errorcode, ts->cs, ts->eip, ts->ss, ts->esp);
    print_eflags(ts->eflags);

    uint32_t task;
    __asm__("str %k0\n" : "=r"(task));

    nprintf("Task: %04x\n", task);

    struct pushad const * const p = &ts->pushad;
    nprintf("CS  %08x, DS  %08x, ES  %08x, FS  %08x, GS  %08x\n",
            ts->cs, ts->ds, ts->es, ts->fs, ts->gs);
    nprintf("EAX %08x, EBX %08x, ECX %08x, EDX %08x\nESI %08x, EDI %08x\n",
            p->eax, p->ebx, p->ecx, p->edx, p->esi, p->edi);

    uint32_t cr0;
    __asm__("movl %%cr0, %0" : "=r" (cr0));

    nprintf("CR0: %08x\n", cr0);

    ud_t ud_obj;

    ud_init(&ud_obj);
    ud_set_input_buffer(&ud_obj, flat_ip, 16);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    ud_set_vendor(&ud_obj, UD_VENDOR_ANY);

    ud_set_mode(&ud_obj, ts->eflags & EFLAGS_VM ? 16 : 32);
    ud_set_pc(&ud_obj, (uint32_t)(MK16(ts->cs, ts->eip)));

    while (ud_disassemble(&ud_obj)) {
        printf("%08llx\t%s\t%s\n", ud_insn_off(&ud_obj),
               ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
    }

    CLI();
    HLT();

    return 0;
}

static inline void pushw86(struct trapstack *ts, uint16_t val) {
    uint16_t sp = ts->esp;

    if (sp < 2) {
        nprintf("Stack floor reached.\n");
    }

    sp -= 2;
    *MK16(ts->ss, sp) = val;
    LOADX(ts->esp, sp);
}

static inline void pushd86(struct trapstack *ts, uint32_t val) {
    uint16_t sp = ts->esp;

    if (sp < 4) {
        nprintf("Stack floor reached.\n");
    }

    sp -= 4;
    *(uint32_t*)MK16(ts->ss, sp) = val;
    LOADX(ts->esp, sp);
}

static uint16_t popw86(struct trapstack *ts) {
    uint16_t sp = ts->esp;

    if (sp > 0xfffe) {
        nprintf("Stack ceiling reached.\n");
    }

    uint16_t val = *MK16(ts->ss, sp);
    sp += 2;
    LOADX(ts->esp, sp);
    return val;
}

static uint16_t popd86(struct trapstack *ts) {
    uint16_t sp = ts->esp;

    if (sp > 0xfffc) {
        nprintf("Stack ceiling reached.\n");
    }

    uint32_t val = *(uint32_t*)MK16(ts->ss, sp);
    sp += 4;
    LOADX(ts->esp, sp);
    return val;
}

static inline void cli86(struct trapstack *ts) {
    ts->eflags = ts->eflags & ~EFLAGS_IF;
}

static inline void sti86(struct trapstack *ts) {
    ts->eflags = ts->eflags | EFLAGS_IF;
}

#define EFLAGS_PRIV_MASK (EFLAGS_TF | EFLAGS_IOPL0 | EFLAGS_IOPL1 | \
                          EFLAGS_NT | EFLAGS_RF | EFLAGS_VM)

#define EFLAGS_VIRT_MASK (EFLAGS_IOPL0 | EFLAGS_IOPL1 | EFLAGS_NT)

static uint16_t virtual_flags = 0;

static inline void pushfw86(struct trapstack *ts, bool op_override) {
    uint32_t ret_eflags = (ts->eflags & ~EFLAGS_PRIV_MASK) | virtual_flags;

    if (op_override)
        pushd86(ts, ret_eflags);
    else
        pushw86(ts, ret_eflags);
}

static inline bool popfw86(struct trapstack *ts, bool op_override) {
    uint16_t new_eflags;

    new_eflags = op_override ? popd86(ts) : popw86(ts);

    bool privchange = false;

    if ((new_eflags & EFLAGS_PRIV_MASK) ^ virtual_flags) {
        privchange = true;
        nprintf("EFLAGS priv change: \n");
        print_eflags(ts->eflags);
        nprintf("=> ");
        print_eflags(new_eflags);
        nprintf("^ ");
        print_eflags(new_eflags & EFLAGS_PRIV_MASK);
        nprintf("\n");
    }

    virtual_flags = new_eflags & EFLAGS_VIRT_MASK;

    LOADX(ts->eflags, ts->eflags | (new_eflags & ~EFLAGS_PRIV_MASK));

    return true;
}

static inline bool iretw86(struct trapstack *ts) {
    ts->eip = popw86(ts);
    ts->cs = popw86(ts);

    return popfw86(ts, false);
}

static inline void insb86(struct trapstack *ts) {
    struct pushad *p = &ts->pushad;
    int dir = (ts->eflags & EFLAGS_DF) ? -1 : 1;

    uint16_t port = p->edx;
    uint16_t di = p->edi;

    uint8_t val = inb(port);

    nprintf("insb 0x%04hx = 0x%02hhx -> %04x:%04x \n", port, val, ts->es, di);

    *(uint8_t*)MK16(ts->es, di) = val;
    di += dir;
    LOADX(p->edi, di);
}

static inline void insw86(struct trapstack *ts) {
    struct pushad *p = &ts->pushad;
    int dir = (ts->eflags & EFLAGS_DF) ? -1 : 1;

    uint16_t port = p->edx;
    uint16_t di = p->edi;

    uint16_t val = inw(port);

    nprintf("insw 0x%04hx = 0x%04hx -> %04x:%04x \n", port, val, ts->es, di);

    *MK16(ts->es, di) = val;
    di += 2*dir;
    LOADX(p->edi, di);
}

static inline void insd86(struct trapstack *ts) {
    struct pushad *p = &ts->pushad;
    int dir = (ts->eflags & EFLAGS_DF) ? -1 : 1;

    uint16_t port = p->edx;
    uint16_t di = p->edi;

    uint32_t val = ind(port);

    //nprintf("[%04x:%04x] insd 0x%04hx = 0x%08x -> %04x:%04x \n", ts->cs, ts->eip & 0xffff,
    // port, val, ts->es, di);

    *(uint32_t*)MK16(ts->es, di) = val;
    di += 4*dir;
    LOADX(p->edi, di);
}

static bool ioperm(struct trapstack *ts, uint16_t port) {
    switch (port) {
    case PIC1_DATA:
    case PIC1_CMD:
    case PIC2_DATA:
    case PIC2_CMD:
        nprintf("forbidden I/O port 0x%04hx\n", port);
        unhandled("I/O port", port, ts);
        return false;

    case 0x0043: // PIC
    case 0x01f1: // ATA
    case 0x01f2:
    case 0x03c9: // VGA
    case 0x03d4:
    case 0x03d5:
    case 0x03f6: // Serial
    case 0x1004: // ACPI PM1a_CNT_BLK
    case 0xd030: // Net
    case 0xd032: // Net
        break;

    default:
        nprintf("ioperm 0x%04hx\n", port);
    }

    return true;
}

static void virtual_outb(struct trapstack *ts, uint16_t port, uint8_t data) {
    if (ioperm(ts, port)) {
        OUTB(port, data);
    }
}

static void virtual_outw(struct trapstack *ts, uint16_t port, uint16_t data) {
    if (ioperm(ts, port)) {
        OUTW(port, data);
    }
}

static uint8_t virtual_inb(struct trapstack *ts, uint16_t port) {
    if (ioperm(ts, port)) {
        return inb(port);
    } else {
        return 0;
    }
}

static uint16_t virtual_inw(struct trapstack *ts, uint16_t port) {
    if (ioperm(ts, port)) {
        return inw(port);
    } else {
        return 0;
    }
}

#define INCIP(inc) ADDX(ts->eip, (inc))

volatile bool pending = false;
volatile uint8_t pending_intnum = 0;

#define OPCODE(ip) (*(uint8_t*)MK16(ts->cs, (ip)))

uint32_t gpf (char const * msg, unsigned int num, struct trapstack *ts) {
    // IRQ

    if ((ts->errorcode & 0x3) == 0x3) {
        int intnum = (ts->errorcode & 0xffff) >> 3;

        pending = true;
        if (intnum == 0x07) {
            // FPU
            __asm__("clts");
            return 0;
        }  else if (intnum >= 0x20 && intnum < 0x28) {
            pending_intnum = intnum - 0x20 + 0x08;
        } else if (intnum >= 0x28 && intnum < 0x30) {
            pending_intnum = intnum - 0x28 + 0x70;
        } else {
            nprintf("Unhandled external interrupt %02xh (errorcode %08x)\n", intnum, ts->errorcode);
            unhandled("interrupt", intnum, ts);
        }

        if (intnum != 0x07 && intnum != 0x20 && intnum != 0x21) {
            nprintf("External interrupt %02xh\n", intnum);
        }
    }

    // uint16_t ip = ts->eip;
    // int dir = (ts->eflags & EFLAGS_DF) ? -1 : 1;
    struct pushad *p = &ts->pushad;

    bool soft_pending = false;
    int soft_intnum = 0;
    if (ts->eflags & EFLAGS_VM) {

        if (ts->errorcode == 0) {
            int op_override = 0;

            uint32_t dip = ts->eip;
            for (bool decoding = true; decoding; dip++) {
                uint8_t op = OPCODE(dip);

                decoding = false;

                switch(op) {
                case 0x0f:
                    // two-byte

                    switch(OPCODE(dip+1)) {
                    case 0x20: // mov from cr
                        switch(OPCODE(dip+2)) {
                        // Only supporting eax for now.
                        case 0xc0:
                            INCIP(3);
                            __asm__("movl %%cr0, %0" : "=r"(p->eax));
                            break;
                        case 0xd0:
                            INCIP(3);
                            __asm__("movl %%cr2, %0" : "=r"(p->eax));
                            break;
                        case 0xd8:
                            INCIP(3);
                            __asm__("movl %%cr3, %0" : "=r"(p->eax));
                            break;
                        default:
                            nprintf("Unhandled MOV CR opcode %02x\n", OPCODE(dip+2));
                            unhandled("MOV CR opcode", 0, ts);
                            return 0;
                        }
                        break;
                    default:
                        nprintf("Unhandled 0F opcode %02x\n", OPCODE(dip+1));
                        unhandled("0F opcode", 0, ts);
                        return 0;
                    }
                    break;

                case 0x66: // operand override
                    INCIP(1);
                    decoding = true;
                    op_override++;
                    break;

                case 0x6c:
                    // insb

                    INCIP(1);
                    insb86(ts);

                    break;

                case 0x6d:
                    // insw

                    INCIP(1);
                    insw86(ts);

                    break;

                case 0x9c: // pushfw
                    INCIP(1);
                    pushfw86(ts, op_override > 0);

                    break;

                case 0x9d:
                    // popfw
                    INCIP(1);

                    if (!popfw86(ts, op_override > 0)) {
                        nprintf("In POPFW\n");
                        return unhandled("popfw", 0, ts);
                    }

                    break;

                case 0xcd:
                    // int
                    INCIP(2);

                    soft_intnum = OPCODE(dip+1);

                    if (soft_intnum == 0x44) {
                        nprintf("SYSCALL\n");
                        return 0;
                    }

                    soft_pending = true;
                    break;

                case 0xcf:
                    // iretw

                    if (!iretw86(ts)) {
                        nprintf("In IRETW\n");
                        return unhandled("iretw", 0, ts);
                    }

                    break;

                case 0xe6:
                    // outb
                {
                    INCIP(1);
                    uint8_t port = OPCODE(dip+1);
                    INCIP(1);

                    virtual_outb(ts, port, p->eax);
                }
                break;

                case 0xec:
                    // inb
                    INCIP(1);

                    LOADL(p->eax, virtual_inb(ts, p->edx));
                    break;

                case 0xed:
                    // inw
                    INCIP(1);

                    LOADX(p->eax, virtual_inw(ts, p->edx));
                    break;

                case 0xee:
                    // outb
                {
                    INCIP(1);

                    virtual_outb(ts, p->edx, p->eax);
                }
                break;

                case 0xef:
                    // outw
                {
                    INCIP(1);

                    virtual_outw(ts, p->edx, p->eax);
                }
                break;

                case 0xf3:
                    // rep
                {
                    uint16_t dp = 0;

                    while (OPCODE(++dip) == 0x66) {
                        dp++;
                    }

                    if (X(p->ecx) == 0) {
                        INCIP(2+dp);
                    } else {
                        ADDX(p->ecx, -1);

                        switch (OPCODE(dip)) {
                        case 0x6c:
                            insb86(ts);
                            break;
                        case 0x6d:
                            if (dp) {
                                insd86(ts);
                            } else {
                                insw86(ts);
                            }
                            break;
                        default:
                            nprintf("Unhandled opcode %02x after REP\n", OPCODE(dip));
                            unhandled("REP opcode", OPCODE(dip), ts);
                        }
                    }

                    break;
                }
                case 0xf4:
                    // hlt
                    INCIP(1);

                    if (!(ts->eflags & EFLAGS_IF)) {
                        nprintf("Uhoh, halt.\n");
                    }

                    video[8]++;

                    __asm__("ljmp %0,$0" : : "i"(NUCLEUS_TSS_GD));

                    break;

                case 0xfa:
                    //cli
                    INCIP(1);
                    cli86(ts);

                    break;

                case 0xfb:
                    //sti
                    INCIP(1);
                    sti86(ts);

                    break;

                default:
                    nprintf("Unhandled opcode %08x.\n", OPCODE(dip));
                    unhandled("vm86 opcode", 0, ts);
                    return 0;
                }
            }
        }

        if ((pending && ts->eflags & EFLAGS_IF) || soft_pending) {
            int intnum;

            if (soft_pending) {
                intnum = soft_intnum;
            } else {
                pending = false;
                intnum = pending_intnum;

                if (intnum != 0x08 && intnum != 0x09) {
                    farp vector = vm86_ivt[intnum];
                    nprintf("Serving interrupt %02xh at %04hx:%04hx\n", intnum,
                           FP_SEG(vector), FP_OFF(vector));
                }
            }

            farp vector = vm86_ivt[intnum];

            if (vector == 0) {
                nprintf("NULL vector for interrupt %04x\n", intnum);
                unhandled("interrupt vector", intnum, ts);
            }

            pushfw86(ts, false);

            ts->eflags = ts->eflags & ~(EFLAGS_IF | EFLAGS_TF | EFLAGS_AF);

            pushw86(ts, ts->cs);
            pushw86(ts, ts->eip);

            ts->cs = FP_SEG(vector);
            ts->eip = FP_OFF(vector);
        }

        if (pending) {
            nprintf("wait...\n");
        }

        return 0;
    } else {
        // Not vm86.

        uint32_t task;
        __asm__("str %k0" : "=a"(task));

        if (pending && task != VM86_TSS_GD) {
            __asm__("ljmp %0,$0" : : "i"(VM86_TSS_GD));
        }
        return 0;
    }

    nprintf("pending: %d, pending interrupt: %d\n", pending, pending_intnum);
    unhandled("GPF", 13, ts);
    return 0;
}

volatile uint32_t idt[2*256] __attribute__((aligned(8))) = { 0 };

struct idtr {
  uint16_t limit;
  uint32_t const *base;
} __attribute__((packed, aligned(8)));

void lidt (struct idtr *idtr) {
    __asm__("lidt (%0)" : : "r" (idtr));
}

void sidt (struct gdtr *idtr) {
    __asm__("sidt (%0)" : "=r" (idtr));
}

void setup_idt (const uint32_t *idt, uint16_t len) {
  struct idtr new_idtr;

  new_idtr.limit = len;
  new_idtr.base = idt;

  lidt(&new_idtr);
}

void setup_interrupts (void) {
    setup_idt((uint32_t*)idt, sizeof(idt)*4);

    idt[6*2+0] = (0x10 << 16) | (VIRT(udtrap) & 0x0000ffff);
    idt[6*2+1] = (VIRT(udtrap) & 0xffff0000) | 0x00008e00;

    idt[8*2+0] = (0x10 << 16) | (VIRT(dftrap) & 0x0000ffff);
    idt[8*2+1] = (VIRT(dftrap) & 0xffff0000) | 0x00008e00;

    idt[10*2+0] = (0x10 << 16) | (VIRT(tsstrap) & 0x0000ffff);
    idt[10*2+1] = (VIRT(tsstrap) & 0xffff0000) | 0x00008e00;

    idt[13*2+0] = (0x10 << 16) | (VIRT(gpftrap) & 0x0000ffff);
    idt[13*2+1] = (VIRT(gpftrap) & 0xffff0000) | 0x00008e00;

    idt[14*2+0] = (0x10 << 16) | (VIRT(pftrap) & 0x0000ffff);
    idt[14*2+1] = (VIRT(pftrap) & 0xffff0000) | 0x00008e00;

}

/*** Start ***/

uint8_t stack[8192];

void _start (unsigned int magic,
             unsigned int *stack_end, unsigned int stack_len,
             unsigned short rendezvous, unsigned short rendezvous_cs,
             unsigned int linear_frame, unsigned int cs_exitreal,
             unsigned int real_esp, unsigned int real_ss) {
    struct gdtr old_gdtr;

    init_serial();

    nprintf("%s %s\n", nucleus, alive);

    if (magic != 0xb0002000)
        nprintf("\n\n*** WARNING: wrong magic %08x ***\n\n", magic);
    nprintf("stack at %p, size %u, esp %p (%i).\n",
           stack_end, stack_len, nucleus_esp, stack_end-nucleus_esp);

    pdir = get_cr3();

    nprintf("page directory is at %p (phys 0x%x). ",
           pdir, lookup_phys(pdir));
    nprintf("I am at %p (phys 0x%x).\n",
           _start, lookup_phys(_start));

    gdt[NUCLEUS_TSS_GD/4+0] |= sizeof(nucleus_tss) & 0x0000ffff;
    gdt[NUCLEUS_TSS_GD/4+1] |= sizeof(nucleus_tss) & 0x00ff0000;
    gdt[NUCLEUS_TSS_GD/4+0] |= (VIRT(&nucleus_tss) & 0x0000ffff) << 16;
    gdt[NUCLEUS_TSS_GD/4+1] |= (VIRT(&nucleus_tss) & 0x00ff0000) >> 16;
    gdt[NUCLEUS_TSS_GD/4+1] |= (VIRT(&nucleus_tss) & 0xff000000);

    gdt[VM86_TSS_GD/4+0] |= sizeof(vm86_tss) & 0x0000ffff;
    gdt[VM86_TSS_GD/4+1] |= sizeof(vm86_tss) & 0x00ff0000;
    gdt[VM86_TSS_GD/4+0] |= (VIRT(&vm86_tss) & 0x0000ffff) << 16;
    gdt[VM86_TSS_GD/4+1] |= (VIRT(&vm86_tss) & 0x00ff0000) >> 16;
    gdt[VM86_TSS_GD/4+1] |= (VIRT(&vm86_tss) & 0xff000000);

    nucleus_tss.pdir = pdir;

    vm86_tss.pdir = pdir;
    vm86_tss.cs = rendezvous_cs;
    vm86_tss.eip = (void*)VIRT(rendezvous);
    vm86_tss.ss = real_ss;
    vm86_tss.esp = real_esp;

    vm86_tss.ss0 = 0x08;
    vm86_tss.esp0 = VIRT(stack+sizeof(stack));

    sgdt(&old_gdtr);
    setup_gdt(gdt, sizeof(gdt));

    unsigned short taskr = NUCLEUS_TSS_GD;
    __asm__("ltr (%0)" : : "r" (&taskr));

    nprintf("\nrendezvous will be at %04x:%04x (phys 0x%x).\n",
           (unsigned int)rendezvous_cs,
           (unsigned int)rendezvous,
           lookup_phys(MK_FP(rendezvous_cs,rendezvous))
        );
    nprintf("rendezvous stack at %04x:%04x (kernel stack: 0x%08x).\n",
            real_ss, real_esp, (lin_addr)stack);

    uint64_t *stack64 = (uint64_t*)stack;
    stack64[0] = 0x0123456789abcdef;
    stack64[1] = 0xfedcba9876543210;

    setup_interrupts();

    init8259();

    // irq_unmask(7); // PIT + Keyboard + Slave
    // irq_mask(1);

    __asm__("ljmp %0,$0" : : "i"(VM86_TSS_GD));

    // Idle.

    nprintf("\nFirst Task switch to lala-land.\n");

    STI();
    for (;;) {
        video[12]++;
        HLT();
    }

    // lgdt(&old_gdtr);
}
