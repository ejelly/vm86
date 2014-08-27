#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef __WATCOMC__
#include <dos.h>
#include <i86.h>
#include <malloc.h>
#else
#define __cdecl
#define __near
#define __far
#define __huge
#define halloc calloc
#define FP_SEG(x) ((size_t)(0))
#define FP_OFF(x) ((size_t)(x))
#define MK_FP(seg, off) ((void __far *)((seg) << 4 | (unsigned long)(off)))
#define _dos_keep(ret,x) exit(x)
#endif

typedef uint32_t addr;
typedef uint32_t addr_diff;

#define LINEAR_ADDR(x) (((addr)FP_SEG(x) << 4) + FP_OFF(x))
#define SEG_LIN(x) ((uint16_t)((x) >> 4))
#define SEG_OFF(x) ((uint16_t)((x) & 0xf))

/* ELF Header Declarations */

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef int32_t Elf32_SWord;

#define EI_MAG0         0  /* File identification */
#define EI_MAG1         1  /* File identification */
#define EI_MAG2         2  /* File identification */
#define EI_MAG3         3  /* File identification */
#define EI_CLASS        4  /* File class */
#define EI_DATA         5  /* Data encoding */
#define EI_VERSION      6  /* File version */
#define EI_OSABI        7  /* Operating system/ABI identification */
#define EI_ABIVERSION   8  /* ABI version */
#define EI_PAD          9  /* Start of padding bytes */
#define EI_NIDENT       16 /* Size of e_ident[] */

#define ET_NONE		0	/* No file type */
#define ET_REL		1	/* Relocatable file */
#define ET_EXEC		2	/* Executable file */
#define ET_DYN		3	/* Shared object file */
#define ET_CORE		4	/* Core file */
#define ET_LOOS		0xfe00	/* Operating system-specific */
#define ET_HIOS		0xfeff	/* Operating system-specific */
#define ET_LOPROC		0xff00	/* Processor-specific */
#define ET_HIPROC		0xffff	/* Processor-specific */

#define ET_NONE		0	/* No file type */
#define ET_REL		1	/* Relocatable file */
#define ET_EXEC		2	/* Executable file */
#define ET_DYN		3	/* Shared object file */
#define ET_CORE		4	/* Core file */
#define ET_LOOS		0xfe00	/* Operating system-specific */
#define ET_HIOS		0xfeff	/* Operating system-specific */
#define ET_LOPROC		0xff00	/* Processor-specific */
#define ET_HIPROC		0xffff	/* Processor-specific */

#define EM_386		3	/* Intel 80386 */

#define EV_NONE		0	/* Invalid version */
#define EV_CURRENT		1	/* Current version */

#define ELFCLASSNONE    0  /* Invalid class */
#define ELFCLASS32      1  /* 32-bit objects */
#define ELFCLASS64      2  /* 64-bit objects */

#define ELFDATANONE	0  /* Invalid data encoding */
#define ELFDATA2LSB	1  /* See below */
#define ELFDATA2MSB	2  /* See below */

typedef struct {
        unsigned char   e_ident[EI_NIDENT];
        Elf32_Half      e_type;
        Elf32_Half      e_machine;
        Elf32_Word      e_version;
        Elf32_Addr      e_entry;
        Elf32_Off       e_phoff;
        Elf32_Off       e_shoff;
        Elf32_Word      e_flags;
        Elf32_Half      e_ehsize;
        Elf32_Half      e_phentsize;
        Elf32_Half      e_phnum;
        Elf32_Half      e_shentsize;
        Elf32_Half      e_shnum;
        Elf32_Half      e_shstrndx;
} Elf32_Ehdr;

#define	PT_NULL	0
#define	PT_LOAD	1
#define	PT_DYNAMIC	2
#define	PT_INTERP	3
#define	PT_NOTE	4
#define	PT_SHLIB	5
#define	PT_PHDR	6
#define	PT_TLS	7
#define	PT_LOOS	0x60000000
#define	PT_HIOS	0x6fffffff
#define	PT_LOPROC	0x70000000
#define	PT_HIPROC	0x7fffffff

typedef struct {
	Elf32_Word	p_type;
	Elf32_Off	p_offset;
	Elf32_Addr	p_vaddr;
	Elf32_Addr	p_paddr;
	Elf32_Word	p_filesz;
	Elf32_Word	p_memsz;
	Elf32_Word	p_flags;
	Elf32_Word	p_align;
} Elf32_Phdr;

/* Page Table Declarations */

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

/* Main Program Declarations */

typedef struct {
  FILE *file;
  Elf32_Off size;

  Elf32_Ehdr ehdr;
  Elf32_Phdr *phdrs;

  size_t segnum;
  void * __huge *segframes;
  void * __huge *segs;
} image;

uint32_t gdt[] = {
  0, 0,                         /* Empty */
  0x0000ffff, 0x00cf9200,       /* CPL0 4GB writable data */
  0x0000ffff, 0x00cf9a00,       /* CPL0 4GB readable code */
  0x0000ffff, 0x00009200,       /* CPL0 64kb writable data 16bit */
  0x0000ffff, 0x00009a00,       /* CPL0 64kb readable code 16bit */
  0x0000ffff, 0x00009200,       /* CPL0 64kb writable data 16bit (stack) */
};

#pragma pack(push,1)
struct gdtr {
  uint16_t limit;
  uint32_t base;
};
#pragma pack(pop)

#define errorout(...) \
  { fprintf(stderr, __VA_ARGS__); exit(2); }
#define perrorout(msg) { perror(msg); exit(2); }

static
void __huge *page_alloc (size_t size, void * __huge *frame) {
    /* Hack to get paged align memory, under the cost
       of one extra page. */

  *frame = halloc((size + PSIZE - 1) / PSIZE + 1, PSIZE);

  if (!*frame)
    errorout("memory allocation error.");
#ifdef __WATCOMC__
  return MK_FP((FP_SEG(*frame)+255) & ~255, 0);
#else
  return (void __huge *)(((size_t)*frame + PSIZE - 1) & ~(PSIZE-1));
#endif
}

static
void img_read (const image *img, void __huge *buf,
               Elf32_Off off, Elf32_Off len) {
  int n;

  if (fseek(img->file, off, SEEK_SET) < 0)
    perrorout("image seek error");

  if ((n = fread(buf, 1, len, img->file)) != len) {
    if (n < 0)
      perrorout("image read error");

    errorout("short read: %i instead of %i bytes.", n, len);
  }
}

static
image *open_image (const char *path) {
  image *img = (image *)malloc(sizeof(image));
  
  struct stat s;

  if (stat(path, &s) < 0)
    perrorout("error opening image");

  img->size = s.st_size;

  if ((img->file = fopen(path, "rb")) == NULL)
    perrorout("error opening image");

  return img;
}

static
void process_elf_header (image *img) {
  static const unsigned char ei_mag[] =
    {0x7f, 'E', 'L', 'F'};

  img_read(img, &img->ehdr, 0, sizeof(Elf32_Ehdr));

  if (memcmp(img->ehdr.e_ident, ei_mag, sizeof(ei_mag)) != 0)
    errorout("wrong magic.");

  if (img->ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
      img->ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
    errorout("not a 32bit LSB ELF.");

  if (img->ehdr.e_ident[EI_VERSION] != EV_CURRENT)
    errorout("wrong ELF version.");

  /* TODO */
  if (img->ehdr.e_type != ET_EXEC)
    errorout("not an executable.");

  /* TODO */
  if (img->ehdr.e_machine != EM_386)
    errorout("architecture not 386.");

  if (img->ehdr.e_version != EV_CURRENT)
    errorout("wrong ELF version.");

}

static
void process_program_headers (image *img) {
  unsigned int i;
  Elf32_Off pos;
  unsigned int ignored = 0;

  /* TODO */
  if (img->ehdr.e_phoff == 0 || img->ehdr.e_phnum == 0)
    errorout("no program headers, nothing to load.")

  img->phdrs = calloc(img->ehdr.e_phnum, img->ehdr.e_phentsize);

  for (i = 0, pos = img->ehdr.e_phoff; i < img->ehdr.e_phnum;
       i++, pos += img->ehdr.e_phentsize)
    img_read(img, img->phdrs+i, pos, sizeof(Elf32_Phdr));

  img->segs = malloc(img->ehdr.e_phnum *
                     sizeof(void __huge *)); /* pessimistic */
  img->segframes = malloc(img->ehdr.e_phnum *
                          sizeof(void __huge *));
  img->segnum = 0;
  for (i = 0; i < img->ehdr.e_phnum; i++) {
    Elf32_Phdr *phdr;
    Elf32_Off aligned_offset;
    Elf32_Off extra_start;

    phdr = img->phdrs+i;
    extra_start = phdr->p_offset % PSIZE;
    aligned_offset = phdr->p_offset - extra_start;

    if (phdr->p_type != PT_LOAD) {
      img->segs[i] = img->segframes[i] = NULL;
      ignored++;
      continue;
    }

    img->segnum++;

    printf("SEG %i: %li pages (%lu/%lu/%lu) ",
           i,
           (unsigned long)(phdr->p_filesz+PSIZE-1) / PSIZE,
           (unsigned long)phdr->p_memsz, (unsigned long)phdr->p_filesz,
           (unsigned long)phdr->p_memsz+extra_start);

    if (phdr->p_filesz > phdr->p_memsz)
      errorout("segmem memsize %u is smaller than filesize %u?",
               phdr->p_filesz, phdr->p_memsz);

    img->segs[i] = page_alloc(phdr->p_memsz + extra_start, img->segframes+i);
    img_read(img, img->segs[i], aligned_offset, phdr->p_filesz+extra_start);

    printf("at %04x, frame %p (%lu bytes wasted).\n",
           (unsigned int)FP_SEG(img->segs[i]), img->segframes[i],
           (unsigned long)(LINEAR_ADDR(img->segs[i]) -
                           LINEAR_ADDR(img->segframes[i])));
  }
  if (ignored)
      printf("%i %s ignored.\n", ignored,
             ignored == 1 ? "segment" : "segments");
}

#ifdef __WATCOMC__
void __cdecl __far cli (void);
void __cdecl __far sti (void);
void __cdecl __far sgdt (struct gdtr __far *);
void __cdecl __far lgdt (struct gdtr __far *);
void __cdecl __far sidt (struct gdtr __far *);
void __cdecl __far lidt (struct gdtr __far *);
void __cdecl __far getcr3 (addr __far*);
void __cdecl __far setcr3 (addr __far*);
void __cdecl __far enterpm (addr, addr, addr_diff);
#else
void cli(void) { };
void sti(void) { };
void sgdt (struct gdtr __far *x) { };
void lgdt (struct gdtr __far *x) { };
void sidt (struct gdtr __far *x) { };
void lidt (struct gdtr __far *x) { };
void setcr3(addr __far *x) { };
void getcr3(addr __far *x) { };
void enterpm(addr x, addr s, addr_diff si) { };
#endif

static
void setup_gdt (uint32_t *gdt, uint16_t len) {
  struct gdtr new_gdtr;

  new_gdtr.limit = len;
  new_gdtr.base = LINEAR_ADDR(gdt);
  
  lgdt(&new_gdtr);
  sgdt(&new_gdtr);
}

#define stack_size 2048

int main (int argc, char *argv[]) {
  image *img;

  addr pdir_addr;
  void *pdir_frame;
  pt_entry __far *pdir;
  void *ptable1st_frame;
  pt_entry __far *ptable1st;

  void __huge *stack_start;
  addr stack_end;

#ifdef __LP64__
  /* To enable testing of the user-space portions of this code on 64bit
     machines, this table contains the high bits of page table addresses. */
  uint64_t pdir_highbits[PSIZE/4];
#endif

  unsigned int i;

  if (argc != 2)
    errorout("must specify path to ELF executable.");

  printf("LOADELF 0.2q  -- "
         "DOS-preserving loader for 32-bit ELF executables.\n"
         "Copyright (C) 2013-2014 Julien Oster <dev@julien-oster.de>\n\n");

  img = open_image(argv[1]);

  process_elf_header(img);
  process_program_headers(img);

  /* Set up empty page directory */
  pdir = page_alloc(PSIZE, &pdir_frame);
  pdir_addr = LINEAR_ADDR(pdir);

  /* Set up identity mapping for first 4MB
     (some entries may be overwritten later) */
  ptable1st = page_alloc(PSIZE, &ptable1st_frame);
  for (i = 0; i < PSIZE/4; i++)
    ptable1st[i] = (uint32_t)i << 12 | PT_PRESENT | PT_USER | PT_WRITE;

  pdir[0] = (LINEAR_ADDR(ptable1st) & ~P_OFF_MASK)
      | PT_PRESENT | PT_USER | PT_WRITE;

  /* Set up page table entries for loaded segments */
  for (i = 0; i < img->ehdr.e_phnum; i++) {
    unsigned int j;

    if (!img->segs[i])
      continue;

    printf("VIRTUAL address of segment %i is 0x%08lx\n",
           i, (unsigned long)img->phdrs[i].p_vaddr);

    for (j = 0; j < (img->phdrs[i].p_memsz+PSIZE-1)/PSIZE; j++) {
      pt_entry __far *pt;
      unsigned int pdir_off, pt_off;
      Elf32_Word paddr, vaddr;

      paddr = LINEAR_ADDR(img->segs[i])+j*PSIZE;
      vaddr = img->phdrs[i].p_vaddr+j*PSIZE;

      pdir_off = (vaddr & P_DIR_MASK) >> 22;
      pt_off = (vaddr & P_PAGE_MASK) >> 12;

      /* Look up page table in dir, create new one if necessary */
      if (pdir[pdir_off]) {
        pt = MK_FP(((addr)pdir[pdir_off] & ~P_OFF_MASK) >> 4, 0);
#ifdef __LP64__
        pt = (pt_entry __far *)(pdir_highbits[pdir_off] | (uint64_t)pt);
#endif
      } else {
        void *pt_frame;
        pt = page_alloc(PSIZE, &pt_frame);
        pdir[pdir_off] = (LINEAR_ADDR(pt) & ~P_OFF_MASK) |
          PT_PRESENT | PT_USER | PT_WRITE;
#ifdef __LP64__
        pdir_highbits[pdir_off] = (uint64_t)LINEAR_ADDR(pt) &
          ~(uint64_t)0xffffffff;
#endif
      }

      pt[pt_off] = ((paddr) & ~P_OFF_MASK) | PT_PRESENT | PT_USER | PT_WRITE;
    }
  }

  printf("\n");

  setup_gdt(gdt, sizeof(gdt));
  /* _dos_keep(0, 0); */

  stack_start = halloc(stack_size / 16, 16);
  stack_end = LINEAR_ADDR(stack_start) + stack_size;

  setcr3(&pdir_addr);
  printf("PREPARE FOR LANDING: 0x%08lx with stack at 0x%05lx\n\n",
         (unsigned long)img->ehdr.e_entry, (unsigned long)stack_end);
  enterpm(img->ehdr.e_entry, stack_end, stack_size);

  printf("LOADELF: Back in Real Mode, exiting.\n");

  return 0;
}
