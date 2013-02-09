#include <stdarg.h>

#include "fbsd_printf.h"

#define NULL ((void*)0)

static unsigned short volatile * const video = (void*)0xb8000;

static char const * const alive = "Protected Mode Kernel Entered.";

static unsigned char * const col_num = (void*)0x44a;
static unsigned char * const cursor_active_page = (void*)0x44e;
static unsigned char * const cursor_pages = (void*)0x450;

register unsigned char *esp __asm__ ("esp");

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

void _start (unsigned int magic,
             unsigned char *stack_end, unsigned int stack_len,
             unsigned short rendezvous, unsigned short rendezvous_cs) {
  printf("Nucleus protected mode kernel entered.\n");

  if (magic != 0xb0002000)
      printf("\n\n*** WARNING: wrong magic %08x ***\n\n");
  printf("stack at %p, size %u, esp %p (%i).\n",
         stack_end, stack_len, esp, stack_end-esp);

  printf("rendezvous will be at %04x:%04x.\n",
         (unsigned int)rendezvous_cs,
         (unsigned int)rendezvous);

  /* printf("%*D", stack_end-esp, esp, " "); */

  /* __asm__("cli\t\nhlt"); */
}
