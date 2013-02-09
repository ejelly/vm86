void _start (unsigned int magic, unsigned char *stack_end, unsigned int stack_len) {
  __asm__("cli\t\nhlt");
}
