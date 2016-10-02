#ifndef FBSD_PRINTF_H
#define FBSD_PRINTF_H

__attribute__((__format__ (__printf__, 1, 2)))
int printf(const char *fmt, ...);

#define nprintf printf

#endif /* FBSD_PRINTF_H */
