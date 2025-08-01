#ifndef T2WHOIS_UTILS_H_INCLUDED
#define T2WHOIS_UTILS_H_INCLUDED

#include <stdarg.h>   // for ...
#include <stdbool.h>  // for bool
#include <stdio.h>    // for FILE
#include <stddef.h>   // for size_t

typedef int (*print_func_t)(FILE *fd, const char *format, ...);

int fprintf_socket(FILE *file, const char *format, ...);
ssize_t read_line(int fd, char *buf, size_t buf_size, bool strip);

#endif // T2WHOIS_UTILS_H_INCLUDED
