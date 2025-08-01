#include "t2whois-utils.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#include "t2log.h"
#include "t2utils.h"


int fprintf_socket(FILE *file, const char *format, ...) {
    const int sockfd = *(int*)file;

    va_list args;
    va_start(args, format);
    int len = vsnprintf(0, 0, format, args);
    va_end(args);

    if (len < 0) return -1;

    len++; // for '\0'

    char * const buf = malloc(len);
    if (!buf) return -1;

    va_start(args, format);
    len = vsnprintf(buf, len, format, args);
    va_end(args);

    if (len < 0) {
        free(buf);
        return -1;
    }

    send(sockfd, buf, len+1, 0);

    free(buf);

    return len;
}


ssize_t read_line(int fd, char *buf, size_t bufmax, bool strip) {
    if (UNLIKELY(bufmax <= 0 || !buf)) {
        errno = EINVAL;
        return -1;
    }

    size_t tot_bytes = 0;
    while (1) {
        char ch;
        const ssize_t num_read = recv(fd, &ch, 1, 0);

        if (num_read == -1) {
            if (errno == EINTR) { // Interrupted
                continue;
            } else {
                return -1;
            }
        } else if (num_read == 0) {
           break;
        } else if (ch == '\n' || ch == '\r' || ch == '\0') {
            tot_bytes++;
            if (!strip) *buf++ = ch;
            break;
        } else if (tot_bytes < bufmax - 1) {
            tot_bytes++;
            *buf++ = ch;
        } else {
            T2_WRN("Too much data to read... Discarding trailing bytes...");
        }
    }

    *buf = '\0';

    return tot_bytes;
}
