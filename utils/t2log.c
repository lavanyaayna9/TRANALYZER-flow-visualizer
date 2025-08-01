/*
 * t2log.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "t2log.h"

#include <inttypes.h>  // for PRIuFAST8, PRIuFAST16
#include <stdint.h>    // for uint_fast8_t, intmax_t, uint_fast16_t
#include <time.h>      // for strftime, gmtime, localtime, time_t


inline void t2_log_date(FILE *stream, const char *prefix, struct timeval date, bool utc) {
    const time_t sec = (uint32_t)date.tv_sec;
    const intmax_t usec = date.tv_usec;

    const struct tm * const t = utc ? gmtime(&sec) : localtime(&sec);
    if (UNLIKELY(!t)) {
        fprintf(stream, "%s%" PRIu32 ".%" T2_PRI_USEC " sec (<invalid>)\n",
                prefix ? prefix : "", (uint32_t)sec, usec);
        return;
    }

    char time[MAX_TM_BUF];
    strftime(time, sizeof(time), "%a %d %b %Y %X", t);

    char offset[MAX_TM_BUF];
    strftime(offset, sizeof(offset), "%Z", t);

    fprintf(stream, "%s%"PRIu32".%" T2_PRI_USEC " sec (%s %s)\n",
            prefix ? prefix : "", (uint32_t)sec, usec, time, offset);
}


inline void t2_log_time(FILE *stream, const char *prefix, struct timeval time) {
    const uint32_t s  = time.tv_sec;
    const intmax_t us = time.tv_usec;

    const uint_fast16_t years = s / 3600. / 24. / 365.;
    const uint_fast16_t days  = s / 3600. / 24. - years * 365;
    const uint_fast8_t  hours = s / 3600. - years * 365 * 24 - days * 24;
    const uint_fast8_t  mins  = s / 60. - hours * 60 - days * 24 * 60 - years * 365 * 24 * 60;
    const uint_fast8_t  secs  = s % 60;

    fprintf(stream, "%s%" PRIu32 ".%" T2_PRI_USEC " sec", prefix ? prefix : "", s, us);
    if (years + days + hours + mins) {
        fputs(" (", stream);
        if (years) fprintf(stream,   "%" PRIuFAST32 "y", years);
        if (days)  fprintf(stream, "%s%" PRIuFAST16 "d", years ? " " : "", days);
        if (hours) fprintf(stream, "%s%" PRIuFAST8  "h", years || days ? " " : "", hours);
        if (mins)  fprintf(stream, "%s%" PRIuFAST8  "m", years || days || hours ? " " : "", mins);
        if (secs)  fprintf(stream,  " %" PRIuFAST8  "s", secs);
        fputc(')', stream);
    }
    fputc('\n', stream);
}
