/*
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define DEL "\"],\""


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: tjx torjsonfile\n");
        exit(EXIT_FAILURE);
    }

    FILE *file;
    if (!(file = fopen(argv[1], "r"))) {
        printf("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    const char * const key[] = {
        "nickname\":",
        "or_addresses\":\[",
        "exit_addresses\":\[",
        "dir_address\":",
        "country\":",
        "region_name\":",
        "city_name\":",
        "latitude\":",
        "longitude\":",
        "as\":\"AS",
        "as_name\":",
        "verified_host_names\":\["
    };

    int i, n;
    size_t len = 0, m;
    char *line = NULL, *p = NULL, *pa = "NULL", *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL, *pe = NULL;
    while (getline(&line, &len, file) != -1) {
        m = strlen(line);
        if (line[0] == '#' || m < 100) continue;
        p = line;
        pe = p + m;

        for (i = 0; i < 12; i++) {
            n = strlen(key[i])-1;
            if (p) {
                pa = memmem(p, m, key[i], n);
                if (pa >= pe) break;
                if (pa) {
                    p1 = pa + n + 1;
                    p3 = strstr(p1, DEL);
                    if (*p1 == '\"') p1++;
                    strtok(p1,",");
                    n = strlen(p1)-1;
                    if (p1[n] == '\"') p1[n] = '\0';
                    else if (p1[--n] == '\"') p1[n] = '\0';

                    if (strchr(p1, '.')) {
                        p4 = strchr(p1, ':');
                        if (p4) *p4 = '\0';
                    }

                    printf("%s", p1);

                    if (*(p1-2) == '[') {
                        if (p3) *p3= '\0';
                        do {
                            p2 = strtok(NULL, ",");
                            if (p2 == NULL || p2 >= p3) break;
                            putchar(';');
                            p4 = strchr(p2, ']');
                            if (p4) {
                                p2++;
                                *p4 = '\0';
                            } else if (strchr(p2, '.')) {
                                p4 = strchr(p2, ':');
                                if (p4) *p4 = '\0';
                            }
                            printf("%s", ++p2);
                        } while (p2);
                    }

                    if (i > 0 && i < 3) putchar('\t');
                    else putchar('\t');
                    p = pa;
                    m = pe - pa;
                } else printf ("-\t");
            }
        }
        putchar('\n');
    }

    fclose(file);

    return EXIT_SUCCESS;
}
