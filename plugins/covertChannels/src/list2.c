/*
 * list2.c
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

#include <list2.h>
#include <stdio.h>
#include <stlib.h>

list2_t* list2_new(size_t size) {
    if (size > 1 >> 32) {
        fprintf(stderr, "list2 maximum size is 2^32\n");
        exit(2);
    }
    list2_t* l = malloc(sizeof(list2_t));
    if (!l) {
        perror("list2_new");
        exit(2);
    }
    l->time = (double*) calloc(size, sizeof(double));
    l->y = (uint16_t*) calloc(size, sizeof(uint16_t));
    if (!l->time || !l->y) {
        perror("list2_new");
        exit(2);
    }
    l->start = 0;
    l->end = 0;
    l->space = size;
    return l;
}

void list2_append(list2_t* l, double time, uint16_t size) {
    l->end = (l->end + 1) % l->space;
    if (l->end == l->start) {
        fprintf(stderr, "list2 is full, try allocating more space in list2_new\n");
        exit(2);
    }
    l->time[l->end] = time;
    l->y[l->end] = size;
}

void list2_del_until(list2_t* l, double time) {
    while (l->time[l->start] < time && l->start != l->end) {
        l->start = (l->start + 1) % l->space;
    }
}

float smallestPackets(list2_t* l) {
    uint16_t e, s1 = 0xFFFF, s2 = 0xFFFF, s3 = 0xFFFF;
    size_t i, pkts = (l->end + l->space - l->start) % l->space;
    if (pkts < 3)
        return -1.0f;
    for (i = 0; i < pkts; i++) {
        e = l->size[(l->start + i) % l->space];
        if (e < s1) {
            s3 = s2; s2 = s1; s1 = e;
        } else if (e < s2) {
            s3 = s2; s2 = e;
        } else if (e < s3) {
            s3 = e;
        }
    }
    return ((float) s1 + s2 + s3) / 3.0f;
}
