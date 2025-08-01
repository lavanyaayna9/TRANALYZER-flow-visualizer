/*
 * list2.h
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

#ifndef TRANALYZER_LIST2_H_
#define TRANALYZER_LIST2_H_

/* This structure is used to represent a 2-dimensional "list"
 * It is quick and dirty code for the sliding window algorithm
 * of SkyDe and shouldn't be used anywhere else. */
typedef struct list2_s {
    double* time;
    uint16_t* size;
    uint32_t start;
    uint32_t end;
    size_t space;
} list2_t;


list2_t* list2_new(size_t size);
void list2_append(list2_t* l, double time, uint16_t size);
void list2_del_until(list2_t* l, double time);
float smallestPackets(list2_t* l);

#endif // TRANALYZER_LIST2_H_
