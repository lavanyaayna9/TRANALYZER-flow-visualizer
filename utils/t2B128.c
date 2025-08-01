/*
 * t2B128.c
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

// Includes
#include <stdio.h>
#include <string.h>
#include "t2B128.h"


// Functions

inline int readU128(uint128_t *g) {
   const int p = 32 * 1.6;
   uint8_t t[p + 1] = {};

   scanf("%s", t);

   const int l = strlen(t);
   if (l > p) return INPOVRFLW;

   uint128_t z = { .a = 0L };
   uint128_t k = { .a = 1L };
   uint128_t o = { .a = 0L };

   for (int i = l - 1; i >= 0; i--) {
      if (t[i] >= '0' && t[i] <= '9') z.a = (t[i] - '0');
      else return UNKWCHR;
      z.a *= k.a;
      g->a += z.a;
      if (g->a < o.a) return CALOVRFLW;
      k.a *= 10;
      o.a = g->a;
   }

   return OK;
}


inline int readX128(uint128_t *g) {
   const int p = 32;
   uint8_t t[p + 1] = {};

   scanf("%s", t);

   const int l = strlen(t);
   if (l > p) return INPOVRFLW;

   uint128_t z = { .a = 0L };
   g->a = 0L;

   for (int i = 0; i < l; i++) {
           if (t[i] >= '0' && t[i] <= '9') z.a = (t[i] - '0');
      else if (t[i] >= 'a' && t[i] <= 'f') z.a = (t[i] - 87);
      else if (t[i] >= 'A' && t[i] <= 'F') z.a = (t[i] - 55);
      else return UNKWCHR;
      g->a |= z.a;
      if (i >= l - 1) break;
      g->a <<= 4;
   }

   return OK;
}


inline void writeU128(uint128_t g) {
   uint8_t t[BUFLEND + 1] = {};
   int i, j = 0;
   for (i = 0; g.a && i < BUFLEND; i++) {
      j = g.a % 10;
      t[i] = 0x30 + j;
      g.a /= 10;
   }

   uint8_t k, m;
   for (j = 0; j < i / 2; j++) {
      k = t[j];
      m = i - j - 1;
      t[j] = t[m];
      t[m] = k;
   }

   t[i] = 0x00;

   puts(t);
}
