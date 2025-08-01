/*
 * t2asm.h
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

#ifndef T2_T2ASM_H_INCLUDED
#define T2_T2ASM_H_INCLUDED

// Rotate left
#define T2_ROL(reg, shift, x) ((reg) = (((reg) << (shift)) | ((reg) >> ((x) - (shift)))))

#define T2_ROL64(reg, shift) T2_ROL((reg), (shift), 64)
#define T2_ROL32(reg, shift) T2_ROL((reg), (shift), 32)
#define T2_ROL16(reg, shift) T2_ROL((reg), (shift), 16)
#define T2_ROL8( reg, shift) T2_ROL((reg), (shift),  8)

// Rotate right
#define T2_ROR(reg, shift, x) ((reg) = (((reg) >> (shift)) | ((reg) << ((x) - (shift)))))

#define T2_ROR64(reg, shift) T2_ROR((reg), (shift), 64)
#define T2_ROR32(reg, shift) T2_ROR((reg), (shift), 32)
#define T2_ROR16(reg, shift) T2_ROR((reg), (shift), 16)
#define T2_ROR8( reg, shift) T2_ROR((reg), (shift),  8)

// Nibble swap

#define NSWP(v) ((v) = (((v) >> 4) | ((v) << 4)))

// Bit inversion to register boundary

#define BINV_64(v) { \
    (v) = ((((v) & 0xaaaaaaaaaaaaaaaa) >>  1) | (((v) & 0x5555555555555555) <<  1)); \
    (v) = ((((v) & 0xcccccccccccccccc) >>  2) | (((v) & 0x3333333333333333) <<  2)); \
    (v) = ((((v) & 0xf0f0f0f0f0f0f0f0) >>  4) | (((v) & 0x0f0f0f0f0f0f0f0f) <<  4)); \
    (v) = ((((v) & 0xff00ff00ff00ff00) >>  8) | (((v) & 0x00ff00ff00ff00ff) <<  8)); \
    (v) = ((((v) & 0xffff0000ffff0000) >> 16) | (((v) & 0x0000ffff0000ffff) << 16)); \
    (v) = (((v) >> 32) | ((v) << 32)); \
}

#define BINV_32(v) { \
    (v) = ((((v) & 0xaaaaaaaa) >> 1) | (((v) & 0x55555555) << 1)); \
    (v) = ((((v) & 0xcccccccc) >> 2) | (((v) & 0x33333333) << 2)); \
    (v) = ((((v) & 0xf0f0f0f0) >> 4) | (((v) & 0x0f0f0f0f) << 4)); \
    (v) = ((((v) & 0xff00ff00) >> 8) | (((v) & 0x00ff00ff) << 8)); \
    (v) = (((v) >> 16) | ((v) << 16)); \
}

#define BINV_16(v) { \
    (v) = ((((v) & 0xaaaa) >> 1) | (((v) & 0x5555) << 1)); \
    (v) = ((((v) & 0xcccc) >> 2) | (((v) & 0x3333) << 2)); \
    (v) = ((((v) & 0xf0f0) >> 4) | (((v) & 0x0f0f) << 4)); \
    (v) = (((v) >> 8) | ((v) << 8)); \
}

#define BINV_8(v) { \
    (v) = ((((v) & 0xaa) >> 1) | (((v) & 0x55) << 1)); \
    (v) = ((((v) & 0xcc) >> 2) | (((v) & 0x33) << 2)); \
    (v) = (((v) >> 4) | ((v) << 4)); \
}

// Alignment of bit inverstion to N boundary
#define LGIBP8(v, n)  ((v) >> (uint8_t) ( 8 - log(n) / log(2)))
#define LGIBP16(v, n) ((v) >> (uint16_t)(16 - log(n) / log(2)))
#define LGIBP32(v, n) ((v) >> (uint32_t)(32 - log(n) / log(2)))
#define LGIBP64(v, n) ((v) >> (uint64_t)(64 - log(n) / log(2)))


#endif // T2_T2ASM_H_INCLUDED
