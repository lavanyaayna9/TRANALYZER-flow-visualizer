/*
 * Wikipedia implementation: https://en.wikipedia.org/wiki/MurmurHash#Algorithm
 * License: Creative Commons Attribution-ShareAlike 3.0 Unported
 */

#include <stdint.h>

uint32_t murmur3_32(const char *key, uint32_t len, uint32_t seed);
