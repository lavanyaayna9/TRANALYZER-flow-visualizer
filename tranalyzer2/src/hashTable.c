/*
 * hashTable.c
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

#include "hashTable.h"

#include <inttypes.h>     // for PRIu32
#include <math.h>         // for ceilf
#include <stdint.h>       // for uint32_t, uint_fast32_t, uint64_t
#include <stdlib.h>       // for free, NULL, size_t
#include <string.h>       // for memcmp, memcpy, strlen

#include "flow.h"         // for RMFLOW_HFULL
#include "main.h"         // for mainHashMap, globalWarn, lruRmLstFlow, captureFileSize
#include "t2log.h"        // for T2_ERR, T2_PERR, T2_PINF, T2_PWRN
#include "t2stats.h"      // for numPackets, bytesProcessed
#include "t2utils.h"      // for t2_[cm]alloc, UNLIKELY, LIKELY, MIN
#include "tranalyzer.h"   // for DEBUG, HASHCHAINTABLE_BASE_SIZE, HASHFACTOR

#if T2_HASH_FUNC == 14 || T2_HASH_FUNC == 13
#include "hash/t1ha/t1ha.h"  // for t1ha0, t1ha2_atonce
#elif T2_HASH_FUNC > 10
#include "hash/fasthash.h"   // for fasthash32, fasthash64
#elif T2_HASH_FUNC == 10
#include "hash/wyhash.h"     // for wyhash
#elif T2_HASH_FUNC == 9
#include "hash/hashlittle.h" // for hashlittle
#elif T2_HASH_FUNC == 8
//#define MUM_V1             // Uncomment to use MUM-hash version 1 instead of 3
//#define MUM_V2             // Uncomment to use MUM-hash version 2 instead of 3
#include "hash/mum.h"        // for mum_hash
#elif T2_HASH_FUNC == 7
#include "hash/city.h"       // for CityHash64
#elif T2_HASH_FUNC == 6 || T2_HASH_FUNC == 5
#define XXH_INLINE_ALL
#include "hash/xxhash.h"     // for XXH3_64bits, XXH3_128bits
#elif T2_HASH_FUNC == 4
#define XXH_INLINE_ALL
#define XXH_NO_XXH3
#include "hash/xxhash.h"     // for XXH64
#elif T2_HASH_FUNC == 3
#define XXH_INLINE_ALL
#define XXH_NO_LONG_LONG
#define XXH_NO_XXH3
#include "hash/xxhash.h"     // for XXH32
#elif T2_HASH_FUNC == 2 || T2_HASH_FUNC == 1
#include "hash/murmur3.h"    // for MurmurHash3_x86_32, MurmurHash3_x64_128
#endif // T2_HASH_FUNC == 1 || T2_HASH_FUNC == 2


// Variables

uint32_t hashFactor = HASHFACTOR;


// Functions prototypes

#if HASHTABLE_DEBUG != 0
static void hashTable_print(hashMap_t *hashMap, const char *title);
#endif


/*
 * Initialize a hashMap
 *   - 'scaleFactor' can be used to change the base size of the hash table
 *   - 'name' is used for error reporting
 */
hashMap_t *hashTable_init(float scaleFactor, unsigned long dataLen, const char *name) {
#if DEBUG != 0
    if (scaleFactor < 1.0f) T2_WRN("Scale factor for hashMap is smaller than 1.0");
#endif

    hashMap_t *hashMap = t2_calloc_fatal(1, sizeof(*hashMap));

    const size_t len = name ? strlen(name) : 0;
    if (len > 0) {
        memcpy(hashMap->name, name, MIN(len, HASHTABLE_NAME_LEN));
    }

    hashMap->dataLen = dataLen;

    const float factor = hashFactor * scaleFactor;

    hashMap->hashTableSize = ceilf(HASHTABLE_BASE_SIZE * factor);
    hashMap->hashTable = t2_calloc_fatal(hashMap->hashTableSize, sizeof(hashBucket_t*));

    hashMap->hashChainTableSize = ceilf(HASHCHAINTABLE_BASE_SIZE * factor);
    hashMap->hashChainTable = t2_calloc_fatal(hashMap->hashChainTableSize, sizeof(hashBucket_t));

    const unsigned long size = hashMap->hashChainTableSize;

    char *data = t2_malloc_fatal(size * dataLen);

    uint_fast32_t i, pos = 0;
    // note the 'minus one' (last bucket has no next bucket)
    for (i = 0; i < size - 1; i++, pos += dataLen) {
        hashMap->hashChainTable[i].data = &data[pos];
        hashMap->hashChainTable[i].nextBucket = &hashMap->hashChainTable[i + 1];
    }
    hashMap->hashChainTable[i].data = &data[pos]; // last bucket

    hashMap->freeBucket = &hashMap->hashChainTable[0];
    hashMap->freeListSize = hashMap->hashChainTableSize;

#if HASHTABLE_DEBUG != 0
    hashTable_print(hashMap, "init");
#endif

    return hashMap;
}


/*
 * Return the index where 'data' is stored in 'hashMap'.
 * Return HASHTABLE_ENTRY_NOT_FOUND if 'data' could not be found.
 */
inline unsigned long hashTable_lookup(hashMap_t *hashMap, const char *data) {
    const unsigned long hash = hashTable_hash(data, hashMap->dataLen) % hashMap->hashTableSize;
    hashBucket_t *currBucket = hashMap->hashTable[hash];
    while (currBucket) {
        if (memcmp(currBucket->data, data, hashMap->dataLen) == 0) {
            return (currBucket - hashMap->hashChainTable);
        }

        currBucket = currBucket->nextBucket;
    }

    return HASHTABLE_ENTRY_NOT_FOUND;
}


/*
 * Generate a hash value
 */
inline unsigned long hashTable_hash(const char *data, unsigned long dataLen) {
#if T2_HASH_FUNC == 14
    static const uint64_t seed = 0;
    return t1ha2_atonce(data, dataLen, seed);
#elif T2_HASH_FUNC == 13
    static const uint64_t seed = 0;
    return t1ha0(data, dataLen, seed);
#elif T2_HASH_FUNC == 12
    static const uint32_t seed = 0;
    return fasthash32(data, dataLen, seed);
#elif T2_HASH_FUNC == 11
    static const uint64_t seed = 0;
    return fasthash64(data, dataLen, seed);
#elif T2_HASH_FUNC == 10
    static const uint64_t seed = 0;
    return wyhash(data, dataLen, seed, _wyp);
#elif T2_HASH_FUNC == 9
    static const uint32_t seed = 0;
    return hashlittle(data, dataLen, seed);
#elif T2_HASH_FUNC == 8
    static const uint64_t seed = 0;
    return mum_hash(data, dataLen, seed);
#elif T2_HASH_FUNC == 7
    return CityHash64(data, dataLen);
#elif T2_HASH_FUNC == 6
    return XXH3_128bits(data, dataLen).low64;
#elif T2_HASH_FUNC == 5
    return XXH3_64bits(data, dataLen);
#elif T2_HASH_FUNC == 4
    static const unsigned long long seed = 0;
    return XXH64(data, dataLen, seed);
#elif T2_HASH_FUNC == 3
    static const unsigned int seed = 0;
    return XXH32(data, dataLen, seed);
#elif T2_HASH_FUNC == 2
    static const uint32_t seed = 0;
    uint64_t hash[2] = {};
    MurmurHash3_x64_128(data, dataLen, seed, &hash);
    return hash[0];
#elif T2_HASH_FUNC == 1
    static const uint32_t seed = 0;
    uint32_t hash = 0;
    MurmurHash3_x86_32(data, dataLen, seed, &hash);
    return hash;
#else // T2_HASH_FUNC == 0
    unsigned long hash = 0;
    for (unsigned long i = 0; i < dataLen; i++) {
        hash += data[i];
        hash += (hash << 10);
        hash ^= (hash >>  6);
    }

    hash += (hash <<  3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
#endif // T2_HASH_FUNC == 0
}


/*
 * Insert a combination of all parameters in hashMap
 */
inline unsigned long hashTable_insert(hashMap_t *hashMap, const char *data) {
    if (UNLIKELY(hashMap->freeListSize == 0)) {
        if (!(globalWarn & RMFLOW_HFULL) && (hashMap == mainHashMap)) {
            uint32_t f = captureFileSize / (24 + bytesProcessed + numPackets * 16);
            if (f < 2) f = 2;
            if (f > 16) {
                f = 16;
#if HASH_AUTOPILOT == 1
            }
            T2_PWRN("Hash Autopilot", "%s HashMap full: flushing %d oldest flow(s)", hashMap->name, NUMFLWRM);
            T2_PINF("Hash Autopilot", "Fix: Invoke Tranalyzer with '-f %" PRIu32 "'", f * hashFactor);
        }
        if (hashMap == mainHashMap) {
            lruRmLstFlow();
        } else {
            T2_ERR("%s HashMap full, Invoke t2 with -f 2", hashMap->name);
            terminate();
            //return HASHTABLE_ENTRY_NOT_FOUND;
        }
#else // HASH_AUTOPILOT == 0
                T2_ERR("%s HashMap full", hashMap->name);
                T2_INF("Fix: Invoke Tranalyzer with '-f %" PRIu32 "'", hashFactor * f / 4);
            } else {
                T2_ERR("%s HashMap full", hashMap->name);
                T2_INF("Fix: Invoke Tranalyzer with '-f %" PRIu32 "'", f * hashFactor);
            }
        }
        if (hashMap != mainHashMap) T2_ERR("%s HashMap full, Invoke t2 with -f 2", hashMap->name);
        terminate();
#endif // HASH_AUTOPILOT
    }

    const unsigned long hash = hashTable_hash(data, hashMap->dataLen) % hashMap->hashTableSize;

    /* take a free bucket from the front of the free list */
    hashBucket_t *currBucket = hashMap->freeBucket;
    hashMap->freeBucket = hashMap->freeBucket->nextBucket;

    /* point the next pointer on the current first bucket */
    currBucket->nextBucket = hashMap->hashTable[hash];

    /* place the current bucket at the front of the hashTable */
    hashMap->hashTable[hash] = currBucket;

    /* fill it with the right values */
    memcpy(currBucket->data, data, hashMap->dataLen);

    hashMap->freeListSize--;

#if HASHTABLE_DEBUG != 0
    hashTable_print(hashMap, "insert");
#endif

    return (currBucket - hashMap->hashChainTable);
}


/*
 * Remove a combination of all parameters in hashMap
 */
inline unsigned long hashTable_remove(hashMap_t *hashMap, const char *data) {
    const unsigned long hash = hashTable_hash(data, hashMap->dataLen) % hashMap->hashTableSize;
    hashBucket_t *currBucket = hashMap->hashTable[hash];
    hashBucket_t *prevBucket = currBucket;
    while (currBucket) {
        if (memcmp(currBucket->data, data, hashMap->dataLen) == 0) {

            /* set the pointers of the hashBucket */
            if (prevBucket == currBucket) {
                hashMap->hashTable[hash] = currBucket->nextBucket;
            } else {
                prevBucket->nextBucket = currBucket->nextBucket;
            }

            /* reinsert bucket into free list */
            currBucket->nextBucket = hashMap->freeBucket;
            hashMap->freeBucket = currBucket;

            hashMap->freeListSize++;

#if HASHTABLE_DEBUG != 0
            hashTable_print(hashMap, "remove");
#endif

            return 0;
        }

        prevBucket = currBucket;
        currBucket = currBucket->nextBucket;
    }

    return HASHTABLE_ENTRY_NOT_FOUND;
}


void hashTable_destroy(hashMap_t *hashMap) {
    if (UNLIKELY(!hashMap)) return;

    if (LIKELY(hashMap->hashChainTable != NULL)) {
        free(hashMap->hashChainTable[0].data);
        hashMap->hashChainTable[0].data = NULL;
        free(hashMap->hashChainTable);
        hashMap->hashChainTable = NULL;
    }

    free(hashMap->hashTable);
    hashMap->hashTable = NULL;

    free(hashMap);
}


#if HASHTABLE_DEBUG != 0
static void hashTable_print(hashMap_t *hashMap, const char *title) {
    fprintf(stdout, "HashTable after %-6s: -----------------------------------\n", title);
    unsigned long j;
    hashBucket_t *bucket;
    const unsigned long size = hashMap->hashTableSize;
    for (unsigned long i = 0; i < size; i++) {
        fprintf(stdout, "%ld:", i);
        j = 0;
        bucket = hashMap->hashTable[i];
        while (bucket) {
            j++;
            bucket = bucket->nextBucket;
        }
        fprintf(stdout, "%ld\n", j);
    }
    fprintf(stdout, "-----------------------------------------------------------\n");
}
#endif // HASHTABLE_DEBUG != 0
