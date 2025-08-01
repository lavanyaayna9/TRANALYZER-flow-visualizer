#pragma once

#include <inttypes.h> // for PRIu64
#include <stdbool.h>  // for bool
#include <stdio.h>    // for printf, fprintf, fflush
#include <stdlib.h>   // for free
#include <string.h>   // for strcmp


#define T2_PRI_GREEN(format, args...) fprintf(stdout, "\e[1;32m" format "\e[0m\n", ##args)
#define T2_PRI_RED(format, args...)   fprintf(stderr, "\e[1;31m" format "\e[0m\n", ##args)

#define T2_PRI_PASS() T2_PRI_GREEN("PASS")
#define T2_PRI_FAIL() T2_PRI_RED("FAIL")

#define T2_TEST_CASE(func) { #func, func }

#define T2_PRINT(format, args...) printf("        Line %d: " format "\n", __LINE__, ##args);

#define T2_TEST_NOT_IMPLEMENTED() { \
    fflush(stdout); \
    T2_PRI_FAIL(); \
    T2_PRINT("Not implemented"); \
    return false; \
}

#define T2_ASSERT_BOOL_EQ(found, expected) \
    if ((found) != (expected)) { \
        fflush(stdout); \
        T2_PRI_FAIL(); \
        T2_PRINT("Expected '%s' but found '%s'", expected ? "true" : "false", found ? "true" : "false"); \
        return false; \
    }

#define T2_ASSERT_STR_EQ(found, expected, free_found) \
    if (strcmp(found, expected) == 0) { \
        if (free_found) { \
            free(found); \
        } \
    } else { \
        fflush(stdout); \
        T2_PRI_FAIL(); \
        T2_PRINT("Expected '%s' but found '%s'", expected, found); \
        if (free_found) { \
            free(found); \
        } \
        return false; \
    }

#define T2_ASSERT_CONST_STR_EQ(found, expected) \
    if (strcmp(found, expected) != 0) { \
        fflush(stdout); \
        T2_PRI_FAIL(); \
        T2_PRINT("Expected '%s' but found '%s'", expected, found); \
        return false; \
    }

#define T2_ASSERT_UINT_EQ(found, expected) \
    if (found != expected) { \
        fflush(stdout); \
        T2_PRI_FAIL(); \
        T2_PRINT("Expected '%" PRIu64"' but found '%" PRIu64 "'", (uint64_t)expected, (uint64_t)found); \
        return false; \
    }

#define T2_ASSERT_ARR_UINT_EQ(found, expected, size) { \
    int nfail = 0; \
    int fail[(size)]; \
    for (int i = 0; i < (size); i++) { \
        if ((found)[i] != (expected)[i]) { \
            fail[nfail++] = i; \
        } \
    } \
    if (nfail > 0) { \
        fflush(stdout); \
        T2_PRI_FAIL(); \
        for (int i = 0; i < nfail; i++) { \
            int elem = fail[i]; \
            T2_PRINT("Expected element [%d] to be '%" PRIu64"' but found '%" PRIu64 "'", elem, (uint64_t)(expected[elem]), (uint64_t)(found[elem])); \
        } \
        return false; \
    } \
}

typedef bool (*t2_test_func_t)();
