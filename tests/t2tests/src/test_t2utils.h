#pragma once

#include <stdbool.h>

#define TESTS_T2UTILS \
    T2_TEST_CASE(test_t2_str_has_prefix_empty)    , \
    T2_TEST_CASE(test_t2_str_has_prefix_true)     , \
    T2_TEST_CASE(test_t2_str_has_prefix_case)     , \
    T2_TEST_CASE(test_t2_str_has_prefix_false)    , \
    T2_TEST_CASE(test_t2_str_has_suffix_empty)    , \
    T2_TEST_CASE(test_t2_str_has_suffix_true)     , \
    T2_TEST_CASE(test_t2_str_has_suffix_case)     , \
    T2_TEST_CASE(test_t2_str_has_suffix_false)    , \
    T2_TEST_CASE(test_t2_strdup_printf)           , \
    T2_TEST_CASE(test_t2_alloc_filename)          , \
    T2_TEST_CASE(test_t2_build_filename)          , \
    T2_TEST_CASE(test_t2_alloc_strcat)            , \
    T2_TEST_CASE(test_t2_strcat)                  , \
    T2_TEST_CASE(test_t2_strncpy_exit)            , \
    T2_TEST_CASE(test_t2_strncpy_empty)           , \
    T2_TEST_CASE(test_t2_strncpy_trunc)           , \
    T2_TEST_CASE(test_t2_strncpy_ellipsis)        , \
    T2_TEST_CASE(test_t2_strcpy_exit)             , \
    T2_TEST_CASE(test_t2_strcpy_empty)            , \
    T2_TEST_CASE(test_t2_strcpy_trunc)            , \
    T2_TEST_CASE(test_t2_strcpy_ellipsis)         , \
    T2_TEST_CASE(test_t2_strncpy_escape_exit)     , \
    T2_TEST_CASE(test_t2_strncpy_escape_empty)    , \
    T2_TEST_CASE(test_t2_strncpy_escape_trunc)    , \
    T2_TEST_CASE(test_t2_strncpy_escape_ellipsis) , \
    T2_TEST_CASE(test_t2_strcpy_escape_exit)      , \
    T2_TEST_CASE(test_t2_strcpy_escape_empty)     , \
    T2_TEST_CASE(test_t2_strcpy_escape_trunc)     , \
    T2_TEST_CASE(test_t2_strcpy_escape_ellipsis)  , \
    T2_TEST_CASE(test_t2_conv_readable_num)       , \
    T2_TEST_CASE(test_t2_swap_mac)                , \
    T2_TEST_CASE(test_t2_mac_to_mac)              , \
    T2_TEST_CASE(test_t2_mac_to_hex)              , \
    T2_TEST_CASE(test_t2_mac_to_uint)             , \
    T2_TEST_CASE(test_t2_mac_to_uint64)           , \
    T2_TEST_CASE(test_t2_uint64_to_mac)           , \
    T2_TEST_CASE(test_t2_ipv4_to_compressed)      , \
    T2_TEST_CASE(test_t2_ipv4_to_uncompressed)    , \
    T2_TEST_CASE(test_t2_ipv4_to_hex)             , \
    T2_TEST_CASE(test_t2_ipv4_to_uint)            , \
    T2_TEST_CASE(test_t2_ipv6_to_compressed)      , \
    T2_TEST_CASE(test_t2_ipv6_to_uncompressed)    , \
    T2_TEST_CASE(test_t2_ipv6_to_hex128)          , \
    T2_TEST_CASE(test_t2_ipv6_to_hex64_hex64)     , \
    T2_TEST_CASE(test_t2_set_env)

bool test_t2_str_has_prefix_empty();
bool test_t2_str_has_prefix_true();
bool test_t2_str_has_prefix_case();
bool test_t2_str_has_prefix_false();

bool test_t2_str_has_suffix_empty();
bool test_t2_str_has_suffix_true();
bool test_t2_str_has_suffix_case();
bool test_t2_str_has_suffix_false();

bool test_t2_strdup_printf();

bool test_t2_alloc_filename();
bool test_t2_build_filename();
bool test_t2_alloc_strcat();
bool test_t2_strcat();
bool test_t2_strncpy_exit();
bool test_t2_strncpy_empty();
bool test_t2_strncpy_trunc();
bool test_t2_strncpy_ellipsis();
bool test_t2_strcpy_exit();
bool test_t2_strcpy_empty();
bool test_t2_strcpy_trunc();
bool test_t2_strcpy_ellipsis();
bool test_t2_strncpy_escape_exit();
bool test_t2_strncpy_escape_empty();
bool test_t2_strncpy_escape_trunc();
bool test_t2_strncpy_escape_ellipsis();
bool test_t2_strcpy_escape_exit();
bool test_t2_strcpy_escape_empty();
bool test_t2_strcpy_escape_trunc();
bool test_t2_strcpy_escape_ellipsis();

bool test_t2_conv_readable_num();

// MAC addresses conversion
bool test_t2_swap_mac();
bool test_t2_mac_to_mac();
bool test_t2_mac_to_hex();
bool test_t2_mac_to_uint();
bool test_t2_mac_to_uint64();
bool test_t2_uint64_to_mac();

// IPv4 addresses conversion
bool test_t2_ipv4_to_compressed();
bool test_t2_ipv4_to_uncompressed();
bool test_t2_ipv4_to_hex();
bool test_t2_ipv4_to_uint();

// IPv6 addresses conversion
bool test_t2_ipv6_to_compressed();
bool test_t2_ipv6_to_uncompressed();
bool test_t2_ipv6_to_hex128();
bool test_t2_ipv6_to_hex64_hex64();

// Environment constant control
bool test_t2_set_env();
