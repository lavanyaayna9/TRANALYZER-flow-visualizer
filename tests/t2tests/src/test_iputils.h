#pragma once

#include <stdbool.h>

#define TESTS_IPUTILS \
    T2_TEST_CASE(test_ipv4_to_mask), \
    T2_TEST_CASE(test_ipv6_to_mask), \
    T2_TEST_CASE(test_mask_to_ipv4), \
    T2_TEST_CASE(test_mask_to_ipv6)

bool test_ipv4_to_mask();
bool test_ipv6_to_mask();
bool test_mask_to_ipv4();
bool test_mask_to_ipv6();
