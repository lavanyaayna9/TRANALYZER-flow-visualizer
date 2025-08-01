#pragma once

#include <stdbool.h>

#define TESTS_T2LOG \
    T2_TEST_CASE(test_t2_log_date_localtime), \
    T2_TEST_CASE(test_t2_log_date_utc), \
    T2_TEST_CASE(test_t2_log_time), \
    T2_TEST_CASE(test_t2_log_time0), \
    T2_TEST_CASE(test_t2_log_time1), \
    T2_TEST_CASE(test_t2_log_time60), \
    T2_TEST_CASE(test_t2_log_time61), \
    T2_TEST_CASE(test_t2_log_time3600), \
    T2_TEST_CASE(test_t2_log_time3601)

bool test_t2_log_date_localtime();
bool test_t2_log_date_utc();
bool test_t2_log_time();
bool test_t2_log_time0();
bool test_t2_log_time1();
bool test_t2_log_time60();
bool test_t2_log_time61();
bool test_t2_log_time3600();
bool test_t2_log_time3601();
