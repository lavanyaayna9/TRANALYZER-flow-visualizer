#include "test_t2log.h"
#include "t2tests.h"      // for T2_ASSERT_CONST_STR_EQ
#include "t2log.h"        // for ipv4_to_mask, ipv6_to_mask, mask_to_ipv4, mask_to_ipv6
#include <stdio.h>


bool test_t2_log_date_localtime() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec  = 1701868462,
        .tv_usec = 424344454
    };

    t2_log_date(file, "My PREFIX ", time, false);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 1701868462.424344454 sec (Wed 06 Dec 2023 14:14:22 CET)");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_date_utc() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec  = 1701868462,
        .tv_usec = 424344454
    };

    t2_log_date(file, "My PREFIX ", time, true);
    fflush(file);
    buf[size-1] = '\0';

#ifdef __APPLE__
    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 1701868462.424344454 sec (Wed 06 Dec 2023 13:14:22 UTC)");
#else // !__APPLE__
    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 1701868462.424344454 sec (Wed 06 Dec 2023 13:14:22 GMT)");
#endif // !__APPLE__

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec  = 1701868462,
        .tv_usec = 424344454
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 1701868462.424344454 sec (53y 352d 13h 14m 22s)");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time0() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {};

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 0.000000000 sec");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time1() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec = 1
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 1.000000000 sec");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time60() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec = 60
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 60.000000000 sec (1m)");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time61() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec = 61
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 61.000000000 sec (1m 1s)");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time3600() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec = 3600
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 3600.000000000 sec (1h)");

    fclose(file);
    free(buf);

    return true;
}


bool test_t2_log_time3601() {
    char *buf;
    size_t size;
    FILE *file = open_memstream(&buf, &size);
    if (!file) return false;

    struct timeval time = {
        .tv_sec = 3601
    };

    t2_log_time(file, "My PREFIX ", time);
    fflush(file);
    buf[size-1] = '\0';

    T2_ASSERT_CONST_STR_EQ(buf, "My PREFIX 3601.000000000 sec (1h 1s)");

    fclose(file);
    free(buf);

    return true;
}
