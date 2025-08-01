#include "test_t2utils.h"
#include "t2tests.h"      // for T2_ASSERT_STR_EQ, T2_ASSERT_BOOL_EQ, T2_ASSERT_UINT_EQ, ...
#include "t2utils.h"      // for t2_mac_to_mac, t2_ipv4_to_compressed, t2_ipv6_to_compressed, ...


bool test_t2_str_has_prefix_empty() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_prefix(str, ""), true);
    return true;
}


bool test_t2_str_has_prefix_true() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_prefix(str, "Andy"), true);
    return true;
}


bool test_t2_str_has_prefix_case() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_prefix(str, "andy"), false);
    return true;
}


bool test_t2_str_has_prefix_false() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_prefix(str, "ndy"), false);
    return true;
}


bool test_t2_str_has_suffix_empty() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_suffix(str, ""), true);
    return true;
}


bool test_t2_str_has_suffix_true() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_suffix(str, "here"), true);
    return true;
}


bool test_t2_str_has_suffix_case() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_suffix(str, "Here"), false);
    return true;
}


bool test_t2_str_has_suffix_false() {
    const char * const str = "Andy was here";
    T2_ASSERT_BOOL_EQ(t2_str_has_suffix(str, "her"), false);
    return true;
}


bool test_t2_strdup_printf() {
    const char * const andy = "Andy";
    const char * const expected = "Andy 0x01020304 was here";
    char *str = t2_strdup_printf("%s 0x%08" PRIx32 " was here", andy, 16909060);
    T2_ASSERT_STR_EQ(str, expected, true);
    return true;
}


bool test_t2_alloc_filename() {
    char *str = t2_alloc_filename("Andy/", "was", "here", NULL);
    T2_ASSERT_STR_EQ(str, "Andy/was/here", true);
    str = t2_alloc_filename(NULL, "was", "here", NULL);
    T2_ASSERT_STR_EQ(str, "was/here", true);
    return true;
}


bool test_t2_build_filename() {
    char str[MAX_FILENAME_LEN];
    t2_build_filename(str, sizeof(str), "Andy", "was/", "here", NULL);
    T2_ASSERT_CONST_STR_EQ(str, "Andy/was/here");
    t2_build_filename(str, sizeof(str), NULL, "was/", "here", NULL);
    T2_ASSERT_CONST_STR_EQ(str, "was/here");
    return true;
}


bool test_t2_alloc_strcat() {
    char *str = t2_alloc_strcat("Andy", " was", " ", "here", NULL);
    T2_ASSERT_STR_EQ(str, "Andy was here", true);
    return true;
}


bool test_t2_strcat() {
    char str[MAX_FILENAME_LEN];
    t2_strcat(str, sizeof(str), "Andy", " ", "was", " here", NULL);
    T2_ASSERT_CONST_STR_EQ(str, "Andy was here");
    return true;
}


bool test_t2_strncpy_exit() {
    const char * const expected = "/tmp/filename.txt";

    char dest[64];
    size_t to_copy = 4;
    size_t copied = t2_strncpy(dest, expected, to_copy, sizeof(dest), T2_STRCPY_EXIT);
    T2_ASSERT_CONST_STR_EQ(dest, "/tmp");
    T2_ASSERT_UINT_EQ(copied, to_copy);
    return true;
}


bool test_t2_strncpy_empty() {
    size_t to_copy = 4;
    char dest[to_copy];
    size_t copied = t2_strncpy(dest, "/tmp/filename.txt", to_copy, sizeof(dest), T2_STRCPY_EMPTY);
    T2_ASSERT_CONST_STR_EQ(dest, "");
    T2_ASSERT_UINT_EQ(copied, 0);
    return true;
}


bool test_t2_strncpy_trunc() {
    char dest[5];
    size_t to_copy = 9;
    size_t copied = t2_strncpy(dest, "/tmp/filename.txt", to_copy, sizeof(dest), T2_STRCPY_TRUNC);
    T2_ASSERT_CONST_STR_EQ(dest, "/tmp");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strncpy_ellipsis() {
    char dest[14];
    size_t to_copy = 16;
    size_t copied = t2_strncpy(dest, "/tmp/filename.txt", to_copy, sizeof(dest), T2_STRCPY_ELLIPSIS);
    T2_ASSERT_CONST_STR_EQ(dest, "/tmp/filen...");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strcpy_exit() {
    const char * const expected = "/tmp/filename.txt";
    const size_t to_copy = strlen(expected);

    char dest[64];
    size_t copied = t2_strcpy(dest, expected, sizeof(dest), T2_STRCPY_EXIT);
    T2_ASSERT_CONST_STR_EQ(dest, expected);
    T2_ASSERT_UINT_EQ(copied, to_copy);
    return true;
}


bool test_t2_strcpy_empty() {
    char dest[14];
    size_t copied = t2_strcpy(dest, "/tmp/filename.txt", sizeof(dest), T2_STRCPY_EMPTY);
    T2_ASSERT_CONST_STR_EQ(dest, "");
    T2_ASSERT_UINT_EQ(copied, 0);
    return true;
}


bool test_t2_strcpy_trunc() {
    char dest[14];
    size_t copied = t2_strcpy(dest, "/tmp/filename.txt", sizeof(dest), T2_STRCPY_TRUNC);
    T2_ASSERT_CONST_STR_EQ(dest, "/tmp/filename");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strcpy_ellipsis() {
    char dest[14];
    size_t copied = t2_strcpy(dest, "/tmp/filename.txt", sizeof(dest), T2_STRCPY_ELLIPSIS);
    T2_ASSERT_CONST_STR_EQ(dest, "/tmp/filen...");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strncpy_escape_exit() {
    const char * const expected = "\"Hello\\World\"";

    char dest[64];
    size_t to_copy = 8;
    size_t copied = t2_strncpy_escape(dest, expected, to_copy, sizeof(dest), T2_STRCPY_EXIT);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"Hello\\\\W");
    T2_ASSERT_UINT_EQ(copied, to_copy + 2); // two extra '\'
    return true;
}


bool test_t2_strncpy_escape_empty() {
    size_t to_copy = 4;
    char dest[to_copy];
    size_t copied = t2_strncpy_escape(dest, "\"Hello\\World\"", to_copy, sizeof(dest), T2_STRCPY_EMPTY);
    T2_ASSERT_CONST_STR_EQ(dest, "");
    T2_ASSERT_UINT_EQ(copied, 0);
    return true;
}


bool test_t2_strncpy_escape_trunc() {
    char dest[5];
    size_t to_copy = 9;
    size_t copied = t2_strncpy_escape(dest, "\"Hello\\World\"", to_copy, sizeof(dest), T2_STRCPY_TRUNC);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"He");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1); // one extra '\'
    return true;
}


bool test_t2_strncpy_escape_ellipsis() {
    char dest[14];
    size_t to_copy = 16;
    size_t copied = t2_strncpy_escape(dest, "\"Hello\\World\"", to_copy, sizeof(dest), T2_STRCPY_ELLIPSIS);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"Hello\\\\W...");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strcpy_escape_exit() {
    const char * const expected = "\"Hello\\World\"";

    char dest[64];
    size_t copied = t2_strcpy_escape(dest, expected, sizeof(dest), T2_STRCPY_EXIT);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"Hello\\\\World\\\"");
    T2_ASSERT_UINT_EQ(copied, strlen(expected) + 3); // three extra '\'
    return true;
}


bool test_t2_strcpy_escape_empty() {
    char dest[5];
    size_t copied = t2_strcpy_escape(dest, "\"Hello\\World\"", sizeof(dest), T2_STRCPY_EMPTY);
    T2_ASSERT_CONST_STR_EQ(dest, "");
    T2_ASSERT_UINT_EQ(copied, 0);
    return true;
}


bool test_t2_strcpy_escape_trunc() {
    char dest[5];
    size_t copied = t2_strcpy_escape(dest, "\"Hello\\World\"", sizeof(dest), T2_STRCPY_TRUNC);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"He");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_strcpy_escape_ellipsis() {
    char dest[7];
    size_t copied = t2_strcpy_escape(dest, "\"Hello\\World\"", sizeof(dest), T2_STRCPY_ELLIPSIS);
    T2_ASSERT_CONST_STR_EQ(dest, "\\\"H...");
    T2_ASSERT_UINT_EQ(copied, sizeof(dest)-1);
    return true;
}


bool test_t2_conv_readable_num() {
    char hrnum[64];
    t2_conv_readable_num(1577658, hrnum, sizeof(hrnum), "b/s");
    const char * const expected = " (1.58 Mb/s)";
    T2_ASSERT_CONST_STR_EQ(hrnum, expected);

    T2_CONV_NUM_SFX(1577658, hrnum, "b/s");
    T2_ASSERT_CONST_STR_EQ(hrnum, expected);

    const char * const expected2 = " (1.58 M)";
    T2_CONV_NUM(1577658, hrnum);
    T2_ASSERT_CONST_STR_EQ(hrnum, expected2);

    return true;
}


bool test_t2_swap_mac() {
    ethDS_t ethDS = {
        .ether_dhost = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
        .ether_shost = { 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c },
    };
    char dest[T2_MAC_STRLEN+1];
    t2_mac_to_mac(ethDS.ether_dhost, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "01:02:03:04:05:06");
    t2_mac_to_mac(ethDS.ether_shost, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "07:08:09:0a:0b:0c");
    t2_swap_mac(&ethDS);
    t2_mac_to_mac(ethDS.ether_dhost, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "07:08:09:0a:0b:0c");
    t2_mac_to_mac(ethDS.ether_shost, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "01:02:03:04:05:06");
    return true;
}


bool test_t2_mac_to_mac() {
    uint8_t mac[ETH_ALEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    char dest[T2_MAC_STRLEN+1];
    t2_mac_to_mac(mac, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "01:02:03:04:05:06");
    return true;
}


bool test_t2_mac_to_hex() {
    uint8_t mac[ETH_ALEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    char dest[32];
    t2_mac_to_hex(mac, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "0x0000010203040506");
    return true;
}


bool test_t2_mac_to_uint() {
    uint8_t mac[ETH_ALEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    char dest[32];
    t2_mac_to_uint(mac, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "1108152157446");
    return true;
}


bool test_t2_mac_to_uint64() {
    uint8_t mac[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    T2_ASSERT_UINT_EQ(t2_mac_to_uint64(mac), 1108152157446);
    return true;
}


bool test_t2_uint64_to_mac() {
    uint64_t mac = 1108152157446;
    uint8_t expected[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    uint8_t dest[ETH_ALEN] = {};
    t2_uint64_to_mac(mac, dest);
    T2_ASSERT_ARR_UINT_EQ(dest, expected, ETH_ALEN);
    return true;
}


bool test_t2_ipv4_to_compressed() {
    char dest[INET_ADDRSTRLEN];
    struct in_addr ip = { .s_addr = 0x04030201 };
    t2_ipv4_to_compressed(ip, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "1.2.3.4");
    return true;
}


bool test_t2_ipv4_to_uncompressed() {
    char dest[INET_ADDRSTRLEN];
    struct in_addr ip = { .s_addr = 0x04030201 };
    t2_ipv4_to_uncompressed(ip, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "001.002.003.004");
    return true;
}


bool test_t2_ipv4_to_hex() {
    char dest[INET_ADDRSTRLEN];
    struct in_addr ip = { .s_addr = 0x04030201 };
    t2_ipv4_to_hex(ip, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "0x01020304");
    return true;
}


bool test_t2_ipv4_to_uint() {
    char dest[INET_ADDRSTRLEN];
    struct in_addr ip = { .s_addr = 0x04030201 };
    t2_ipv4_to_uint(ip, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "16909060");
    return true;
}


bool test_t2_ipv6_to_compressed() {
    char dest[INET6_ADDRSTRLEN];
    struct in6_addr ip6 = {};
    inet_pton(AF_INET6, "2001:db8::1", &ip6);
    t2_ipv6_to_compressed(ip6, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "2001:db8::1");
    return true;
}


bool test_t2_ipv6_to_uncompressed() {
    char dest[INET6_ADDRSTRLEN];
    struct in6_addr ip6 = {};
    inet_pton(AF_INET6, "2001:db8::1", &ip6);
    t2_ipv6_to_uncompressed(ip6, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "2001:0db8:0000:0000:0000:0000:0000:0001");
    return true;
}


bool test_t2_ipv6_to_hex128() {
    char dest[INET6_ADDRSTRLEN];
    struct in6_addr ip6 = {};
    inet_pton(AF_INET6, "2001:db8::1", &ip6);
    t2_ipv6_to_hex128(ip6, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "0x20010db8000000000000000000000001");
    return true;
}


bool test_t2_ipv6_to_hex64_hex64() {
    char dest[INET6_ADDRSTRLEN];
    struct in6_addr ip6 = {};
    inet_pton(AF_INET6, "2001:db8::1", &ip6);
    t2_ipv6_to_hex64_hex64(ip6, dest, sizeof(dest));
    T2_ASSERT_CONST_STR_EQ(dest, "0x20010db800000000_0x0000000000000001");
    return true;
}


bool test_t2_set_env() {
#define TEST_T2_SET_ENV_STR "This is a test."
#define TEST_T2_SET_ENV_NUM 42
    enum {
        ENV_TEST_T2_SET_ENV_STR,
        ENV_TEST_T2_SET_ENV_NUM,
        ENV_TEST_T2_SET_ENV_N
    };
    t2_env_t env[ENV_TEST_T2_SET_ENV_N] = {};
    T2_SET_ENV_STR(TEST_T2_SET_ENV_STR);
    T2_SET_ENV_NUM(TEST_T2_SET_ENV_NUM);
    // Test keys
    T2_ASSERT_CONST_STR_EQ(env[0].key, "TEST_T2_SET_ENV_STR");
    T2_ASSERT_CONST_STR_EQ(env[1].key, "TEST_T2_SET_ENV_NUM");
    // Test values
    T2_ASSERT_CONST_STR_EQ(env[0].val, "This is a test.");
    T2_ASSERT_CONST_STR_EQ(env[1].val, "42");
#undef TEST_T2_SET_ENV_VAL1
#undef TEST_T2_SET_ENV_VAL2
    return true;
}
