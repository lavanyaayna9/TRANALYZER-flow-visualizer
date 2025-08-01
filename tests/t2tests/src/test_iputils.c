#include "test_iputils.h"
#include "t2tests.h"      // for T2_ASSERT_STR_EQ, T2_ASSERT_BOOL_EQ, T2_ASSERT_UINT_EQ, ...
#include "iputils.h"      // for ipv4_to_mask, ipv6_to_mask, mask_to_ipv4, mask_to_ipv6

#include <arpa/inet.h>    // for inet_pton


bool test_ipv4_to_mask() {
    uint8_t mask;

    mask = ipv4_to_mask(0xffffffff);
    T2_ASSERT_UINT_EQ(mask, 32);

    mask = ipv4_to_mask(0xfffffffc);
    T2_ASSERT_UINT_EQ(mask, 30);

    mask = ipv4_to_mask(0xffffffc0);
    T2_ASSERT_UINT_EQ(mask, 26);

    mask = ipv4_to_mask(0xffffff00);
    T2_ASSERT_UINT_EQ(mask, 24);

    mask = ipv4_to_mask(0xffff0000);
    T2_ASSERT_UINT_EQ(mask, 16);

    mask = ipv4_to_mask(0xff000000);
    T2_ASSERT_UINT_EQ(mask, 8);

    mask = ipv4_to_mask(0xfc000000);
    T2_ASSERT_UINT_EQ(mask, 6);

    mask = ipv4_to_mask(0x80000000);
    T2_ASSERT_UINT_EQ(mask, 1);

    mask = ipv4_to_mask(0x00000000);
    T2_ASSERT_UINT_EQ(mask, 0);

    return true;
}


bool test_ipv6_to_mask() {
    uint8_t mask;
    ipAddr_t ip = {};

    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 0);

    inet_pton(AF_INET6, "f000::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 4);

    inet_pton(AF_INET6, "fc00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 6);

    inet_pton(AF_INET6, "ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 8);

    inet_pton(AF_INET6, "ffc0::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 10);

    inet_pton(AF_INET6, "ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 16);

    inet_pton(AF_INET6, "ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 24);

    inet_pton(AF_INET6, "ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 32);

    inet_pton(AF_INET6, "ffff:ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 40);

    inet_pton(AF_INET6, "ffff:ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 48);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 56);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 64);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 72);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 80);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 88);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 96);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ff00::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 104);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff::", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 112);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 120);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &ip.IPv6);
    mask = ipv6_to_mask(ip);
    T2_ASSERT_UINT_EQ(mask, 128);

    return true;
}


bool test_mask_to_ipv4() {
    uint32_t ip;

    ip = mask_to_ipv4(32);
    T2_ASSERT_UINT_EQ(ip, 0xffffffff);

    ip = mask_to_ipv4(30);
    T2_ASSERT_UINT_EQ(ip, 0xfffffffc);

    ip = mask_to_ipv4(26);
    T2_ASSERT_UINT_EQ(ip, 0xffffffc0);

    ip = mask_to_ipv4(24);
    T2_ASSERT_UINT_EQ(ip, 0xffffff00);

    ip = mask_to_ipv4(16);
    T2_ASSERT_UINT_EQ(ip, 0xffff0000);

    ip = mask_to_ipv4(8);
    T2_ASSERT_UINT_EQ(ip, 0xff000000);

    ip = mask_to_ipv4(6);
    T2_ASSERT_UINT_EQ(ip, 0xfc000000);

    ip = mask_to_ipv4(1);
    T2_ASSERT_UINT_EQ(ip, 0x80000000);

    ip = mask_to_ipv4(0);
    T2_ASSERT_UINT_EQ(ip, 0x00000000);

    return true;
}


bool test_mask_to_ipv6() {
    ipAddr_t ip = {};
    ipAddr_t expected = {};

    ip = mask_to_ipv6(0);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "f000::", &expected.IPv6);
    ip = mask_to_ipv6(4);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "fc00::", &expected.IPv6);
    ip = mask_to_ipv6(6);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ff00::", &expected.IPv6);
    ip = mask_to_ipv6(8);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffc0::", &expected.IPv6);
    ip = mask_to_ipv6(10);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff::", &expected.IPv6);
    ip = mask_to_ipv6(16);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(24);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(32);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(40);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(48);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(56);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(64);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(72);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(80);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(88);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(96);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ff00::", &expected.IPv6);
    ip = mask_to_ipv6(104);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff::", &expected.IPv6);
    ip = mask_to_ipv6(112);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", &expected.IPv6);
    ip = mask_to_ipv6(120);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &expected.IPv6);
    ip = mask_to_ipv6(128);
    T2_ASSERT_ARR_UINT_EQ(ip.IPv4x, expected.IPv4x, 4);

    return true;
}
