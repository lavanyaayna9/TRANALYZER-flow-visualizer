#include "t2tests.h"
#include "test_iputils.h"
#include "test_t2base64.h"
#include "test_t2log.h"
#include "test_t2utils.h"

#include "t2utils.h"


#define T2_TEST_FUNC_BEGIN(index) \
    printf("\e[1;33m    %2d: %-32s\e[00m ", index+1, tests[index].name)

#define T2_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))


static struct {
    const char *name;
    t2_test_func_t func;
} tests[] = {
    TESTS_IPUTILS,
    TESTS_T2BASE64,
    TESTS_T2LOG,
    TESTS_T2UTILS,
    { NULL, NULL },
};


void usage(const char *self) {
    printf("Usage:\n");
    printf("    %s test_number\n\n", self);
    printf("Available tests:\n");
    printf("    %2d) run all the tests\n", 0);
    for (int i = 0; tests[i].name; i++) {
        printf("    %2d) %s\n", i+1, tests[i].name);
    }
}


int main(int argc, char **argv) {

    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return (argc < 2) ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    int test = atoi(argv[1]);

    const int num_tests = T2_ARRAY_SIZE(tests);

    if (test < 0 || test > num_tests) {
        fprintf(stderr, "Invalid test number %d\n\n", test);
        return EXIT_FAILURE;
    }

    if (test > 0) {
        test -= 1;
        T2_TEST_FUNC_BEGIN(test);
        if (tests[test].func()) {
            T2_PRI_PASS();
        }
    } else {
        printf("\nRunning through all the tests...\n\n");
        int i;
        int failed = 0;
        bool results[num_tests];
        for (i = 0; tests[i].func; i++) {
            T2_TEST_FUNC_BEGIN(i);
            if ((results[i] = tests[i].func())) {
                T2_PRI_PASS();
            } else {
                failed++;
            }
        }

        printf("\n");

        if (failed == 0) {
            T2_PRI_GREEN("All tests were successfully completed");
        } else {
            T2_PRI_RED("Summary: %d test(s) failed:", failed);
            for (i = 0; tests[i].func; i++) {
                if (results[i]) {
                    T2_PRI_GREEN("    Test %2d: PASS", i+1);
                } else {
                    T2_PRI_RED("    Test %2d: FAIL", i+1);
                }
            }
        }
    }

    return EXIT_SUCCESS;
}
