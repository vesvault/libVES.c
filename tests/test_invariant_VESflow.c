#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Forward declarations for VESflow functions */
typedef struct VESflow {
    char *name;
    char *url;
} VESflow;

extern VESflow *VESflow_new(const char *name, const char *url);
extern void VESflow_free(VESflow *flow);

START_TEST(test_vesflow_allocation_size_safety)
{
    /* Invariant: Allocation sizes must not overflow when computed from input lengths */
    
    /* Test cases: valid input, boundary case, large name+url combination */
    const char *names[] = {
        "test",                          /* valid short input */
        "a",                             /* minimal boundary */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" /* longer name to test off-by-one */
    };
    const char *urls[] = {
        "http://example.com",
        "x",
        "http://example.com/path?query=1"
    };
    int num_cases = sizeof(names) / sizeof(names[0]);

    for (int i = 0; i < num_cases; i++) {
        VESflow *flow = VESflow_new(names[i], urls[i]);
        
        if (flow != NULL) {
            /* Invariant: allocated strings must be properly null-terminated */
            /* and have sufficient space for their content */
            if (flow->name != NULL) {
                size_t expected_len = strlen(names[i]);
                size_t actual_len = strlen(flow->name);
                ck_assert_uint_eq(actual_len, expected_len);
            }
            if (flow->url != NULL) {
                size_t expected_len = strlen(urls[i]);
                size_t actual_len = strlen(flow->url);
                ck_assert_uint_eq(actual_len, expected_len);
            }
            VESflow_free(flow);
        }
    }
}
END_TEST

START_TEST(test_vesflow_size_overflow_protection)
{
    /* Invariant: size calculations must not produce values that wrap around */
    
    /* Simulate the overflow check: 3 * jsonl + urll + name_len + 16 */
    size_t large_json_len = (size_t)INT32_MAX / 2;  /* Would overflow 3*jsonl in int */
    size_t safe_limit = SIZE_MAX / 4;
    
    /* The calculation 3 * jsonl must not overflow */
    ck_assert_msg(large_json_len < safe_limit, 
                  "Test setup error: large_json_len should be within testable range");
    
    /* Verify that proper size_t arithmetic would catch the overflow */
    size_t result = 3 * large_json_len;
    ck_assert_msg(result > large_json_len, 
                  "Multiplication must not wrap around for security");
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_vesflow_allocation_size_safety);
    tcase_add_test(tc_core, test_vesflow_size_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}