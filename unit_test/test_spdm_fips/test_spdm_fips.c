/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE
uint8_t m_selftest_buffer[0x2000];
#endif

/**
 * Test 1: Run the self-tests on a context where none of them have run.
 * Expected behavior: every self-test runs and passes, so libspdm_fips_run_selftest returns true.
 **/
static void libspdm_test_fips_case1(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;

    fips_selftest_context.tested_algo = 0;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
#else
    skip();
#endif
}

/**
 * Test 2: Run the self-tests again on a context where all of them have run and passed.
 * Expected behavior: each self-test finds its bit set in tested_algo and returns without running
 * again, so libspdm_fips_run_selftest returns true and leaves the context unchanged.
 **/
static void libspdm_test_fips_case2(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;
    uint32_t tested_algo;
    uint32_t self_test_result;

    fips_selftest_context.tested_algo = 0;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    /* Every self-test runs and passes. */
    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
    tested_algo = fips_selftest_context.tested_algo;
    self_test_result = fips_selftest_context.self_test_result;

    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
    assert_int_equal(fips_selftest_context.tested_algo, tested_algo);
    assert_int_equal(fips_selftest_context.self_test_result, self_test_result);
#else
    skip();
#endif
}

/**
 * Test 3: Run the self-tests on a context that records a failed AES-GCM self-test.
 * Expected behavior: each self-test finds that an earlier self-test failed and returns without
 * running, so libspdm_fips_run_selftest returns false and leaves the context unchanged.
 **/
static void libspdm_test_fips_case3(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;

    /* The AES-GCM self-test ran and failed. */
    fips_selftest_context.tested_algo = LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    assert_false(libspdm_fips_run_selftest(&fips_selftest_context));
    assert_int_equal(fips_selftest_context.tested_algo, LIBSPDM_FIPS_SELF_TEST_AES_GCM);
    assert_int_equal(fips_selftest_context.self_test_result, 0);
#else
    skip();
#endif
}

int libspdm_crypt_lib_setup(void **state)
{
    return 0;
}

int libspdm_crypt_lib_teardown(void **state)
{
    return 0;
}

int libspdm_crypt_lib_test_main(void)
{
    const struct CMUnitTest spdm_crypt_lib_tests[] = {
        cmocka_unit_test(libspdm_test_fips_case1),
        cmocka_unit_test(libspdm_test_fips_case2),
        cmocka_unit_test(libspdm_test_fips_case3),
    };

    return cmocka_run_group_tests(spdm_crypt_lib_tests,
                                  libspdm_crypt_lib_setup,
                                  libspdm_crypt_lib_teardown);
}

int main(void)
{
    int return_value = 0;

    if (libspdm_crypt_lib_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
