/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_x509_certificate_check(void **State)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = *State;

    libspdm_x509_certificate_check(
        (uint8_t *)spdm_test_context->test_buffer,
        spdm_test_context->test_buffer_size);
}

spdm_test_context_t m_spdm_x509_certificate_check_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_x509_certificate_check_test_context);

    m_spdm_x509_certificate_check_test_context.test_buffer = test_buffer;
    m_spdm_x509_certificate_check_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    spdm_unit_test_group_setup(&State);
    test_spdm_x509_certificate_check(&State);
    spdm_unit_test_group_teardown(&State);
}
