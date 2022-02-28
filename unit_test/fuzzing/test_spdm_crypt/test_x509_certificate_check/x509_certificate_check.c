/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void libspdm_test_x509_certificate_check(void **State)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *State;

    libspdm_x509_certificate_check(
        (uint8_t *)spdm_test_context->test_buffer,
        spdm_test_context->test_buffer_size);
}

libspdm_test_context_t m_spdm_x509_certificate_check_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_spdm_x509_certificate_check_test_context);

    m_spdm_x509_certificate_check_test_context.test_buffer = test_buffer;
    m_spdm_x509_certificate_check_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_x509_certificate_check(&State);
    libspdm_unit_test_group_teardown(&State);
}
