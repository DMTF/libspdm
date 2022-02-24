/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(void *spdm_context,
                                       uintn request_size, const void *request,
                                       uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(void *spdm_context,
                                          uintn *response_size,
                                          void *response,
                                          uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    copy_mem(response, *response_size, spdm_test_context->test_buffer,
             spdm_test_context->test_buffer_size);
    *response_size = spdm_test_context->test_buffer_size;
    return RETURN_SUCCESS;
}

void test_spdm_requester_get_version(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_get_version(spdm_context, NULL, NULL);
}

spdm_test_context_t m_spdm_requester_get_version_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_get_version_test_context);

    m_spdm_requester_get_version_test_context.test_buffer = (void *)test_buffer;
    m_spdm_requester_get_version_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Successful response*/
    test_spdm_requester_get_version(&State);

    spdm_unit_test_group_teardown(&State);
}
