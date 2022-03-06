/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_send_message(void *spdm_context,
                                          uintn request_size, const void *request,
                                          uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status libspdm_device_receive_message(void *spdm_context,
                                             uintn *response_size,
                                             void **response,
                                             uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    libspdm_copy_mem(response, *response_size, spdm_test_context->test_buffer,
                     spdm_test_context->test_buffer_size);
    *response_size = spdm_test_context->test_buffer_size;
    return RETURN_SUCCESS;
}

void libspdm_test_requester_get_capabilities(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_get_capabilities(spdm_context);
}

libspdm_test_context_t m_libspdm_test_requester_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_test_requester_context);

    m_libspdm_test_requester_context.test_buffer = (void *)test_buffer;
    m_libspdm_test_requester_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    /* Successful response*/
    libspdm_test_requester_get_capabilities(&State);

    libspdm_unit_test_group_teardown(&State);
}
