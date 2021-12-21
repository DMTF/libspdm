/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context,
                       IN uintn request_size, IN void *request,
                       IN uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context,
                      IN OUT uintn *response_size,
                      IN OUT void *response,
                      IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    *response_size = spdm_test_context->test_buffer_size;
    copy_mem(response, spdm_test_context->test_buffer,
         spdm_test_context->test_buffer_size);

    return RETURN_SUCCESS;
}

void test_spdm_requester_negotiate_algorithms(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_negotiate_algorithms(spdm_context);
}

spdm_test_context_t test_spdm_requester_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&test_spdm_requester_context);

    test_spdm_requester_context.test_buffer = test_buffer;
    test_spdm_requester_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Successful response*/
    test_spdm_requester_negotiate_algorithms(&State);

    spdm_unit_test_group_teardown(&State);
}
