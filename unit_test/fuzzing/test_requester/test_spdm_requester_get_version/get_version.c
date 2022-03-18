/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"

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
                                             void *response,
                                             uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t spdm_response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn spdm_response_size;
    uint8_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = 1;
    spdm_response_size = spdm_test_context->test_buffer_size - test_message_header_size;
    if (spdm_response_size < LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) {
        libspdm_copy_mem((uint8_t *)spdm_response, sizeof(spdm_response),
                         (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
                         spdm_response_size);
    } else {
        libspdm_copy_mem((uint8_t *)spdm_response, sizeof(spdm_response),
                         (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
                         LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - test_message_header_size);
    }
    if (spdm_response_size < LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) {
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              spdm_response_size,
                                              spdm_response, response_size, response);
    } else {
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - LIBSPDM_TEST_ALIGNMENT,
                                              spdm_response, response_size, response);
    }
    return RETURN_SUCCESS;
}

void libspdm_test_requester_get_version(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_get_version(spdm_context, NULL, NULL);
}

libspdm_test_context_t m_libspdm_requester_get_version_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_get_version_test_context);

    m_libspdm_requester_get_version_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_get_version_test_context.test_buffer_size =
        test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    /* Successful response*/
    libspdm_test_requester_get_version(&State);

    libspdm_unit_test_group_teardown(&State);
}
