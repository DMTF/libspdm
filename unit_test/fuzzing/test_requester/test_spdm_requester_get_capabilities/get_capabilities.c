/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_send_message(void *spdm_context,
                                          size_t request_size, const void *request,
                                          uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status libspdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t *spdm_response;
    size_t spdm_response_size;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = libspdm_transport_test_get_header_size(spdm_context);
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }
    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     (uint8_t *)spdm_test_context->test_buffer,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    return RETURN_SUCCESS;
}

void libspdm_test_requester_get_capabilities(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_get_capabilities(spdm_context);
}

libspdm_test_context_t m_libspdm_test_requester_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, size_t test_buffer_size)
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
