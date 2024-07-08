/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

uint8_t temp_buf[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context,
                                             size_t request_size, const void *request,
                                             uint64_t timeout)
{
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context,
                                                size_t *response_size,
                                                void **response,
                                                uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_measurement_extension_log_response_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;
    size_t test_buffer_size;

    static size_t test_buffer_offset = 0;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;

    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    test_buffer_size = spdm_test_context->test_buffer_size;

    if(test_buffer_size < test_buffer_offset) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    test_buffer_size -= test_buffer_offset;

    if (test_buffer_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        test_buffer_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }

    if (test_buffer_size < sizeof(spdm_measurement_extension_log_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    } else {
        libspdm_zero_mem(temp_buf, sizeof(temp_buf));
        libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                         sizeof(temp_buf) - test_message_header_size,
                         (uint8_t *)spdm_test_context->test_buffer + test_buffer_offset,
                         test_buffer_size);
    }
    test_buffer_size -= sizeof(spdm_measurement_extension_log_response_t);

    if(test_buffer_size < spdm_response->portion_length) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                         spdm_response->portion_length;

    libspdm_transport_test_encode_message(spdm_test_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    test_buffer_offset += spdm_response_size;

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_get_measurement_extension_log(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_b(spdm_context);
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    libspdm_get_measurement_extension_log(spdm_context, NULL,
                                          &spdm_mel_size, spdm_mel);
}

libspdm_test_context_t m_libspdm_requester_get_measurement_extension_log_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};


void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_get_measurement_extension_log_test_context);

    m_libspdm_requester_get_measurement_extension_log_test_context.test_buffer = test_buffer;
    m_libspdm_requester_get_measurement_extension_log_test_context.test_buffer_size =
        test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_extension_log(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP*/
