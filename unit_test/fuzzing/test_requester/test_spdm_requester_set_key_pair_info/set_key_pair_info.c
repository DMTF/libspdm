/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

#define LIBSPDM_MAX_key_pair_info_SIZE 0x1000

uint8_t temp_buf[LIBSPDM_MAX_key_pair_info_SIZE];

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
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    libspdm_zero_mem(temp_buf, sizeof(temp_buf));
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }
    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     spdm_test_context->test_buffer,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_set_key_pair_info(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t key_pair_id;
    uint8_t operation;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;


    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    key_pair_id = 1;
    operation = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    desired_key_usage = 0;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0;
    libspdm_set_key_pair_info(spdm_context, NULL, key_pair_id,
                              operation, desired_key_usage, desired_asym_algo,
                              desired_assoc_cert_slot_mask);

    key_pair_id = 1;
    operation = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    desired_key_usage = 0;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0;
    libspdm_set_key_pair_info(spdm_context, NULL, key_pair_id,
                              operation, desired_key_usage, desired_asym_algo,
                              desired_assoc_cert_slot_mask);


    key_pair_id = 1;
    operation = SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION;
    desired_key_usage = 0;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0;
    libspdm_set_key_pair_info(spdm_context, NULL, key_pair_id,
                              operation, desired_key_usage, desired_asym_algo,
                              desired_assoc_cert_slot_mask);

}

libspdm_test_context_t m_libspdm_requester_set_key_pair_info_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};


void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_set_key_pair_info_test_context);

    m_libspdm_requester_set_key_pair_info_test_context.test_buffer = test_buffer;
    m_libspdm_requester_set_key_pair_info_test_context.test_buffer_size =
        test_buffer_size;

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_set_key_pair_info(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/
