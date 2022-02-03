/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context, IN uintn request_size,
                                       IN void *request, IN uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context, IN OUT uintn *response_size,
                                          IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    *response_size = spdm_test_context->test_buffer_size;
    copy_mem(response, spdm_test_context->test_buffer, spdm_test_context->test_buffer_size);
    return RETURN_SUCCESS;
}

void test_spdm_requester_negotiate_algorithms_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    spdm_negotiate_algorithms(spdm_context);
}

void test_spdm_requester_negotiate_algorithms_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    spdm_negotiate_algorithms(spdm_context);
}

void test_spdm_requester_negotiate_algorithms_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    spdm_negotiate_algorithms(spdm_context);
}

spdm_test_context_t test_spdm_requester_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&test_spdm_requester_context);

    test_spdm_requester_context.test_buffer = test_buffer;
    test_spdm_requester_context.test_buffer_size = test_buffer_size;

    /* Successful V1.0 response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_negotiate_algorithms_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Successful V1.1 response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_negotiate_algorithms_case2(&State);
    spdm_unit_test_group_teardown(&State);

    spdm_unit_test_group_setup(&State);
    test_spdm_requester_negotiate_algorithms_case3(&State);
    spdm_unit_test_group_teardown(&State);
}
