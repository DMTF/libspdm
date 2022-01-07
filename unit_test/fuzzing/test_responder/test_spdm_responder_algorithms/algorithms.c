/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_algorithms_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}
void test_spdm_responder_algorithms_case5(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case6(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case7(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case8(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case9(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case10(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

spdm_test_context_t test_spdm_responder_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;
    setup_spdm_test_context(&test_spdm_responder_context);

    test_spdm_responder_context.test_buffer = test_buffer;
    test_spdm_responder_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* connection_state Check */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case2(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case3(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case4(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case5(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case6(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case7(&State);
    spdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case8(&State);
    spdm_unit_test_group_teardown(&State);

    /* response_state: LIBSPDM_RESPONSE_STATE_BUSY */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case9(&State);
    spdm_unit_test_group_teardown(&State);

    /* capablities: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_algorithms_case10(&State);
    spdm_unit_test_group_teardown(&State);

}
