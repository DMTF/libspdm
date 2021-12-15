/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

uintn get_max_buffer_size(void)
{
    return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_algorithms_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 0;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
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
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;

    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case12(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY;
    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case10(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
    spdm_context->connection_info.algorithm.base_hash_algo = 0;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.measurement_spec = 0;
    libspdm_reset_message_a(spdm_context);

    spdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_algorithms_case11(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->local_context.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;

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

    spdm_unit_test_group_setup(&State);

    test_spdm_responder_algorithms_case1(&State);
    test_spdm_responder_algorithms_case2(&State);
    test_spdm_responder_algorithms_case3(&State);
    test_spdm_responder_algorithms_case4(&State);
    test_spdm_responder_algorithms_case5(&State);
    test_spdm_responder_algorithms_case6(&State);
    test_spdm_responder_algorithms_case7(&State);
    test_spdm_responder_algorithms_case8(&State);
    test_spdm_responder_algorithms_case9(&State);
    test_spdm_responder_algorithms_case10(&State);
    test_spdm_responder_algorithms_case11(&State);

    spdm_unit_test_group_teardown(&State);
}
