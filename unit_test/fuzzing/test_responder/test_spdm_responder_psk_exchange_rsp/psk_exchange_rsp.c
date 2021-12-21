/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_responder_lib.h"

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} spdm_psk_exchange_request_mine_t;

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_psk_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void test_spdm_responder_psk_exchange(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.dhe_named_group =
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    spdm_context->connection_info.algorithm.key_schedule =
        SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    read_responder_public_certificate_chain(m_use_hash_algo,
                        m_use_asym_algo, &data,
                        &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size;
    spdm_context->local_context.slot_count = 1;

    libspdm_reset_message_a(spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING,
         sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    response_size = sizeof(response);
    spdm_get_response_psk_exchange(spdm_context,
                       spdm_test_context->test_buffer_size,
                       spdm_test_context->test_buffer,
                       &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_psk_exchange_test_context);

    m_spdm_responder_psk_exchange_test_context.test_buffer = test_buffer;
    m_spdm_responder_psk_exchange_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Success Case*/
    test_spdm_responder_psk_exchange(&State);

    spdm_unit_test_group_teardown(&State);
}
