/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"

uintn get_max_buffer_size(void)
{
    return MAX_SPDM_MESSAGE_BUFFER_SIZE;
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

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

spdm_finish_request_mine_t m_spdm_finish_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request1_size = sizeof(m_spdm_finish_request1);

void test_spdm_requester_get_version(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;
    uint8_t req_slot_id_param;
    uint32_t session_id;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;
    uint8_t m_dummy_buffer[MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.base_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.dhe_named_group =
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    read_responder_public_certificate_chain(m_use_hash_algo,
                        m_use_asym_algo, &data,
                        &data_size, &hash, &hash_size);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
    hash_size = spdm_get_hash_size(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    spdm_send_receive_finish(spdm_context, session_id, req_slot_id_param);
}

spdm_test_context_t m_spdm_requester_get_version_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_get_version_test_context);

    m_spdm_requester_get_version_test_context.test_buffer = test_buffer;
    m_spdm_requester_get_version_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_requester_get_version(&State);

    spdm_unit_test_group_teardown(&State);
}
