/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
static uint8_t test_case_id;

static GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_zero_filled_buffer[64];

uintn spdm_test_get_key_exchange_request_size(IN void *spdm_context, IN void *buffer,
                                              IN uintn buffer_size)
{
    spdm_key_exchange_request_t *spdm_request;
    uintn message_size;
    uintn dhe_key_size;
    uint16_t opaque_length;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_KEY_EXCHANGE) {
        return buffer_size;
    }

    message_size = sizeof(spdm_key_exchange_request_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    message_size += dhe_key_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    opaque_length =
        *(uint16_t *)((uintn)buffer + sizeof(spdm_key_exchange_request_t) + dhe_key_size);
    message_size += opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    /* Good message, return actual size*/
    return message_size;
}

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context, IN uintn request_size,
                                       IN void *request, IN uint64_t timeout)
{
    uintn header_size;
    uintn message_size;

    header_size = sizeof(test_message_header_t);
    m_local_buffer_size = 0;
    message_size = spdm_test_get_key_exchange_request_size(
        spdm_context, (uint8_t *)request + header_size, request_size - header_size);
    copy_mem(m_local_buffer, (uint8_t *)request + header_size, message_size);
    m_local_buffer_size += message_size;
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context, IN OUT uintn *response_size,
                                          IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    uint8_t test_message_header_size;

    switch (test_case_id) {
    case 0x01: {
        spdm_key_exchange_response_t *spdm_response;
        uintn dhe_key_size;
        uint32_t hash_size;
        uintn signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        uintn final_key_size;
        uintn opaque_key_exchange_rsp_size;
        void *data;
        uintn data_size;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t THCurrHashData[64];
        uint8_t bin_str0[128];
        uintn bin_str0_size;
        uint8_t bin_str2[128];
        uintn bin_str2_size;
        uint8_t bin_str7[128];
        uintn bin_str7_size;
        uintn temp_buff_size;
        uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

        spdm_test_context = get_spdm_test_context();
        test_message_header_size = 1;
        temp_buff_size = sizeof(spdm_psk_finish_response_t);
        copy_mem((uint8_t *)temp_buf,
                 (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
                 spdm_test_context->test_buffer_size);

        ((spdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_use_hash_algo;
        ((spdm_context_t *)spdm_context)->connection_info.algorithm.dhe_named_group =
            m_use_dhe_algo;
        ((spdm_context_t *)spdm_context)->connection_info.algorithm.measurement_hash_algo =
            m_use_measurement_hash_algo;
        signature_size = libspdm_get_asym_signature_size(m_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            spdm_get_opaque_data_version_selection_data_size(spdm_context);
        temp_buff_size = sizeof(spdm_key_exchange_response_t) + dhe_key_size + 0 +
                         sizeof(uint16_t) + opaque_key_exchange_rsp_size + signature_size +
                         hmac_size;
        spdm_response = (void *)temp_buf;

        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context =
            libspdm_dhe_new(spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                            m_use_dhe_algo, TRUE);
        libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(m_use_dhe_algo, dhe_context,
                                (uint8_t *)&m_local_buffer[0] + sizeof(spdm_key_exchange_request_t),
                                dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* zero_mem (ptr, hash_size);*/
        /* ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        spdm_build_opaque_data_version_selection_data(spdm_context, &opaque_key_exchange_rsp_size,
                                                      ptr);
        ptr += opaque_key_exchange_rsp_size;
        read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                                NULL, NULL);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 (uintn)ptr - (uintn)spdm_response);
        m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
        DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n", m_local_buffer_size));
        internal_dump_hex(m_local_buffer, m_local_buffer_size);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        append_managed_buffer(&th_curr, m_local_buffer, m_local_buffer_size);
        libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        libspdm_responder_data_sign(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_KEY_EXCHANGE_RSP, m_use_asym_algo, m_use_hash_algo, FALSE,
            get_managed_buffer(&th_curr), get_managed_buffer_size(&th_curr), ptr, &signature_size);
        copy_mem(&m_local_buffer[m_local_buffer_size], ptr, signature_size);
        m_local_buffer_size += signature_size;
        append_managed_buffer(&th_curr, ptr, signature_size);
        ptr += signature_size;
        libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), THCurrHashData);
        bin_str0_size = sizeof(bin_str0);
        libspdm_bin_concat(SPDM_BIN_STR_0_LABEL, sizeof(SPDM_BIN_STR_0_LABEL) - 1, NULL,
                           (uint16_t)hash_size, hash_size, bin_str0, &bin_str0_size);
        libspdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer, hash_size, final_key,
                         final_key_size, handshake_secret);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1, THCurrHashData,
                           (uint16_t)hash_size, hash_size, bin_str2, &bin_str2_size);
        libspdm_hkdf_expand(m_use_hash_algo, handshake_secret, hash_size, bin_str2, bin_str2_size,
                            response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
                           (uint16_t)hash_size, hash_size, bin_str7, &bin_str7_size);
        libspdm_hkdf_expand(m_use_hash_algo, response_handshake_secret, hash_size, bin_str7,
                            bin_str7_size, response_finished_key, hash_size);
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, FALSE, FALSE, temp_buff_size,
                                           temp_buf, response_size, response);
        break;
    }
    case 0x02: {
        spdm_error_response_t spdm_response;
        spdm_test_context = get_spdm_test_context();
        test_message_header_size = 1;
        copy_mem(&spdm_response,
                 (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
                 spdm_test_context->test_buffer_size);
        spdm_transport_test_encode_message(spdm_context, NULL, FALSE, FALSE,
                                           spdm_test_context->test_buffer_size, &spdm_response,
                                           response_size, response);
        break;
    }
    case 0x03: {
        spdm_test_context_t *spdm_test_context;

        spdm_test_context = get_spdm_test_context();
        *response_size = spdm_test_context->test_buffer_size;
        copy_mem(response, spdm_test_context->test_buffer, spdm_test_context->test_buffer_size);
        break;
    }
    }
    return RETURN_SUCCESS;
}

void test_spdm_requester_key_exchange_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));

    spdm_send_receive_key_exchange(spdm_context, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   0, 0, &session_id, &heartbeat_period, &slot_id_param,
                                   measurement_hash);
    free(data);
}

void test_spdm_requester_key_exchange_case2(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    test_case_id = 0x02;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    spdm_send_receive_key_exchange(spdm_context, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   0, 0, &session_id, &heartbeat_period, &slot_id_param,
                                   measurement_hash);
    free(data);
}

void test_spdm_requester_key_exchange_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    test_case_id = 0x03;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
         data, data_size);
#endif
    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));

    spdm_send_receive_key_exchange(spdm_context, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   0, 0, &session_id, &heartbeat_period, &slot_id_param,
                                   measurement_hash);
    free(data);
}

void test_spdm_requester_key_exchange_ex_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t requester_random_in[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t requester_random[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t responder_random[LIBSPDM_MAX_BUFFER_SIZE];

    spdm_test_context = *State;
    test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    spdm_send_receive_key_exchange_ex(spdm_context,
                                      SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
                                      &session_id, &heartbeat_period, &slot_id_param,
                                      measurement_hash, requester_random_in, requester_random,
                                      responder_random);
    free(data);
}

spdm_test_context_t m_spdm_requester_key_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_key_exchange_test_context);

    m_spdm_requester_key_exchange_test_context.test_buffer = test_buffer;
    m_spdm_requester_key_exchange_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_exchange_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_exchange_case2(&State);
    spdm_unit_test_group_teardown(&State);

    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_exchange_case3(&State);
    spdm_unit_test_group_teardown(&State);

    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_exchange_ex_case1(&State);
    spdm_unit_test_group_teardown(&State);
}
