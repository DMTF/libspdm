/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

uint8_t test_message_header;
static uint8_t m_local_psk_hint[32];
static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

uintn spdm_test_get_measurement_request_size(const void *spdm_context, const void *buffer,
                                             uintn buffer_size)
{
    const spdm_get_measurements_request_t *spdm_request;
    uintn message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_GET_MEASUREMENTS) {
        return buffer_size;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
            if (buffer_size < sizeof(spdm_get_measurements_request_t)) {
                return buffer_size;
            }
            message_size = sizeof(spdm_get_measurements_request_t);
        } else {
            if (buffer_size <
                sizeof(spdm_get_measurements_request_t) - sizeof(spdm_request->slot_id_param)) {
                return buffer_size;
            }
            message_size =
                sizeof(spdm_get_measurements_request_t) - sizeof(spdm_request->slot_id_param);
        }
    } else {
        /* already checked before if buffer_size < sizeof(spdm_message_header_t)*/
        message_size = sizeof(spdm_message_header_t);
    }

    /* Good message, return actual size*/
    return message_size;
}

return_status spdm_device_send_message(void *spdm_context, uintn request_size,
                                       const void *request, uint64_t timeout)
{
    uintn header_size;
    uintn message_size;

    m_local_buffer_size = 0;
    header_size = sizeof(test_message_header_t);
    message_size = spdm_test_get_measurement_request_size(
        spdm_context, (uint8_t *)request + header_size, request_size - header_size);
    copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
               (uint8_t *)request + header_size, message_size);
    m_local_buffer_size += message_size;
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(void *spdm_context, uintn *response_size,
                                          void *response, uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    spdm_test_context = get_spdm_test_context();
    if (test_message_header == TEST_MESSAGE_TYPE_SECURED_TEST) {
        copy_mem_s((uint8_t *)response, *response_size,  &test_message_header, 1);
        copy_mem_s((uint8_t *)response + 1, *response_size - 1,
                   (uint8_t *)spdm_test_context->test_buffer,
                   spdm_test_context->test_buffer_size);
    } else {
        copy_mem_s(response, *response_size,
                   spdm_test_context->test_buffer, spdm_test_context->test_buffer_size);
    }
    *response_size = spdm_test_context->test_buffer_size;

    return RETURN_SUCCESS;
}

void test_spdm_requester_get_measurement_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, NULL, request_attribute, 1, 0, NULL, &number_of_block,
                            &measurement_record_length, measurement_record);
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    free(spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

void test_spdm_requester_get_measurement_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement_ex(spdm_context, NULL, request_attribute, 1, 0, NULL, &number_of_block,
                               &measurement_record_length, measurement_record, NULL, NULL, NULL);
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    free(spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

void test_spdm_requester_get_measurement_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint32_t session_id;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;
    session_id = 0xFFFFFFFF;
    test_message_header = TEST_MESSAGE_TYPE_SECURED_TEST;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, &session_id, request_attribute, 1, 0, NULL,
                            &number_of_block, &measurement_record_length, measurement_record);
    test_message_header = 0;
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    free(spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

void test_spdm_requester_get_measurement_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, NULL, request_attribute,
                            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS, 0,
                            NULL, &number_of_block, &measurement_record_length, measurement_record);
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    free(spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

spdm_test_context_t m_spdm_requester_get_measurements_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_get_measurements_test_context);

    m_spdm_requester_get_measurements_test_context.test_buffer = (void *)test_buffer;
    m_spdm_requester_get_measurements_test_context.test_buffer_size = test_buffer_size;

    /* Successful response to get measurement with signature*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_measurement_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Successful response to get measurement with signature*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_measurement_case2(&State);
    spdm_unit_test_group_teardown(&State);

    /* Successful response to get a session based measurement with signature*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_measurement_case3(&State);
    spdm_unit_test_group_teardown(&State);

    /* Successful response to get all measurements without signature*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_measurement_case4(&State);
    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(const void *test_buffer, uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
