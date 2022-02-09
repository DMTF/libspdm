/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_psk_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

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

void test_spdm_responder_psk_exchange_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];
    spdm_psk_exchange_request_mine_t m_spdm_psk_exchange_request;
    uintn m_spdm_psk_exchange_request_size;
    uint8_t *ptr;
    uintn opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;

    m_spdm_psk_exchange_request =
        *(spdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context.connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context.connection_info.local_used_cert_chain_buffer = data;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context.local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context.local_context.psk_hint = m_local_psk_hint;

    opaque_psk_exchange_req_size = spdm_get_opaque_data_supported_version_data_size(&spdm_context);
    ptr = m_spdm_psk_exchange_request.psk_hint;
    copy_mem(ptr, &spdm_context.local_context.psk_hint, spdm_context.local_context.psk_hint_size);
    ptr += m_spdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_spdm_psk_exchange_request.context_length;
    spdm_build_opaque_data_supported_version_data(&spdm_context, &opaque_psk_exchange_req_size,
                                                  ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    spdm_get_response_psk_exchange(&spdm_context, m_spdm_psk_exchange_request_size,
                                   &m_spdm_psk_exchange_request, &response_size, response);
}

void test_spdm_responder_psk_exchange_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];
    spdm_psk_exchange_request_mine_t m_spdm_psk_exchange_request;
    uintn m_spdm_psk_exchange_request_size;
    uint8_t *ptr;
    uintn opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    m_spdm_psk_exchange_request =
        *(spdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context.connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context.connection_info.local_used_cert_chain_buffer = data;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context.local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context.local_context.psk_hint = m_local_psk_hint;

    opaque_psk_exchange_req_size = spdm_get_opaque_data_supported_version_data_size(&spdm_context);
    ptr = m_spdm_psk_exchange_request.psk_hint;
    copy_mem(ptr, &spdm_context.local_context.psk_hint, spdm_context.local_context.psk_hint_size);
    ptr += m_spdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_spdm_psk_exchange_request.context_length;
    spdm_build_opaque_data_supported_version_data(&spdm_context, &opaque_psk_exchange_req_size,
                                                  ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    spdm_get_response_psk_exchange(&spdm_context, m_spdm_psk_exchange_request_size,
                                   &m_spdm_psk_exchange_request, &response_size, response);
}

void test_spdm_responder_psk_exchange_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];
    spdm_psk_exchange_request_mine_t m_spdm_psk_exchange_request;
    uintn m_spdm_psk_exchange_request_size;
    uint8_t *ptr;
    uintn opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;

    m_spdm_psk_exchange_request =
        *(spdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_psk_exchange_request_size = spdm_test_context->test_buffer_size;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context.connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context.connection_info.local_used_cert_chain_buffer = data;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context.local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context.local_context.psk_hint = m_local_psk_hint;

    opaque_psk_exchange_req_size = spdm_get_opaque_data_supported_version_data_size(&spdm_context);
    ptr = m_spdm_psk_exchange_request.psk_hint;
    copy_mem(ptr, &spdm_context.local_context.psk_hint, spdm_context.local_context.psk_hint_size);
    ptr += m_spdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_spdm_psk_exchange_request.context_length;
    spdm_build_opaque_data_supported_version_data(&spdm_context, &opaque_psk_exchange_req_size,
                                                  ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    spdm_get_response_psk_exchange(&spdm_context, m_spdm_psk_exchange_request_size,
                                   &m_spdm_psk_exchange_request, &response_size, response);
}

void test_spdm_responder_psk_exchange_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];
    spdm_psk_exchange_request_mine_t m_spdm_psk_exchange_request;
    uintn m_spdm_psk_exchange_request_size;
    uint8_t *ptr;
    uintn opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    m_spdm_psk_exchange_request =
        *(spdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context.connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context.connection_info.local_used_cert_chain_buffer = data;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context.local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context.local_context.psk_hint = m_local_psk_hint;

    opaque_psk_exchange_req_size = spdm_get_opaque_data_supported_version_data_size(&spdm_context);
    ptr = m_spdm_psk_exchange_request.psk_hint;
    copy_mem(ptr, &spdm_context.local_context.psk_hint, spdm_context.local_context.psk_hint_size);
    ptr += m_spdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_spdm_psk_exchange_request.context_length;
    spdm_build_opaque_data_supported_version_data(&spdm_context, &opaque_psk_exchange_req_size,
                                                  ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    spdm_get_response_psk_exchange(&spdm_context, m_spdm_psk_exchange_request_size,
                                   &m_spdm_psk_exchange_request, &response_size, response);
}

void test_spdm_responder_psk_exchange_case5(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    static uint8_t m_local_psk_hint[32];
    spdm_psk_exchange_request_mine_t m_spdm_psk_exchange_request;
    uintn m_spdm_psk_exchange_request_size;
    uint8_t *ptr;
    uintn opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    m_spdm_psk_exchange_request =
        *(spdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context.encap_context.error_state = LIBSPDM_STATUS_SUCCESS;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context.connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context.connection_info.local_used_cert_chain_buffer = data;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size;
    spdm_context.local_context.slot_count = 1;

    libspdm_reset_message_a(&spdm_context);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context.local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context.local_context.psk_hint = m_local_psk_hint;

    opaque_psk_exchange_req_size = spdm_get_opaque_data_supported_version_data_size(&spdm_context);
    ptr = m_spdm_psk_exchange_request.psk_hint;
    copy_mem(ptr, &spdm_context.local_context.psk_hint, spdm_context.local_context.psk_hint_size);
    ptr += m_spdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_spdm_psk_exchange_request.context_length;
    spdm_build_opaque_data_supported_version_data(&spdm_context, &opaque_psk_exchange_req_size,
                                                  ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    spdm_get_response_psk_exchange(&spdm_context, m_spdm_psk_exchange_request_size,
                                   &m_spdm_psk_exchange_request, &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_psk_exchange_test_context);

    m_spdm_responder_psk_exchange_test_context.test_buffer = test_buffer;
    m_spdm_responder_psk_exchange_test_context.test_buffer_size = test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Success Case*/
    test_spdm_responder_psk_exchange_case1(&State);
    test_spdm_responder_psk_exchange_case2(&State);
    /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
    test_spdm_responder_psk_exchange_case3(&State);
    /* capability.flags: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT */
    test_spdm_responder_psk_exchange_case4(&State);
    /* capability.flags: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP */
    test_spdm_responder_psk_exchange_case5(&State);

    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size){
    
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
