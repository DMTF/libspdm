/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t opaque_data_size;
    uint8_t opaque_data[8];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_psk_finish_request_mine_14_t;
#pragma pack()

static libspdm_th_managed_buffer_t th_curr;

static libspdm_psk_finish_request_mine_14_t m_libspdm_psk_finish_request = {
    { SPDM_MESSAGE_VERSION_14, SPDM_PSK_FINISH, 0, 0 },
};
static size_t m_libspdm_psk_finish_request_size;

static uint8_t m_libspdm_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

extern size_t libspdm_secret_lib_psk_finish_opaque_data_size;
extern bool g_generate_psk_finish_opaque_data;
extern bool g_psk_finish_opaque_data_error;

static void libspdm_secured_message_set_request_finished_key(
    void *spdm_secured_message_context, const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.request_finished_key,
                     sizeof(secured_message_context->handshake_secret.request_finished_key),
                     key, secured_message_context->hash_size);
}

/**
 * Test 1: SPDM version 1.4, and the Integrator's libspdm_psk_finish_rsp_opaque_data returns
 *         OpaqueData larger than the protocol maximum.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=Unspecified.
 **/
static void rsp_psk_finish_rsp_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    g_generate_psk_finish_opaque_data = true;
    libspdm_secret_lib_psk_finish_opaque_data_size = SPDM_MAX_OPAQUE_DATA_SIZE + 1;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_libspdm_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_libspdm_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    m_libspdm_psk_finish_request.opaque_data_size =
        sizeof(m_libspdm_psk_finish_request.opaque_data);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_psk_finish_request.verify_data;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_psk_finish_request,
                                  sizeof(spdm_psk_finish_request_t) + sizeof(uint16_t) +
                                  m_libspdm_psk_finish_request.opaque_data_size);
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_psk_finish_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size +
                                        sizeof(uint16_t) +
                                        m_libspdm_psk_finish_request.opaque_data_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_finish(
        spdm_context, m_libspdm_psk_finish_request_size, &m_libspdm_psk_finish_request,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    g_generate_psk_finish_opaque_data = false;
    free(data1);
}

/**
 * Test 2: SPDM version 1.4, and the Integrator's libspdm_psk_finish_rsp_opaque_data returns false.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=Unspecified.
 **/
static void rsp_psk_finish_rsp_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    g_psk_finish_opaque_data_error = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_libspdm_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_libspdm_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    m_libspdm_psk_finish_request.opaque_data_size =
        sizeof(m_libspdm_psk_finish_request.opaque_data);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_psk_finish_request.verify_data;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_psk_finish_request,
                                  sizeof(spdm_psk_finish_request_t) + sizeof(uint16_t) +
                                  m_libspdm_psk_finish_request.opaque_data_size);
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_psk_finish_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size +
                                        sizeof(uint16_t) +
                                        m_libspdm_psk_finish_request.opaque_data_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_finish(
        spdm_context, m_libspdm_psk_finish_request_size, &m_libspdm_psk_finish_request,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    g_psk_finish_opaque_data_error = false;
    free(data1);
}

int libspdm_rsp_psk_finish_rsp_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_psk_finish_rsp_err_case1),
        cmocka_unit_test(rsp_psk_finish_rsp_err_case2),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
