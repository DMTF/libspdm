/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

static const uint32_t m_session_id = 0xFFFFFFFF;

/* The only SPDM version that the Responder supports. */
static uint8_t m_responder_version;

/* The number of requests sent since the state was last set. */
static size_t m_request_count;

/* The last request, as send_message decoded it. */
static uint8_t m_request[LIBSPDM_MAX_SPDM_MSG_SIZE];
static size_t m_request_size;
static bool m_request_is_secured;
static bool m_request_is_app_message;

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
static const uint8_t m_app_request[] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
static const uint8_t m_app_response[] = {
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC
};

static void set_standard_state(libspdm_context_t *spdm_context)
{
    m_responder_version = SPDM_MESSAGE_VERSION_10;
    m_request_count = 0;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;

    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
}

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
/* Sets up an SPDM 1.2 connection that can carry secured messages. */
static void set_connection_state(libspdm_context_t *spdm_context)
{
    m_request_count = 0;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    libspdm_reset_message_a(spdm_context);
}

/* Sets up an SPDM 1.2 connection with a session in the given state. */
static void set_session_state(libspdm_context_t *spdm_context,
                              libspdm_session_state_t session_state, bool use_psk)
{
    libspdm_session_info_t *session_info;

    set_connection_state(spdm_context);

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, use_psk);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              session_state);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

/* One context both encodes and decodes each secured message, so this undoes the increment of the
 * sequence number by the encode. */
static void rewind_sequence_number(libspdm_context_t *spdm_context, bool is_request)
{
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, m_session_id);
    assert_non_null(session_info);
    secured_message_context = session_info->secured_message_context;

    if (libspdm_secured_message_get_session_state(secured_message_context) ==
        LIBSPDM_SESSION_STATE_HANDSHAKING) {
        if (is_request) {
            secured_message_context->handshake_secret.request_handshake_sequence_number--;
        } else {
            secured_message_context->handshake_secret.response_handshake_sequence_number--;
        }
    } else if (is_request) {
        secured_message_context->application_secret.request_data_sequence_number--;
    } else {
        secured_message_context->application_secret.response_data_sequence_number--;
    }
}

static size_t build_version_response(uint8_t *buffer)
{
    spdm_version_response_t *spdm_response;
    spdm_version_number_t version_number_entry;

    spdm_response = (void *)buffer;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_VERSION;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->reserved = 0;
    spdm_response->version_number_entry_count = 1;
    version_number_entry = (spdm_version_number_t)(m_responder_version <<
                                                   SPDM_VERSION_NUMBER_SHIFT_BIT);
    libspdm_copy_mem(spdm_response + 1, sizeof(version_number_entry),
                     &version_number_entry, sizeof(version_number_entry));

    return sizeof(spdm_version_response_t) + sizeof(spdm_version_number_t);
}

static size_t build_capabilities_response(uint8_t *buffer, bool supported_algorithms)
{
    spdm_capabilities_response_t *spdm_response;
    spdm_supported_algorithms_block_t *supported_algorithms_block;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    size_t supported_algorithms_size;

    spdm_response = (void *)buffer;
    libspdm_zero_mem(spdm_response, sizeof(spdm_capabilities_response_t));
    spdm_response->header.spdm_version = m_responder_version;
    spdm_response->header.request_response_code = SPDM_CAPABILITIES;
    spdm_response->ct_exponent = 0;
    spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_response->max_spdm_msg_size = LIBSPDM_DATA_TRANSFER_SIZE;

    if (!supported_algorithms) {
        return sizeof(spdm_capabilities_response_t);
    }

    spdm_response->header.param1 = SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
    supported_algorithms_size = sizeof(spdm_supported_algorithms_block_t) +
                                4 * sizeof(spdm_negotiate_algorithms_common_struct_table_t);
    supported_algorithms_block = (void *)(spdm_response + 1);
    libspdm_zero_mem(supported_algorithms_block, supported_algorithms_size);
    supported_algorithms_block->param1 = 4;
    supported_algorithms_block->length = (uint16_t)supported_algorithms_size;
    supported_algorithms_block->measurement_specification = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    supported_algorithms_block->base_asym_algo = m_libspdm_use_asym_algo;
    supported_algorithms_block->base_hash_algo = m_libspdm_use_hash_algo;
    supported_algorithms_block->mel_specification = SPDM_MEL_SPECIFICATION_DMTF;
    struct_table = (void *)(supported_algorithms_block + 1);
    struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    struct_table[0].alg_count = 0x20;
    struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    struct_table[1].alg_count = 0x20;
    struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    struct_table[2].alg_count = 0x20;
    struct_table[2].alg_supported = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    struct_table[3].alg_count = 0x20;
    struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;

    return sizeof(spdm_capabilities_response_t) + supported_algorithms_size;
}

static size_t build_algorithms_response(uint8_t *buffer)
{
    spdm_algorithms_response_t *spdm_response;

    spdm_response = (void *)buffer;
    libspdm_zero_mem(spdm_response, sizeof(spdm_algorithms_response_t));
    spdm_response->header.spdm_version = m_responder_version;
    spdm_response->header.request_response_code = SPDM_ALGORITHMS;
    spdm_response->length = sizeof(spdm_algorithms_response_t);
    spdm_response->measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
    spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
    spdm_response->base_hash_sel = m_libspdm_use_hash_algo;

    return sizeof(spdm_algorithms_response_t);
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
/* Computes ResponderVerifyData over the VCA, the PSK_EXCHANGE request and the response that
 * precedes it. */
static void compute_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                          const void *spdm_response, size_t spdm_response_size,
                                          uint8_t *hmac)
{
    void *hash_context;
    uint8_t th1_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t bin_str2[128];
    size_t bin_str2_size;
    uint8_t bin_str7[128];
    size_t bin_str7_size;
    uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
    uint32_t hash_size;
    bool result;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);

    hash_context = libspdm_hash_new(m_libspdm_use_hash_algo);
    assert_non_null(hash_context);
    result = libspdm_hash_init(m_libspdm_use_hash_algo, hash_context) &&
             libspdm_hash_update(m_libspdm_use_hash_algo, hash_context,
                                 libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
                                 libspdm_get_managed_buffer_size(
                                     &spdm_context->transcript.message_a)) &&
             libspdm_hash_update(m_libspdm_use_hash_algo, hash_context,
                                 spdm_context->last_spdm_request,
                                 spdm_context->last_spdm_request_size) &&
             libspdm_hash_update(m_libspdm_use_hash_algo, hash_context,
                                 spdm_response, spdm_response_size) &&
             libspdm_hash_final(m_libspdm_use_hash_algo, hash_context, th1_hash);
    libspdm_hash_free(m_libspdm_use_hash_algo, hash_context);
    assert_true(result);

    bin_str2_size = sizeof(bin_str2);
    libspdm_bin_concat(spdm_context->connection_info.version,
                       SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                       th1_hash, (uint16_t)hash_size, hash_size, bin_str2, &bin_str2_size);
    result = libspdm_psk_handshake_secret_hkdf_expand(
        spdm_context->connection_info.version, m_libspdm_use_hash_algo,
        (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        bin_str2, bin_str2_size, response_handshake_secret, hash_size);
    assert_true(result);

    bin_str7_size = sizeof(bin_str7);
    libspdm_bin_concat(spdm_context->connection_info.version,
                       SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                       NULL, (uint16_t)hash_size, hash_size, bin_str7, &bin_str7_size);
    result = libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret, hash_size,
                                 bin_str7, bin_str7_size, response_finished_key, hash_size) &&
             libspdm_hmac_all(m_libspdm_use_hash_algo, th1_hash, hash_size,
                              response_finished_key, hash_size, hmac);
    assert_true(result);
}

/* Builds PSK_EXCHANGE_RSP, with a ResponderContext only if the Responder supports one. */
static size_t build_psk_exchange_response(libspdm_context_t *spdm_context, uint8_t *buffer)
{
    spdm_psk_exchange_response_t *spdm_response;
    uint16_t context_length;
    size_t opaque_data_size;
    uint8_t *ptr;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    } else {
        context_length = 0;
    }
    opaque_data_size = libspdm_get_opaque_data_version_selection_data_size(spdm_context);

    spdm_response = (void *)buffer;
    spdm_response->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_response->header.request_response_code = SPDM_PSK_EXCHANGE_RSP;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->rsp_session_id = (uint16_t)(m_session_id >> 16);
    spdm_response->reserved = 0;
    spdm_response->context_length = context_length;
    spdm_response->opaque_length = (uint16_t)opaque_data_size;
    ptr = (uint8_t *)(spdm_response + 1);
    libspdm_set_mem(ptr, context_length, 0xA5);
    ptr += context_length;
    libspdm_build_opaque_data_version_selection_data(
        spdm_context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            &opaque_data_size, ptr);
    ptr += opaque_data_size;
    compute_psk_exchange_rsp_hmac(spdm_context, buffer, (size_t)(ptr - buffer), ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);

    return (size_t)(ptr - buffer);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_return_t status;
    uint32_t *message_session_id;
    uint8_t message[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    uint8_t *decoded_request;
    size_t decoded_request_size;

    m_request_count++;
    m_request_is_secured = (((const libspdm_test_message_header_t *)request)->message_type ==
                            LIBSPDM_TEST_MESSAGE_TYPE_SECURED_TEST);
    if (m_request_is_secured) {
        rewind_sequence_number(spdm_context, true);
    }

    libspdm_copy_mem(message, sizeof(message), request, request_size);
    libspdm_get_scratch_buffer(spdm_context, (void **)&decoded_request, &decoded_request_size);
    status = libspdm_transport_test_decode_message(spdm_context, &message_session_id,
                                                   &m_request_is_app_message, true, request_size,
                                                   message, &decoded_request_size,
                                                   (void **)&decoded_request);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    libspdm_copy_mem(m_request, sizeof(m_request), decoded_request, decoded_request_size);
    m_request_size = decoded_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/* Answers the last request, as a Responder that supports only m_responder_version would. */
static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_return_t status;
    spdm_message_header_t *spdm_request;
    spdm_message_header_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t session_id;
    uint8_t request_code;

    spdm_test_context = libspdm_get_test_context();
    spdm_request = (void *)m_request;
    request_code = m_request_is_app_message ? 0 : spdm_request->request_response_code;

    switch (spdm_test_context->case_id) {
    case 0x3:
    case 0x7:
        if (request_code == SPDM_GET_VERSION) {
            /* {ERROR} The transport fails to receive VERSION. */
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        break;
    case 0x4:
    case 0x9:
        if (request_code == SPDM_GET_CAPABILITIES) {
            /* {ERROR} The transport fails to receive CAPABILITIES. */
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        break;
    case 0x5:
        if (request_code == SPDM_NEGOTIATE_ALGORITHMS) {
            /* {ERROR} The transport fails to receive ALGORITHMS. */
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        break;
    case 0x15:
    case 0x1A:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    default:
        break;
    }

    if (m_request_is_secured) {
        /* The encryption of a secured response must not overlap the response, so the response is
         * built in the scratch buffer. */
        libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        spdm_response = (void *)(scratch_buffer + LIBSPDM_TEST_TRANSPORT_HEADER_SIZE);
    } else {
        spdm_response = (void *)((uint8_t *)*response + LIBSPDM_TEST_TRANSPORT_HEADER_SIZE);
    }

    if (m_request_is_app_message) {
        libspdm_copy_mem(spdm_response, sizeof(m_app_response),
                         m_app_response, sizeof(m_app_response));
        spdm_response_size = sizeof(m_app_response);
    } else {
        switch (request_code) {
        case SPDM_GET_VERSION:
            spdm_response_size = build_version_response((void *)spdm_response);
            break;
        case SPDM_GET_CAPABILITIES:
            spdm_response_size = build_capabilities_response(
                (void *)spdm_response,
                (spdm_request->param1 &
                 SPDM_GET_CAPABILITIES_REQUEST_PARAM1_SUPPORTED_ALGORITHMS) != 0);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS:
            spdm_response_size = build_algorithms_response((void *)spdm_response);
            break;
        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        case SPDM_PSK_EXCHANGE:
            spdm_response_size = build_psk_exchange_response(spdm_context, (void *)spdm_response);
            break;
        case SPDM_PSK_FINISH:
            spdm_response->spdm_version = spdm_request->spdm_version;
            spdm_response->request_response_code = SPDM_PSK_FINISH_RSP;
            spdm_response->param1 = 0;
            spdm_response->param2 = 0;
            spdm_response_size = sizeof(spdm_psk_finish_response_t);
            break;
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
        case SPDM_END_SESSION:
            spdm_response->spdm_version = spdm_request->spdm_version;
            spdm_response->request_response_code = SPDM_END_SESSION_ACK;
            spdm_response->param1 = 0;
            spdm_response->param2 = 0;
            spdm_response_size = sizeof(spdm_end_session_response_t);
            break;
        case SPDM_HEARTBEAT:
            /* {ERROR} The Responder could not decrypt the request. */
            spdm_response->spdm_version = spdm_request->spdm_version;
            spdm_response->request_response_code = SPDM_ERROR;
            spdm_response->param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
            spdm_response->param2 = 0;
            spdm_response_size = sizeof(spdm_error_response_t);
            break;
        default:
            assert_true(false);
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    }

    if (!m_request_is_secured) {
        return libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                                     spdm_response_size, spdm_response,
                                                     response_size, response);
    }

    session_id = m_session_id;
    status = libspdm_transport_test_encode_message(spdm_context, &session_id,
                                                   m_request_is_app_message, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    rewind_sequence_number(spdm_context, false);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: libspdm_init_connection is asked to exchange only GET_VERSION.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS with SPDM 1.0 negotiated and the connection in
 *                    the LIBSPDM_CONNECTION_STATE_AFTER_VERSION state.
 **/
static void req_communication_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    status = libspdm_init_connection(spdm_context, true);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);
    assert_int_equal(libspdm_get_connection_version(spdm_context), SPDM_MESSAGE_VERSION_10);
}

/**
 * Test 2: libspdm_init_connection exchanges GET_VERSION, GET_CAPABILITIES and
 *         NEGOTIATE_ALGORITHMS.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS with the connection in the
 *                    LIBSPDM_CONNECTION_STATE_NEGOTIATED state.
 **/
static void req_communication_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    status = libspdm_init_connection(spdm_context, false);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    assert_int_equal(spdm_context->connection_info.algorithm.base_hash_algo,
                     m_libspdm_use_hash_algo);
}

/**
 * Test 3: The transport fails to receive VERSION during libspdm_init_connection.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    status = libspdm_init_connection(spdm_context, false);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 4: The transport fails to receive CAPABILITIES during libspdm_init_connection.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    status = libspdm_init_connection(spdm_context, false);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 5: The transport fails to receive ALGORITHMS during libspdm_init_connection.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    status = libspdm_init_connection(spdm_context, false);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/* spdm_requester_lib.h declares libspdm_get_supported_algorithms only under this condition. */
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
/**
 * Test 6: The Requester supports no SPDM version that can report supported algorithms in
 *         CAPABILITIES, which SPDM 1.3 introduced.
 * Expected Behavior: libspdm_get_supported_algorithms returns LIBSPDM_STATUS_UNSUPPORTED_CAP
 *                    without sending a request.
 **/
static void req_communication_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_device_version_t local_version;
    uint8_t supported_algorithms[256];
    size_t supported_algorithms_length;
    uint8_t spdm_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* {ERROR} The Requester supports only SPDM 1.2. */
    local_version = spdm_context->local_context.version;
    spdm_context->local_context.version.spdm_version_count = 1;
    spdm_context->local_context.version.spdm_version[0] =
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    supported_algorithms_length = sizeof(supported_algorithms);
    status = libspdm_get_supported_algorithms(spdm_context, &supported_algorithms_length,
                                              supported_algorithms, &spdm_version);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);

    spdm_context->local_context.version = local_version;
}

/**
 * Test 7: The transport fails to receive VERSION during libspdm_get_supported_algorithms.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algorithms[256];
    size_t supported_algorithms_length;
    uint8_t spdm_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    supported_algorithms_length = sizeof(supported_algorithms);
    status = libspdm_get_supported_algorithms(spdm_context, &supported_algorithms_length,
                                              supported_algorithms, &spdm_version);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 8: The Responder supports only SPDM 1.2, which cannot report supported algorithms in
 *         CAPABILITIES.
 * Expected Behavior: libspdm_get_supported_algorithms returns LIBSPDM_STATUS_UNSUPPORTED_CAP after
 *                    the version exchange.
 **/
static void req_communication_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algorithms[256];
    size_t supported_algorithms_length;
    uint8_t spdm_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    /* {ERROR} The Responder supports only SPDM 1.2. */
    m_responder_version = SPDM_MESSAGE_VERSION_12;

    supported_algorithms_length = sizeof(supported_algorithms);
    status = libspdm_get_supported_algorithms(spdm_context, &supported_algorithms_length,
                                              supported_algorithms, &spdm_version);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(m_request_count, 1);
}

/**
 * Test 9: The transport fails to receive CAPABILITIES during libspdm_get_supported_algorithms.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algorithms[256];
    size_t supported_algorithms_length;
    uint8_t spdm_version;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    m_responder_version = SPDM_MESSAGE_VERSION_14;

    supported_algorithms_length = sizeof(supported_algorithms);
    status = libspdm_get_supported_algorithms(spdm_context, &supported_algorithms_length,
                                              supported_algorithms, &spdm_version);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 10: The Responder supports SPDM 1.4 and reports its supported algorithms in CAPABILITIES.
 * Expected Behavior: libspdm_get_supported_algorithms returns LIBSPDM_STATUS_SUCCESS, SPDM 1.4,
 *                    and the Responder's SupportedAlgorithms block.
 **/
static void req_communication_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algorithms[256];
    size_t supported_algorithms_length;
    uint8_t spdm_version;
    const spdm_supported_algorithms_block_t *supported_algorithms_block;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    m_responder_version = SPDM_MESSAGE_VERSION_14;

    supported_algorithms_length = sizeof(supported_algorithms);
    status = libspdm_get_supported_algorithms(spdm_context, &supported_algorithms_length,
                                              supported_algorithms, &spdm_version);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_version, SPDM_MESSAGE_VERSION_14);
    supported_algorithms_block = (const void *)supported_algorithms;
    assert_int_equal(supported_algorithms_length, supported_algorithms_block->length);
    assert_int_equal(supported_algorithms_block->base_hash_algo, m_libspdm_use_hash_algo);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
/**
 * Test 11: libspdm_start_session with KEY_EXCHANGE to a Responder without KEY_EX_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_communication_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_connection_state(spdm_context);
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    /* {ERROR} The Responder does not support KEY_EXCHANGE. */
    status = libspdm_start_session(spdm_context, false, NULL, 0,
                                   SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
                                   &session_id, &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
}

/**
 * Test 12: libspdm_start_session_exchange with KEY_EXCHANGE to a Responder without KEY_EX_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_communication_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_connection_state(spdm_context);
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    /* {ERROR} The Responder does not support KEY_EXCHANGE. */
    status = libspdm_start_session_exchange(
        spdm_context, false, NULL, 0, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, measurement_hash,
        NULL, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
}

/**
 * Test 13: libspdm_start_session_finish for a KEY_EXCHANGE session with a Responder without
 *          KEY_EX_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending FINISH, and the
 *                    session is freed.
 **/
static void req_communication_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_HANDSHAKING, false);
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    /* {ERROR} The Responder does not support KEY_EXCHANGE. */
    status = libspdm_start_session_finish(spdm_context, m_session_id, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
    assert_null(libspdm_get_session_info_via_session_id(spdm_context, m_session_id));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
/**
 * Test 14: libspdm_start_session with PSK_EXCHANGE to a Responder without PSK_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_communication_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    set_connection_state(spdm_context);
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    /* {ERROR} The Responder does not support PSK_EXCHANGE. */
    status = libspdm_start_session(spdm_context, true, LIBSPDM_TEST_PSK_HINT_STRING,
                                   sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                   SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
                                   &session_id, &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
}

/**
 * Test 15: libspdm_start_session_exchange with PSK_EXCHANGE to a Responder without PSK_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_communication_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    set_connection_state(spdm_context);
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    /* {ERROR} The Responder does not support PSK_EXCHANGE. */
    status = libspdm_start_session_exchange(
        spdm_context, true, LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, measurement_hash,
        NULL, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
}

/**
 * Test 16: libspdm_start_session_finish for a PSK session with a Responder that supports context,
 *          but the Requester does not support PSK_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending PSK_FINISH, and the
 *                    session is freed.
 **/
static void req_communication_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_HANDSHAKING, true);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;

    /* {ERROR} The Requester does not support pre-shared keys. */
    status = libspdm_start_session_finish(spdm_context, m_session_id, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(m_request_count, 0);
    assert_null(libspdm_get_session_info_via_session_id(spdm_context, m_session_id));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
/**
 * Test 17: libspdm_stop_session ends an established session.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS after END_SESSION_ACK, and the session is
 *                    freed.
 **/
static void req_communication_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    status = libspdm_stop_session(spdm_context, m_session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(m_request_is_secured);
    assert_int_equal(((spdm_message_header_t *)m_request)->request_response_code,
                     SPDM_END_SESSION);
    assert_null(libspdm_get_session_info_via_session_id(spdm_context, m_session_id));
}

/**
 * Test 18: libspdm_send_receive_data exchanges application data in an established session.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS. The Responder receives the application data
 *                    of the request, and the Requester receives that of the response.
 **/
static void req_communication_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t response[sizeof(m_app_response)];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    session_id = m_session_id;
    response_size = sizeof(response);
    status = libspdm_send_receive_data(spdm_context, &session_id, true,
                                       m_app_request, sizeof(m_app_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(m_request_is_app_message);
    assert_int_equal(m_request_size, sizeof(m_app_request));
    assert_memory_equal(m_request, m_app_request, sizeof(m_app_request));
    assert_int_equal(response_size, sizeof(m_app_response));
    assert_memory_equal(response, m_app_response, sizeof(m_app_response));

    libspdm_free_session_id(spdm_context, m_session_id);
}

/**
 * Test 19: The Requester cannot acquire the sender buffer for application data.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_ACQUIRE_FAIL without sending a
 *                    request.
 **/
static void req_communication_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t response[sizeof(m_app_response)];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    session_id = m_session_id;
    response_size = sizeof(response);
    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_send_receive_data(spdm_context, &session_id, true,
                                       m_app_request, sizeof(m_app_request),
                                       response, &response_size);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_request_count, 0);

    libspdm_free_session_id(spdm_context, m_session_id);
}

/**
 * Test 20: Application data is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_communication_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t response[sizeof(m_app_response)];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    session_id = m_session_id;
    response_size = sizeof(response);
    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_send_receive_data(spdm_context, &session_id, true,
                                       m_app_request, sizeof(m_app_request),
                                       response, &response_size);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_request_count, 1);
    assert_true(m_request_is_app_message);

    libspdm_free_session_id(spdm_context, m_session_id);
}

/**
 * Test 21: The transport fails to receive the application data of the response.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t response[sizeof(m_app_response)];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    session_id = m_session_id;
    response_size = sizeof(response);
    status = libspdm_send_receive_data(spdm_context, &session_id, true,
                                       m_app_request, sizeof(m_app_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);

    libspdm_free_session_id(spdm_context, m_session_id);
}

/**
 * Test 22: The Requester's buffer is one byte smaller than the application data of the response.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the
 *                    size of the application data.
 **/
static void req_communication_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t response[sizeof(m_app_response)];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    session_id = m_session_id;
    /* {ERROR} The buffer cannot hold the response. */
    response_size = sizeof(response) - 1;
    status = libspdm_send_receive_data(spdm_context, &session_id, true,
                                       m_app_request, sizeof(m_app_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(response_size, sizeof(m_app_response));

    libspdm_free_session_id(spdm_context, m_session_id);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

/**
 * Test 23: libspdm_send_receive_data sends GET_VERSION as SPDM data outside a session.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS and the VERSION response unchanged.
 **/
static void req_communication_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    const spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    set_standard_state(spdm_context);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    response_size = sizeof(response);
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_false(m_request_is_secured);
    assert_memory_equal(m_request, &spdm_request, sizeof(spdm_request));
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) + sizeof(spdm_version_number_t));
    spdm_response = (const void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_response->version_number_entry_count, 1);
}

/**
 * Test 24: The Requester cannot acquire the sender buffer for SPDM data.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_ACQUIRE_FAIL without sending a
 *                    request.
 **/
static void req_communication_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    set_standard_state(spdm_context);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    response_size = sizeof(response);
    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_request_count, 0);
}

/**
 * Test 25: SPDM data is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_communication_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    set_standard_state(spdm_context);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    response_size = sizeof(response);
    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_request_count, 1);
}

/**
 * Test 26: The transport fails to receive the response to SPDM data.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_communication_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    set_standard_state(spdm_context);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    response_size = sizeof(response);
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 27: The Requester's buffer is one byte smaller than the SPDM response.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the
 *                    size of the response.
 **/
static void req_communication_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    set_standard_state(spdm_context);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    /* {ERROR} The buffer cannot hold VERSION. */
    response_size = sizeof(spdm_version_response_t) + sizeof(spdm_version_number_t) - 1;
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) + sizeof(spdm_version_number_t));
}

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
/**
 * Test 28: The Responder returns an ERROR message with ErrorCode=DecryptError to SPDM data in a
 *          session.
 * Expected Behavior: libspdm_send_receive_data returns LIBSPDM_STATUS_SESSION_MSG_ERROR and frees
 *                    the session.
 **/
static void req_communication_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    spdm_heartbeat_request_t spdm_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    set_session_state(spdm_context, LIBSPDM_SESSION_STATE_ESTABLISHED, false);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_HEARTBEAT;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    session_id = m_session_id;
    response_size = sizeof(response);
    status = libspdm_send_receive_data(spdm_context, &session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       response, &response_size);
    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
    assert_true(m_request_is_secured);
    assert_null(libspdm_get_session_info_via_session_id(spdm_context, m_session_id));
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
/**
 * Test 29: libspdm_start_session with PSK_EXCHANGE to a Responder that does not support a context.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS without sending PSK_FINISH, and the session is
 *                    established.
 **/
static void req_communication_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    set_connection_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    status = libspdm_start_session(spdm_context, true, LIBSPDM_TEST_PSK_HINT_STRING,
                                   sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                   SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
                                   &session_id, &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, m_session_id);
    assert_int_equal(m_request_count, 1);
    assert_false(m_request_is_secured);
    assert_int_equal(((spdm_message_header_t *)m_request)->request_response_code,
                     SPDM_PSK_EXCHANGE);
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    assert_non_null(session_info);
    assert_int_equal(
        libspdm_secured_message_get_session_state(session_info->secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_free_session_id(spdm_context, session_id);
}

/**
 * Test 30: libspdm_start_session with PSK_EXCHANGE to a Responder that supports a context.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS after PSK_FINISH is sent in the session, and
 *                    the session is established.
 **/
static void req_communication_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;

    set_connection_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    status = libspdm_start_session(spdm_context, true, LIBSPDM_TEST_PSK_HINT_STRING,
                                   sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                   SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
                                   &session_id, &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, m_session_id);
    assert_int_equal(m_request_count, 2);
    assert_true(m_request_is_secured);
    assert_int_equal(((spdm_message_header_t *)m_request)->request_response_code,
                     SPDM_PSK_FINISH);
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    assert_non_null(session_info);
    assert_int_equal(
        libspdm_secured_message_get_session_state(session_info->secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_free_session_id(spdm_context, session_id);
}

/**
 * Test 31: libspdm_start_session_exchange with PSK_EXCHANGE to a Responder that supports a context,
 *          followed by libspdm_start_session_finish.
 * Expected Behavior: The exchange returns LIBSPDM_STATUS_SUCCESS with the session handshaking. The
 *                    finish returns LIBSPDM_STATUS_SUCCESS after PSK_FINISH, and the session is
 *                    established.
 **/
static void req_communication_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    set_connection_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    status = libspdm_start_session_exchange(
        spdm_context, true, LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, measurement_hash,
        NULL, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, m_session_id);
    assert_int_equal(m_request_count, 1);
    assert_int_equal(((spdm_message_header_t *)m_request)->request_response_code,
                     SPDM_PSK_EXCHANGE);
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    assert_non_null(session_info);
    assert_int_equal(
        libspdm_secured_message_get_session_state(session_info->secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    status = libspdm_start_session_finish(spdm_context, session_id, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(m_request_count, 2);
    assert_true(m_request_is_secured);
    assert_int_equal(((spdm_message_header_t *)m_request)->request_response_code,
                     SPDM_PSK_FINISH);
    assert_int_equal(
        libspdm_secured_message_get_session_state(session_info->secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_free_session_id(spdm_context, session_id);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

int libspdm_req_communication_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_communication_case1),
        cmocka_unit_test(req_communication_case2),
        cmocka_unit_test(req_communication_case3),
        cmocka_unit_test(req_communication_case4),
        cmocka_unit_test(req_communication_case5),
        #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
        cmocka_unit_test(req_communication_case6),
        cmocka_unit_test(req_communication_case7),
        cmocka_unit_test(req_communication_case8),
        cmocka_unit_test(req_communication_case9),
        cmocka_unit_test(req_communication_case10),
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
        #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        cmocka_unit_test(req_communication_case11),
        cmocka_unit_test(req_communication_case12),
        cmocka_unit_test(req_communication_case13),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        cmocka_unit_test(req_communication_case14),
        cmocka_unit_test(req_communication_case15),
        cmocka_unit_test(req_communication_case16),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
        #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
        cmocka_unit_test(req_communication_case17),
        cmocka_unit_test(req_communication_case18),
        cmocka_unit_test(req_communication_case19),
        cmocka_unit_test(req_communication_case20),
        cmocka_unit_test(req_communication_case21),
        cmocka_unit_test(req_communication_case22),
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
        cmocka_unit_test(req_communication_case23),
        cmocka_unit_test(req_communication_case24),
        cmocka_unit_test(req_communication_case25),
        cmocka_unit_test(req_communication_case26),
        cmocka_unit_test(req_communication_case27),
        #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
        cmocka_unit_test(req_communication_case28),
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        cmocka_unit_test(req_communication_case29),
        cmocka_unit_test(req_communication_case30),
        cmocka_unit_test(req_communication_case31),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
