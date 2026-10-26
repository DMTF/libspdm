/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_transport_tcp_lib.h"
#include "industry_standard/spdm_tcp_binding.h"

static const uint32_t m_session_id = 0x12345678;

/* A GET_VERSION request. */
static const uint8_t m_spdm_message[] = {
    SPDM_MESSAGE_VERSION_10, SPDM_GET_VERSION, 0x00, 0x00
};

/* An application message whose fourth byte is not a TCP message type that libspdm decodes. */
static const uint8_t m_app_message[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

static uint8_t m_transport_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static uint8_t m_scratch_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static uint8_t m_message_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

/* Places the message after room for the transport header, as libspdm does, in the transport buffer
 * outside a session and in the scratch buffer in a session. Then encodes it as a request into the
 * transport buffer. */
static libspdm_return_t encode_message(void *spdm_context, const uint32_t *session_id,
                                       bool is_app_message, const uint8_t *message,
                                       size_t message_size, size_t *transport_message_size,
                                       uint8_t **transport_message)
{
    uint8_t *buffer_message;

    if (session_id == NULL) {
        buffer_message = m_transport_buffer + LIBSPDM_TCP_TRANSPORT_HEADER_SIZE;
    } else {
        buffer_message = m_scratch_buffer + LIBSPDM_TCP_TRANSPORT_HEADER_SIZE;
    }
    libspdm_copy_mem(buffer_message,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE - LIBSPDM_TCP_TRANSPORT_HEADER_SIZE,
                     message, message_size);
    *transport_message = m_transport_buffer;
    *transport_message_size = sizeof(m_transport_buffer);

    return libspdm_transport_tcp_encode_message(spdm_context, session_id, is_app_message, true,
                                                message_size, buffer_message,
                                                transport_message_size,
                                                (void **)transport_message);
}

/* Decodes a request, with m_message_buffer as the buffer for a decrypted message. */
static libspdm_return_t decode_message(void *spdm_context, uint32_t **session_id,
                                       bool *is_app_message, size_t transport_message_size,
                                       uint8_t *transport_message, size_t *message_size,
                                       uint8_t **message)
{
    *message = m_message_buffer;
    *message_size = sizeof(m_message_buffer);

    return libspdm_transport_tcp_decode_message(spdm_context, session_id, is_app_message, true,
                                                transport_message_size, transport_message,
                                                message_size, (void **)message);
}

/* Builds a TCP message of the given type around a payload, with the payload length that
 * DSP0287 specifies. */
static size_t build_tcp_message(uint8_t message_type, const void *payload, size_t payload_size,
                                uint8_t *tcp_message)
{
    spdm_tcp_binding_header_t *header;

    header = (void *)tcp_message;
    header->payload_length = (uint16_t)payload_size;
    header->binding_version = 0x01;
    header->message_type = message_type;
    if (payload_size != 0) {
        libspdm_copy_mem(tcp_message + sizeof(spdm_tcp_binding_header_t), payload_size,
                         payload, payload_size);
    }

    return sizeof(spdm_tcp_binding_header_t) + payload_size;
}

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
/* Establishes a session with m_session_id whose messages are encrypted and authenticated. */
static void set_session(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

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
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/* One context both encodes and decodes each secured request, so this undoes the increment of the
 * request sequence number by the encode. */
static void rewind_sequence_number(libspdm_context_t *spdm_context)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_context->session_info[0].secured_message_context;
    secured_message_context->application_secret.request_data_sequence_number--;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

/**
 * Test 1: Encode an SPDM message into a transport buffer one byte too small.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the size required.
 **/
static void libspdm_test_transport_tcp_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *message;
    size_t transport_message_size;
    void *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    message = m_transport_buffer + sizeof(spdm_tcp_binding_header_t);
    libspdm_copy_mem(message, sizeof(m_transport_buffer) - sizeof(spdm_tcp_binding_header_t),
                     m_spdm_message, sizeof(m_spdm_message));
    transport_message = m_transport_buffer;
    /* {ERROR} The buffer is one byte too small. */
    transport_message_size = sizeof(spdm_tcp_binding_header_t) + sizeof(m_spdm_message) - 1;

    status = libspdm_transport_tcp_encode_message(spdm_test_context->spdm_context, NULL, false,
                                                  true, sizeof(m_spdm_message), message,
                                                  &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(transport_message_size,
                     sizeof(spdm_tcp_binding_header_t) + sizeof(m_spdm_message));
}

/**
 * Test 2: Encode an application message outside a session.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, since application messages are
 * carried only in sessions.
 **/
static void libspdm_test_transport_tcp_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    /* {ERROR} An application message without a session. */
    status = encode_message(spdm_test_context->spdm_context, NULL, true, m_app_message,
                            sizeof(m_app_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: Encode an SPDM message in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_tcp_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;

    /* {ERROR} No session has m_session_id. */
    status = encode_message(spdm_test_context->spdm_context, &m_session_id, false,
                            m_spdm_message, sizeof(m_spdm_message), &transport_message_size,
                            &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: Decode a TCP message of a type that does not carry an SPDM message.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_tcp_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x4;

    /* {ERROR} A role inquiry carries no SPDM message. */
    transport_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY,
                                               m_spdm_message, sizeof(m_spdm_message),
                                               transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: Decode an in-session TCP message that ends within its session ID.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_tcp_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t) + sizeof(uint32_t)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x5;

    /* {ERROR} The session ID is not followed by a secured message. */
    transport_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_IN_SESSION, &m_session_id,
                                               sizeof(m_session_id), transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 6: Decode an in-session TCP message in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, and the last SPDM error is
 * InvalidSession for that session ID.
 **/
static void libspdm_test_transport_tcp_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t payload[sizeof(uint32_t) + 16];
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t) + sizeof(payload)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x6;

    libspdm_zero_mem(payload, sizeof(payload));
    /* {ERROR} No session has m_session_id. */
    libspdm_write_uint32(payload, m_session_id);
    transport_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_IN_SESSION, payload,
                                               sizeof(payload), transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    libspdm_get_last_spdm_error_struct(spdm_test_context->spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_INVALID_SESSION);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
}

/**
 * Test 7: Decode an in-session TCP message whose encrypted data was changed.
 * Expected Behavior: returns LIBSPDM_STATUS_CRYPTO_ERROR, and the last SPDM error is DecryptError
 * for that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_tcp_err_case7(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* {ERROR} The first encrypted byte, after the session ID and the length, is changed. */
    transport_message[sizeof(spdm_tcp_binding_header_t) + sizeof(uint32_t) +
                      sizeof(spdm_secured_message_a_data_header2_t)] ^= 0xFF;

    rewind_sequence_number(spdm_context);
    status = decode_message(spdm_context, &session_id, &is_app_message, transport_message_size,
                            transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    libspdm_get_last_spdm_error_struct(spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 8: Decode an in-session TCP message that carries another in-session TCP message.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, since a secured message carries only
 * an SPDM message or an application message.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_tcp_err_case8(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t payload[sizeof(uint32_t) + 4];
    uint8_t inner_message[sizeof(spdm_tcp_binding_header_t) + sizeof(payload)];
    size_t inner_message_size;
    size_t transport_message_size;
    uint8_t *transport_message;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    set_session(spdm_context);

    /* {ERROR} The application message is an in-session TCP message. */
    libspdm_zero_mem(payload, sizeof(payload));
    libspdm_write_uint32(payload, m_session_id);
    inner_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_IN_SESSION, payload,
                                           sizeof(payload), inner_message);

    status = encode_message(spdm_context, &m_session_id, true, inner_message,
                            inner_message_size, &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    rewind_sequence_number(spdm_context);
    status = decode_message(spdm_context, &session_id, &is_app_message, transport_message_size,
                            transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 9: Encode a discovery message of a type that is neither a role inquiry nor an error.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_PARAMETER.
 **/
static void libspdm_test_transport_tcp_err_case9(void **state)
{
    size_t transport_message_size;
    void *transport_message;

    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    /* {ERROR} An out-of-session message carries an SPDM message. */
    assert_int_equal(libspdm_tcp_encode_discovery_message(SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION,
                                                          &transport_message_size,
                                                          &transport_message),
                     LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 10: Encode a role inquiry into a buffer smaller than the header.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the size required.
 **/
static void libspdm_test_transport_tcp_err_case10(void **state)
{
    size_t transport_message_size;
    void *transport_message;

    transport_message = m_transport_buffer;
    /* {ERROR} The buffer is one byte too small. */
    transport_message_size = sizeof(spdm_tcp_binding_header_t) - 1;

    assert_int_equal(libspdm_tcp_encode_discovery_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY,
                                                          &transport_message_size,
                                                          &transport_message),
                     LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(transport_message_size, sizeof(spdm_tcp_binding_header_t));
}

/**
 * Test 11: Decode a discovery message shorter than the header.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_tcp_err_case11(void **state)
{
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t)];
    uint8_t message_type;

    build_tcp_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY, NULL, 0, transport_message);

    /* {ERROR} The message ends before the header does. */
    assert_int_equal(libspdm_tcp_decode_discovery_message(sizeof(transport_message) - 1,
                                                          transport_message, &message_type),
                     LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 12: Decode a discovery message of a binding version other than 1.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_tcp_err_case12(void **state)
{
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t)];
    uint8_t message_type;

    build_tcp_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY, NULL, 0, transport_message);
    /* {ERROR} The binding version is 2. */
    ((spdm_tcp_binding_header_t *)transport_message)->binding_version = 0x02;

    assert_int_equal(libspdm_tcp_decode_discovery_message(sizeof(transport_message),
                                                          transport_message, &message_type),
                     LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 13: Decode a discovery message whose payload length is not 0.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_tcp_err_case13(void **state)
{
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t)];
    uint8_t message_type;

    build_tcp_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY, NULL, 0, transport_message);
    /* {ERROR} A role inquiry has no payload. */
    ((spdm_tcp_binding_header_t *)transport_message)->payload_length = 1;

    assert_int_equal(libspdm_tcp_decode_discovery_message(sizeof(transport_message),
                                                          transport_message, &message_type),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: Decode a discovery message of a type that is neither a role inquiry nor an error.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_tcp_err_case14(void **state)
{
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t)];
    uint8_t message_type;

    /* {ERROR} An out-of-session message is not a discovery message. */
    build_tcp_message(SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION, NULL, 0, transport_message);

    assert_int_equal(libspdm_tcp_decode_discovery_message(sizeof(transport_message),
                                                          transport_message, &message_type),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 15: Decode an out-of-session TCP message of a binding version other than 1.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_tcp_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xF;

    transport_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION,
                                               m_spdm_message, sizeof(m_spdm_message),
                                               transport_message);
    /* {ERROR} The binding version is 2. */
    ((spdm_tcp_binding_header_t *)transport_message)->binding_version = 0x02;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 16: Decode an in-session TCP message of a binding version other than 1.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_tcp_err_case16(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* {ERROR} The binding version is 2. */
    ((spdm_tcp_binding_header_t *)transport_message)->binding_version = 0x02;

    rewind_sequence_number(spdm_context);
    status = decode_message(spdm_context, &session_id, &is_app_message, transport_message_size,
                            transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

int libspdm_transport_tcp_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case5,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case7,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case8,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case9),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case10),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case11),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case12),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case13),
        cmocka_unit_test(libspdm_test_transport_tcp_err_case14),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case15,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_err_case16,
                               libspdm_unit_test_reset_context),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        NULL,
        NULL,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
