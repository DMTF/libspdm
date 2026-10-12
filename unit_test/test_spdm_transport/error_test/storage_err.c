/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_transport_storage_lib.h"
#include "industry_standard/spdm_storage_binding.h"

static const uint32_t m_session_id = 0x12345678;

/* A GET_VERSION request. */
static const uint8_t m_spdm_message[] = {
    SPDM_MESSAGE_VERSION_10, SPDM_GET_VERSION, 0x00, 0x00
};

static uint8_t m_transport_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static uint8_t m_scratch_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static uint8_t m_message_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

/* Places the message after room for the transport header, as libspdm does, in the transport buffer
 * outside a session and in the scratch buffer in a session. Then encodes it into the transport
 * buffer. */
static libspdm_return_t encode_message(void *spdm_context, const uint32_t *session_id,
                                       bool is_app_message, bool is_request_message,
                                       const uint8_t *message, size_t message_size,
                                       size_t *transport_message_size,
                                       uint8_t **transport_message)
{
    uint8_t *buffer_message;

    if (session_id == NULL) {
        buffer_message = m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    } else {
        buffer_message = m_scratch_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    }
    libspdm_copy_mem(buffer_message,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE -
                     LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE,
                     message, message_size);
    *transport_message = m_transport_buffer;
    *transport_message_size = sizeof(m_transport_buffer);

    return libspdm_transport_storage_encode_message(spdm_context, session_id, is_app_message,
                                                    is_request_message, message_size,
                                                    buffer_message, transport_message_size,
                                                    (void **)transport_message);
}

/* Decodes a message, with m_message_buffer as the buffer for a decrypted message. */
static libspdm_return_t decode_message(void *spdm_context, uint32_t **session_id,
                                       bool *is_app_message, bool is_request_message,
                                       size_t transport_message_size,
                                       uint8_t *transport_message, size_t *message_size,
                                       uint8_t **message)
{
    *message = m_message_buffer;
    *message_size = sizeof(m_message_buffer);

    return libspdm_transport_storage_decode_message(spdm_context, session_id, is_app_message,
                                                    is_request_message, transport_message_size,
                                                    transport_message, message_size,
                                                    (void **)message);
}

/* Builds a storage request, a virtual header of the given operation and connection followed by
 * the payload. */
static size_t build_request(uint8_t operation, uint8_t connection_id, const void *payload,
                            size_t payload_size, uint8_t *transport_message)
{
    libspdm_storage_transport_virtual_header_t *header;

    header = (void *)transport_message;
    header->security_protocol = SPDM_STORAGE_SECURITY_PROTOCOL_DMTF;
    header->security_protocol_specific = (uint16_t)((operation << 2) | connection_id);
    if (payload_size != 0) {
        libspdm_copy_mem(transport_message + sizeof(libspdm_storage_transport_virtual_header_t),
                         payload_size, payload, payload_size);
    }

    return sizeof(libspdm_storage_transport_virtual_header_t) + payload_size;
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

/* One context both encodes and decodes each secured message, so this undoes the increment of the
 * sequence number by the encode. */
static void rewind_sequence_number(libspdm_context_t *spdm_context, bool is_request_message)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_context->session_info[0].secured_message_context;
    if (is_request_message) {
        secured_message_context->application_secret.request_data_sequence_number--;
    } else {
        secured_message_context->application_secret.response_data_sequence_number--;
    }
}

/* Carries the two low-order bytes of the sequence number in a secured message, as the storage
 * transport library does. */
static uint8_t get_sequence_number(uint64_t sequence_number, uint8_t *sequence_number_buffer)
{
    libspdm_write_uint16(sequence_number_buffer, (uint16_t)sequence_number);

    return SPDM_STORAGE_SEQUENCE_NUMBER_COUNT;
}

static uint32_t get_max_random_number_count(void)
{
    return 0;
}

static spdm_version_number_t get_secured_spdm_version(
    spdm_version_number_t secured_message_version)
{
    return secured_message_version;
}

/* Secures the application data as a request in m_session_id, then builds the secured storage
 * request around it in m_transport_buffer. Unlike the storage transport library, this does not
 * build the descriptor, so the application data can be malformed. */
static size_t build_secured_request(libspdm_context_t *spdm_context, const uint8_t *app_data,
                                    size_t app_data_size)
{
    libspdm_return_t status;
    libspdm_secured_message_callbacks_t callbacks;
    uint8_t *app_message;
    size_t header_size;
    size_t secured_message_size;

    callbacks.version = LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    callbacks.get_sequence_number = get_sequence_number;
    callbacks.get_max_random_number_count = get_max_random_number_count;
    callbacks.get_secured_spdm_version = get_secured_spdm_version;

    /* The encode places the application data length in front of the application data. */
    app_message = m_scratch_buffer + sizeof(spdm_secured_message_cipher_header_t);
    libspdm_copy_mem(app_message,
                     sizeof(m_scratch_buffer) - sizeof(spdm_secured_message_cipher_header_t),
                     app_data, app_data_size);

    libspdm_zero_mem(m_transport_buffer, sizeof(m_transport_buffer));
    header_size = build_request(SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE, 0, NULL, 0,
                                m_transport_buffer) +
                  LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES;
    secured_message_size = sizeof(m_transport_buffer) - header_size;
    status = libspdm_encode_secured_message(
        spdm_context->session_info[0].secured_message_context, m_session_id, true,
        app_data_size, app_message, &secured_message_size, m_transport_buffer + header_size,
        &callbacks);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    return header_size + secured_message_size;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

/**
 * Test 1: Encode an application message.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, since the storage transport carries
 * only SPDM messages.
 **/
static void libspdm_test_transport_storage_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    /* {ERROR} An application message. */
    status = encode_message(spdm_test_context->spdm_context, NULL, true, true, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: Encode an SPDM request into a transport buffer of size 0.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_storage_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *message;
    size_t transport_message_size;
    void *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    message = m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    libspdm_copy_mem(message, sizeof(m_transport_buffer) - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE,
                     m_spdm_message, sizeof(m_spdm_message));
    transport_message = m_transport_buffer;
    /* {ERROR} The transport buffer is empty. */
    transport_message_size = 0;

    status = libspdm_transport_storage_encode_message(spdm_test_context->spdm_context, NULL,
                                                      false, true, sizeof(m_spdm_message),
                                                      message, &transport_message_size,
                                                      &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 3: Encode an SPDM request into a transport buffer one byte too small.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the size required.
 **/
static void libspdm_test_transport_storage_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *message;
    size_t transport_message_size;
    void *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;

    message = m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    libspdm_copy_mem(message, sizeof(m_transport_buffer) - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE,
                     m_spdm_message, sizeof(m_spdm_message));
    transport_message = m_transport_buffer;
    /* {ERROR} The buffer is one byte too small. */
    transport_message_size = sizeof(libspdm_storage_transport_virtual_header_t) +
                             sizeof(m_spdm_message) - 1;

    status = libspdm_transport_storage_encode_message(spdm_test_context->spdm_context, NULL,
                                                      false, true, sizeof(m_spdm_message),
                                                      message, &transport_message_size,
                                                      &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(transport_message_size,
                     sizeof(libspdm_storage_transport_virtual_header_t) + sizeof(m_spdm_message));
}

/**
 * Test 4: Encode an SPDM request in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_storage_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x4;

    /* {ERROR} No session has m_session_id. */
    status = encode_message(spdm_test_context->spdm_context, &m_session_id, false, true,
                            m_spdm_message, sizeof(m_spdm_message), &transport_message_size,
                            &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: Encode an SPDM request for connection 4.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD, since a connection ID has two bits.
 **/
static void libspdm_test_transport_storage_err_case5(void **state)
{
    uint8_t *message;
    size_t transport_message_size;
    void *transport_message;

    message = m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    libspdm_copy_mem(message, sizeof(m_transport_buffer) - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE,
                     m_spdm_message, sizeof(m_spdm_message));
    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    /* {ERROR} The connection ID does not fit in two bits. */
    assert_int_equal(libspdm_storage_encode_message(NULL, 4, sizeof(m_spdm_message), message,
                                                    &transport_message_size, &transport_message),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 6: Decode a request of a security protocol other than DMTF SPDM.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_storage_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(m_spdm_message)];
    size_t transport_message_size;
    libspdm_storage_transport_virtual_header_t *header;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x6;

    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_MESSAGE, 0,
                                           m_spdm_message, sizeof(m_spdm_message),
                                           transport_message);
    header = (void *)transport_message;
    /* {ERROR} Security protocol 0 is not DMTF SPDM. */
    header->security_protocol = 0;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 7: Decode a request whose security protocol specific field has its high-order byte set.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_storage_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(m_spdm_message)];
    size_t transport_message_size;
    libspdm_storage_transport_virtual_header_t *header;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x7;

    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_MESSAGE, 0,
                                           m_spdm_message, sizeof(m_spdm_message),
                                           transport_message);
    header = (void *)transport_message;
    /* {ERROR} The high-order byte is reserved. */
    header->security_protocol_specific |= 0x0100;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 8: Decode a request of a reserved operation.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_storage_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x8;

    /* {ERROR} Operation 0x03 is reserved. */
    transport_message_size = build_request(0x03, 0, m_spdm_message, sizeof(m_spdm_message),
                                           transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 9: Decode a request that is only a virtual header.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_storage_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x9;

    /* {ERROR} No SPDM message follows the virtual header. */
    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_MESSAGE, 0, NULL, 0,
                                           transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 10: Decode a secured request that ends before its session ID.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_storage_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t payload[LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES];
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(payload)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xA;

    /* {ERROR} The reserved bytes are not followed by a session ID. */
    libspdm_zero_mem(payload, sizeof(payload));
    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE, 0,
                                           payload, sizeof(payload), transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 11: Decode a secured request in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, and the last SPDM error is
 * InvalidSession for that session ID.
 **/
static void libspdm_test_transport_storage_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t payload[LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES + sizeof(uint32_t) + 16];
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(payload)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xB;

    libspdm_zero_mem(payload, sizeof(payload));
    /* {ERROR} No session has m_session_id. */
    libspdm_write_uint32(payload + LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES,
                         m_session_id);
    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE, 0,
                                           payload, sizeof(payload), transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    libspdm_get_last_spdm_error_struct(spdm_test_context->spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_INVALID_SESSION);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
}

/**
 * Test 12: Decode a secured response that ends before its session ID.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_storage_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES +
                              sizeof(uint32_t) - 1];
    uint32_t session_id_value;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xC;

    /* {ERROR} The message ends within the session ID. */
    libspdm_zero_mem(transport_message, sizeof(transport_message));
    session_id_value = 0;
    session_id = &session_id_value;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, false,
                            sizeof(transport_message), transport_message, &message_size,
                            &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 13: Decode a secured response in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP and the session ID of the response, and
 * the last SPDM error is InvalidSession for that session ID.
 **/
static void libspdm_test_transport_storage_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES +
                              sizeof(uint32_t) + 16];
    uint32_t session_id_value;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xD;

    libspdm_zero_mem(transport_message, sizeof(transport_message));
    /* {ERROR} No session has m_session_id. */
    libspdm_write_uint32(transport_message + LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES,
                         m_session_id);
    session_id_value = 0;
    session_id = &session_id_value;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, false,
                            sizeof(transport_message), transport_message, &message_size,
                            &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(session_id_value, m_session_id);
    libspdm_get_last_spdm_error_struct(spdm_test_context->spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_INVALID_SESSION);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
}

/**
 * Test 14: Decode a secured request whose MAC does not verify.
 * Expected Behavior: returns LIBSPDM_STATUS_CRYPTO_ERROR, and the last SPDM error is DecryptError
 * for that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_err_case14(void **state)
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
    spdm_test_context->case_id = 0xE;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, true, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* {ERROR} The last byte of the MAC is changed. */
    transport_message[transport_message_size - 1] ^= 0xFF;

    rewind_sequence_number(spdm_context, true);
    status = decode_message(spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    libspdm_get_last_spdm_error_struct(spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 15: Encode an SPDM response in a session after an error, then decode it.
 * Expected Behavior: the descriptor of the response carries the encapsulated status of the last
 * SPDM error, so decoding it returns LIBSPDM_STATUS_ERROR_PEER.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_err_case15(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_error_struct_t last_spdm_error;
    size_t transport_message_size;
    uint8_t *transport_message;
    uint32_t session_id_value;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    set_session(spdm_context);

    /* {ERROR} The last request was an invalid command. */
    last_spdm_error.error_code = SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_INVALID_CMD;
    last_spdm_error.session_id = m_session_id;
    libspdm_set_last_spdm_error_struct(spdm_context, &last_spdm_error);

    status = encode_message(spdm_context, &m_session_id, false, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    rewind_sequence_number(spdm_context, false);
    session_id_value = 0;
    session_id = &session_id_value;
    status = decode_message(spdm_context, &session_id, &is_app_message, false,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 16: Decode a secured request whose application data is shorter than one descriptor.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_err_case16(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t app_data[LIBSPDM_STORAGE_SECURED_MESSAGE_DESCRIPTOR_MIN_SIZE - 1];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    set_session(spdm_context);

    /* {ERROR} The application data ends within the descriptor. */
    libspdm_zero_mem(app_data, sizeof(app_data));
    app_data[0] = 1;
    transport_message_size = build_secured_request(spdm_context, app_data, sizeof(app_data));

    rewind_sequence_number(spdm_context, true);
    status = decode_message(spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, m_transport_buffer, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 17: Decode a secured request without descriptors.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD, and the last SPDM error is the
 * Invalid Command encapsulated status for that session, which the next response carries.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_err_case17(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t app_data[LIBSPDM_STORAGE_SECURED_MESSAGE_DESCRIPTOR_MIN_SIZE + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    set_session(spdm_context);

    /* {ERROR} Num Descriptors is 0. */
    libspdm_zero_mem(app_data, sizeof(app_data));
    transport_message_size = build_secured_request(spdm_context, app_data, sizeof(app_data));

    rewind_sequence_number(spdm_context, true);
    status = decode_message(spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, m_transport_buffer, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    libspdm_get_last_spdm_error_struct(spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code,
                     SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_INVALID_CMD);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 18: Decode a secured request with two descriptors.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, since libspdm handles only one
 * descriptor, and the last SPDM error is the Invalid Command encapsulated status for that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_err_case18(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t app_data[LIBSPDM_STORAGE_SECURED_MESSAGE_DESCRIPTOR_MIN_SIZE +
                     sizeof(spdm_storage_secured_message_descriptor) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    set_session(spdm_context);

    /* {ERROR} Num Descriptors is 2. */
    libspdm_zero_mem(app_data, sizeof(app_data));
    app_data[0] = 2;
    transport_message_size = build_secured_request(spdm_context, app_data, sizeof(app_data));

    rewind_sequence_number(spdm_context, true);
    status = decode_message(spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, m_transport_buffer, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    libspdm_get_last_spdm_error_struct(spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code,
                     SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_INVALID_CMD);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 19: Encode a management command of a direction other than IF-SEND or IF-RECV.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_storage_err_case19(void **state)
{
    size_t transport_message_size;
    size_t allocation_length;

    transport_message_size = sizeof(m_transport_buffer);

    /* {ERROR} Direction 0x03 is neither IF-SEND nor IF-RECV. */
    assert_int_equal(libspdm_transport_storage_encode_management_cmd(
                         0x03, SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0,
                         &transport_message_size, &allocation_length, m_transport_buffer),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 20: Encode a management command of the SPDM Storage Message operation.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD, since only Discovery and Pending
 * Info are management commands.
 **/
static void libspdm_test_transport_storage_err_case20(void **state)
{
    size_t transport_message_size;
    size_t allocation_length;

    transport_message_size = sizeof(m_transport_buffer);

    /* {ERROR} An SPDM Storage Message is not a management command. */
    assert_int_equal(libspdm_transport_storage_encode_management_cmd(
                         LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV,
                         SPDM_STORAGE_OPERATION_CODE_MESSAGE, 0,
                         &transport_message_size, &allocation_length, m_transport_buffer),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 21: Encode a management command for connection 4.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD, since a connection ID has two bits.
 **/
static void libspdm_test_transport_storage_err_case21(void **state)
{
    size_t transport_message_size;
    size_t allocation_length;

    transport_message_size = sizeof(m_transport_buffer);

    /* {ERROR} The connection ID does not fit in two bits. */
    assert_int_equal(libspdm_transport_storage_encode_management_cmd(
                         LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV,
                         SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 4,
                         &transport_message_size, &allocation_length, m_transport_buffer),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 22: Encode an SPDM Storage Discovery command to receive into a buffer smaller than the
 * Discovery response.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void libspdm_test_transport_storage_err_case22(void **state)
{
    size_t transport_message_size;
    size_t allocation_length;

    /* {ERROR} The buffer is one byte too small for the response. */
    transport_message_size = sizeof(spdm_storage_discovery_response_t) - 1;

    assert_int_equal(libspdm_transport_storage_encode_management_cmd(
                         LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV,
                         SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0,
                         &transport_message_size, &allocation_length, m_transport_buffer),
                     LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 23: Encode a management command into a buffer smaller than the virtual header.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void libspdm_test_transport_storage_err_case23(void **state)
{
    size_t transport_message_size;
    size_t allocation_length;

    /* {ERROR} The buffer is one byte too small for the virtual header. */
    transport_message_size = sizeof(libspdm_storage_transport_virtual_header_t) - 1;

    assert_int_equal(libspdm_transport_storage_encode_management_cmd(
                         LIBSPDM_STORAGE_CMD_DIRECTION_IF_SEND,
                         SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0,
                         &transport_message_size, &allocation_length, m_transport_buffer),
                     LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 24: Decode a management command of a security protocol other than DMTF SPDM.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_storage_err_case24(void **state)
{
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t)];
    libspdm_storage_transport_virtual_header_t *header;
    uint8_t transport_command;

    build_request(SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0, NULL, 0, transport_message);
    header = (void *)transport_message;
    /* {ERROR} Security protocol 0 is not DMTF SPDM. */
    header->security_protocol = 0;

    assert_int_equal(libspdm_transport_storage_decode_management_cmd(
                         sizeof(transport_message), transport_message, &transport_command),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 25: Decode a management command whose security protocol specific field has its high-order
 * byte set.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_storage_err_case25(void **state)
{
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t)];
    libspdm_storage_transport_virtual_header_t *header;
    uint8_t transport_command;

    build_request(SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0, NULL, 0, transport_message);
    header = (void *)transport_message;
    /* {ERROR} The high-order byte is reserved. */
    header->security_protocol_specific |= 0x0100;

    assert_int_equal(libspdm_transport_storage_decode_management_cmd(
                         sizeof(transport_message), transport_message, &transport_command),
                     LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 26: Decode a management command of a reserved operation.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP and command 0.
 **/
static void libspdm_test_transport_storage_err_case26(void **state)
{
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t)];
    uint8_t transport_command;

    /* {ERROR} Operation 0x03 is reserved. */
    build_request(0x03, 0, NULL, 0, transport_message);
    transport_command = 0xFF;

    assert_int_equal(libspdm_transport_storage_decode_management_cmd(
                         sizeof(transport_message), transport_message, &transport_command),
                     LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(transport_command, 0);
}

/**
 * Test 27: Encode an SPDM Storage Discovery response into a buffer one byte too small.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void libspdm_test_transport_storage_err_case27(void **state)
{
    size_t transport_message_size;

    /* {ERROR} The buffer is one byte too small. */
    transport_message_size = sizeof(spdm_storage_discovery_response_t) - 1;

    assert_int_equal(libspdm_transport_storage_encode_discovery_response(&transport_message_size,
                                                                         m_transport_buffer),
                     LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 28: Encode an SPDM Storage Pending Info response into a buffer one byte too small.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void libspdm_test_transport_storage_err_case28(void **state)
{
    size_t transport_message_size;

    /* {ERROR} The buffer is one byte too small. */
    transport_message_size = sizeof(spdm_storage_pending_info_response_t) - 1;

    assert_int_equal(libspdm_transport_storage_encode_pending_info_response(
                         &transport_message_size, m_transport_buffer, true, 0x100),
                     LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

int libspdm_transport_storage_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_storage_err_case5),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case7,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case8,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case9,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case10,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case11,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case12,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case13,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case14,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case15,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case16,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case17,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_err_case18,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_storage_err_case19),
        cmocka_unit_test(libspdm_test_transport_storage_err_case20),
        cmocka_unit_test(libspdm_test_transport_storage_err_case21),
        cmocka_unit_test(libspdm_test_transport_storage_err_case22),
        cmocka_unit_test(libspdm_test_transport_storage_err_case23),
        cmocka_unit_test(libspdm_test_transport_storage_err_case24),
        cmocka_unit_test(libspdm_test_transport_storage_err_case25),
        cmocka_unit_test(libspdm_test_transport_storage_err_case26),
        cmocka_unit_test(libspdm_test_transport_storage_err_case27),
        cmocka_unit_test(libspdm_test_transport_storage_err_case28),
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
