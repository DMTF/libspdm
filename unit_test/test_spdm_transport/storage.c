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
static const uint32_t m_session_id = 0x12345678;

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
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

/**
 * Test 1: Encode an SPDM request outside a session.
 * Expected Behavior: the transport message is the SPDM message after a virtual header of the
 * DMTF security protocol and the SPDM Storage Message operation, built in place in front of the
 * SPDM message.
 **/
static void libspdm_test_transport_storage_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    libspdm_storage_transport_virtual_header_t *header;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    status = encode_message(spdm_test_context->spdm_context, NULL, false, true, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message,
                     m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE -
                     sizeof(libspdm_storage_transport_virtual_header_t));
    assert_int_equal(transport_message_size,
                     sizeof(libspdm_storage_transport_virtual_header_t) + sizeof(m_spdm_message));
    header = (void *)transport_message;
    assert_int_equal(header->security_protocol, SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    assert_int_equal(header->security_protocol_specific,
                     SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2);
    assert_memory_equal(transport_message + sizeof(libspdm_storage_transport_virtual_header_t),
                        m_spdm_message, sizeof(m_spdm_message));
}

/**
 * Test 2: Encode an SPDM response outside a session.
 * Expected Behavior: the transport message is the SPDM message unchanged, since a storage response
 * has no virtual header.
 **/
static void libspdm_test_transport_storage_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    status = encode_message(spdm_test_context->spdm_context, NULL, false, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message, m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE);
    assert_int_equal(transport_message_size, sizeof(m_spdm_message));
    assert_memory_equal(transport_message, m_spdm_message, sizeof(m_spdm_message));
}

/**
 * Test 3: Encode an SPDM request for connection 3.
 * Expected Behavior: the virtual header carries the connection ID in the two low-order bits of the
 * security protocol specific field.
 **/
static void libspdm_test_transport_storage_case3(void **state)
{
    libspdm_return_t status;
    uint8_t *message;
    size_t transport_message_size;
    void *transport_message;
    libspdm_storage_transport_virtual_header_t *header;

    message = m_transport_buffer + LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE;
    libspdm_copy_mem(message, sizeof(m_transport_buffer) - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE,
                     m_spdm_message, sizeof(m_spdm_message));
    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_storage_encode_message(NULL, 3, sizeof(m_spdm_message), message,
                                            &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    header = transport_message;
    assert_int_equal(header->security_protocol_specific,
                     (SPDM_STORAGE_OPERATION_CODE_MESSAGE << 2) | 3);
}

/**
 * Test 4: Decode an SPDM request.
 * Expected Behavior: returns the SPDM message that follows the virtual header, outside a session.
 **/
static void libspdm_test_transport_storage_case4(void **state)
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
    spdm_test_context->case_id = 0x4;

    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_MESSAGE, 0,
                                           m_spdm_message, sizeof(m_spdm_message),
                                           transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_ptr_equal(message,
                     transport_message + sizeof(libspdm_storage_transport_virtual_header_t));
    assert_int_equal(message_size, sizeof(m_spdm_message));
}

/**
 * Test 5: Decode the virtual header of an SPDM request for connection 2.
 * Expected Behavior: returns connection ID 2 and the SPDM message that follows the virtual header.
 **/
static void libspdm_test_transport_storage_case5(void **state)
{
    libspdm_return_t status;
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t) +
                              sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    uint8_t connection_id;
    size_t message_size;
    void *message;

    transport_message_size = build_request(SPDM_STORAGE_OPERATION_CODE_MESSAGE, 2,
                                           m_spdm_message, sizeof(m_spdm_message),
                                           transport_message);

    status = libspdm_storage_decode_message(&session_id, &connection_id, transport_message_size,
                                            transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_int_equal(connection_id, 2);
    assert_ptr_equal(message,
                     transport_message + sizeof(libspdm_storage_transport_virtual_header_t));
    assert_int_equal(message_size, sizeof(m_spdm_message));
}

/**
 * Test 6: Decode an SPDM response outside a session.
 * Expected Behavior: returns the transport message unchanged, outside a session, since a storage
 * response has no virtual header.
 **/
static void libspdm_test_transport_storage_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(m_spdm_message)];
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x6;

    libspdm_copy_mem(transport_message, sizeof(transport_message),
                     m_spdm_message, sizeof(m_spdm_message));
    session_id = NULL;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message, false,
                            sizeof(transport_message), transport_message, &message_size,
                            &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_ptr_equal(message, transport_message);
    assert_int_equal(message_size, sizeof(transport_message));
}

/**
 * Test 7: Encode an SPDM request in a session, then decode it.
 * Expected Behavior: the virtual header is of the SPDM Storage Secured Message operation, the
 * secured message starts with four reserved bytes and the session ID, and decoding it returns the
 * SPDM message in that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_case7(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    libspdm_storage_transport_virtual_header_t *header;
    uint8_t *secured_message;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, true, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    header = (void *)transport_message;
    assert_int_equal(header->security_protocol, SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    assert_int_equal(header->security_protocol_specific,
                     SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE << 2);
    secured_message = transport_message + sizeof(libspdm_storage_transport_virtual_header_t);
    assert_int_equal(libspdm_read_uint32(secured_message), 0);
    assert_int_equal(libspdm_read_uint32(secured_message +
                                         LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES),
                     m_session_id);

    rewind_sequence_number(spdm_context, true);
    status = decode_message(spdm_context, &session_id, &is_app_message, true,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(session_id);
    assert_int_equal(*session_id, m_session_id);
    assert_false(is_app_message);
    assert_int_equal(message_size, sizeof(m_spdm_message));
    assert_memory_equal(message, m_spdm_message, sizeof(m_spdm_message));
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 8: Encode an SPDM response in a session, then decode it.
 * Expected Behavior: the transport message starts with four reserved bytes and the session ID, and
 * decoding it returns the SPDM message and the session ID.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_storage_case8(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    uint32_t session_id_value;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_read_uint32(transport_message), 0);
    assert_int_equal(libspdm_read_uint32(transport_message +
                                         LIBSPDM_STORAGE_SECURED_MESSAGE_HEADER_RESERVED_BYTES),
                     m_session_id);

    rewind_sequence_number(spdm_context, false);
    session_id_value = 0;
    session_id = &session_id_value;
    status = decode_message(spdm_context, &session_id, &is_app_message, false,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(session_id, &session_id_value);
    assert_int_equal(session_id_value, m_session_id);
    assert_false(is_app_message);
    assert_int_equal(message_size, sizeof(m_spdm_message));
    assert_memory_equal(message, m_spdm_message, sizeof(m_spdm_message));
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 9: Encode an SPDM Storage Discovery command to receive.
 * Expected Behavior: the command is a virtual header of the Discovery operation, and the
 * allocation length is the size of the Discovery response.
 **/
static void libspdm_test_transport_storage_case9(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    size_t allocation_length;
    libspdm_storage_transport_virtual_header_t *header;

    transport_message_size = sizeof(m_transport_buffer);
    allocation_length = 0;

    status = libspdm_transport_storage_encode_management_cmd(
        LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV, SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 1,
        &transport_message_size, &allocation_length, m_transport_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, sizeof(libspdm_storage_transport_virtual_header_t));
    assert_int_equal(allocation_length, sizeof(spdm_storage_discovery_response_t));
    header = (void *)m_transport_buffer;
    assert_int_equal(header->security_protocol, SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    assert_int_equal(header->security_protocol_specific,
                     (SPDM_STORAGE_OPERATION_CODE_DISCOVERY << 2) | 1);
}

/**
 * Test 10: Encode an SPDM Storage Pending Info command to receive.
 * Expected Behavior: the allocation length is the size of the Pending Info response.
 **/
static void libspdm_test_transport_storage_case10(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    size_t allocation_length;
    libspdm_storage_transport_virtual_header_t *header;

    transport_message_size = sizeof(m_transport_buffer);
    allocation_length = 0;

    status = libspdm_transport_storage_encode_management_cmd(
        LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV, SPDM_STORAGE_OPERATION_CODE_PENDING_INFO, 0,
        &transport_message_size, &allocation_length, m_transport_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, sizeof(libspdm_storage_transport_virtual_header_t));
    assert_int_equal(allocation_length, sizeof(spdm_storage_pending_info_response_t));
    header = (void *)m_transport_buffer;
    assert_int_equal(header->security_protocol_specific,
                     SPDM_STORAGE_OPERATION_CODE_PENDING_INFO << 2);
}

/**
 * Test 11: Decode an SPDM Storage Discovery command.
 * Expected Behavior: returns the Discovery operation.
 **/
static void libspdm_test_transport_storage_case11(void **state)
{
    uint8_t transport_message[sizeof(libspdm_storage_transport_virtual_header_t)];
    uint8_t transport_command;

    build_request(SPDM_STORAGE_OPERATION_CODE_DISCOVERY, 0, NULL, 0, transport_message);

    assert_int_equal(libspdm_transport_storage_decode_management_cmd(
                         sizeof(transport_message), transport_message, &transport_command),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_command, SPDM_STORAGE_OPERATION_CODE_DISCOVERY);
}

/**
 * Test 12: Encode an SPDM Storage Discovery response.
 * Expected Behavior: the response reports its own length, storage binding version 1.0, a single
 * connection and support for all four operations.
 **/
static void libspdm_test_transport_storage_case12(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    spdm_storage_discovery_response_t *response;

    libspdm_set_mem(m_transport_buffer, sizeof(m_transport_buffer), 0xFF);
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_transport_storage_encode_discovery_response(&transport_message_size,
                                                                 m_transport_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, sizeof(spdm_storage_discovery_response_t));
    response = (void *)m_transport_buffer;
    assert_int_equal(response->storage_response_headers.data_length,
                     sizeof(spdm_storage_discovery_response_t));
    assert_int_equal(response->storage_response_headers.storage_binding_version,
                     SPDM_STORAGE_SECURITY_BINDING_VERSION);
    assert_int_equal(response->conn_params, 0);
    assert_int_equal(response->supported_operations,
                     (1 << SPDM_STORAGE_OPERATION_CODE_DISCOVERY) |
                     (1 << SPDM_STORAGE_OPERATION_CODE_PENDING_INFO) |
                     (1 << SPDM_STORAGE_OPERATION_CODE_MESSAGE) |
                     (1 << SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE));
}

/**
 * Test 13: Encode an SPDM Storage Pending Info response without a pending response.
 * Expected Behavior: the response reports its own length and storage binding version 1.0, and its
 * flags and response length are 0.
 **/
static void libspdm_test_transport_storage_case13(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    spdm_storage_pending_info_response_t *response;

    libspdm_set_mem(m_transport_buffer, sizeof(m_transport_buffer), 0xFF);
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_transport_storage_encode_pending_info_response(&transport_message_size,
                                                                    m_transport_buffer, false,
                                                                    0x100);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, sizeof(spdm_storage_pending_info_response_t));
    response = (void *)m_transport_buffer;
    assert_int_equal(response->storage_response_headers.data_length,
                     sizeof(spdm_storage_pending_info_response_t));
    assert_int_equal(response->storage_response_headers.storage_binding_version,
                     SPDM_STORAGE_SECURITY_BINDING_VERSION);
    assert_int_equal(response->pending_info_flag, 0);
    assert_int_equal(response->response_length, 0);
}

/**
 * Test 14: Encode an SPDM Storage Pending Info response with a pending response.
 * Expected Behavior: the ValidResponse flag is set, and the response length is that of the pending
 * response.
 **/
static void libspdm_test_transport_storage_case14(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    spdm_storage_pending_info_response_t *response;

    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_transport_storage_encode_pending_info_response(&transport_message_size,
                                                                    m_transport_buffer, true,
                                                                    0x100);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = (void *)m_transport_buffer;
    assert_int_equal(response->pending_info_flag, 1);
    assert_int_equal(response->response_length, 0x100);
}

int libspdm_transport_storage_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_storage_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_storage_case3),
        cmocka_unit_test_setup(libspdm_test_transport_storage_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_storage_case5),
        cmocka_unit_test_setup(libspdm_test_transport_storage_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_case7,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_storage_case8,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_storage_case9),
        cmocka_unit_test(libspdm_test_transport_storage_case10),
        cmocka_unit_test(libspdm_test_transport_storage_case11),
        cmocka_unit_test(libspdm_test_transport_storage_case12),
        cmocka_unit_test(libspdm_test_transport_storage_case13),
        cmocka_unit_test(libspdm_test_transport_storage_case14),
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
