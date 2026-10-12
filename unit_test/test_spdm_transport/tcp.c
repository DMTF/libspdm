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

/* A GET_VERSION request. */
static const uint8_t m_spdm_message[] = {
    SPDM_MESSAGE_VERSION_10, SPDM_GET_VERSION, 0x00, 0x00
};

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
static const uint32_t m_session_id = 0x12345678;

/* An application message whose fourth byte is not a TCP message type that libspdm decodes. */
static const uint8_t m_app_message[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

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
 * Test 1: Encode an SPDM message outside a session.
 * Expected Behavior: the TCP message is the SPDM message after an out-of-session header, built in
 * place in front of the SPDM message. Per DSP0287, the payload length is the size of the SPDM
 * message.
 **/
static void libspdm_test_transport_tcp_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    spdm_tcp_binding_header_t *header;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    status = encode_message(spdm_test_context->spdm_context, NULL, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message,
                     m_transport_buffer + LIBSPDM_TCP_TRANSPORT_HEADER_SIZE -
                     sizeof(spdm_tcp_binding_header_t));
    assert_int_equal(transport_message_size,
                     sizeof(spdm_tcp_binding_header_t) + sizeof(m_spdm_message));
    header = (void *)transport_message;
    assert_int_equal(header->payload_length, sizeof(m_spdm_message));
    assert_int_equal(header->binding_version, 0x01);
    assert_int_equal(header->message_type, SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION);
    assert_memory_equal(transport_message + sizeof(spdm_tcp_binding_header_t), m_spdm_message,
                        sizeof(m_spdm_message));
}

/**
 * Test 2: Decode an out-of-session TCP message.
 * Expected Behavior: returns the SPDM message that follows the header, outside a session.
 **/
static void libspdm_test_transport_tcp_case2(void **state)
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
    spdm_test_context->case_id = 0x2;

    transport_message_size = build_tcp_message(SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION,
                                               m_spdm_message, sizeof(m_spdm_message),
                                               transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_ptr_equal(message, transport_message + sizeof(spdm_tcp_binding_header_t));
    assert_int_equal(message_size, sizeof(m_spdm_message));
}

/**
 * Test 3: Encode an SPDM message in a session, then decode it.
 * Expected Behavior: the TCP message is in-session, starts with the session ID and has the size of
 * the secured message as its payload length, and decoding it returns the SPDM message in that
 * session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_tcp_case3(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    spdm_tcp_binding_header_t *header;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    header = (void *)transport_message;
    assert_int_equal(header->payload_length,
                     transport_message_size - sizeof(spdm_tcp_binding_header_t));
    assert_int_equal(header->binding_version, 0x01);
    assert_int_equal(header->message_type, SPDM_TCP_MESSAGE_TYPE_IN_SESSION);
    assert_int_equal(libspdm_read_uint32(transport_message + sizeof(spdm_tcp_binding_header_t)),
                     m_session_id);

    rewind_sequence_number(spdm_context);
    status = decode_message(spdm_context, &session_id, &is_app_message, transport_message_size,
                            transport_message, &message_size, &message);

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
 * Test 4: Encode an application message in a session, then decode it.
 * Expected Behavior: decoding returns the application message in that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_tcp_case4(void **state)
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
    spdm_test_context->case_id = 0x4;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, true, m_app_message,
                            sizeof(m_app_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    rewind_sequence_number(spdm_context);
    status = decode_message(spdm_context, &session_id, &is_app_message, transport_message_size,
                            transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(session_id);
    assert_int_equal(*session_id, m_session_id);
    assert_true(is_app_message);
    assert_int_equal(message_size, sizeof(m_app_message));
    assert_memory_equal(message, m_app_message, sizeof(m_app_message));
#else
    skip();
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
}

/**
 * Test 5: Encode a role inquiry.
 * Expected Behavior: the message is a header alone, with a payload length of 0.
 **/
static void libspdm_test_transport_tcp_case5(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    void *transport_message;
    spdm_tcp_binding_header_t *header;

    libspdm_set_mem(m_transport_buffer, sizeof(m_transport_buffer), 0xFF);
    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_tcp_encode_discovery_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY,
                                                  &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message, m_transport_buffer);
    assert_int_equal(transport_message_size, sizeof(spdm_tcp_binding_header_t));
    header = transport_message;
    assert_int_equal(header->payload_length, 0);
    assert_int_equal(header->binding_version, 0x01);
    assert_int_equal(header->message_type, SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY);
}

/**
 * Test 6: Encode a TCP binding error message.
 * Expected Behavior: the message is a header alone, of that error type.
 **/
static void libspdm_test_transport_tcp_case6(void **state)
{
    libspdm_return_t status;
    size_t transport_message_size;
    void *transport_message;
    spdm_tcp_binding_header_t *header;

    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_tcp_encode_discovery_message(SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE,
                                                  &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, sizeof(spdm_tcp_binding_header_t));
    header = transport_message;
    assert_int_equal(header->payload_length, 0);
    assert_int_equal(header->message_type, SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE);
}

/**
 * Test 7: Decode a role inquiry.
 * Expected Behavior: returns its message type.
 **/
static void libspdm_test_transport_tcp_case7(void **state)
{
    uint8_t transport_message[sizeof(spdm_tcp_binding_header_t)];
    uint8_t message_type;

    build_tcp_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY, NULL, 0, transport_message);

    assert_int_equal(libspdm_tcp_decode_discovery_message(sizeof(transport_message),
                                                          transport_message, &message_type),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(message_type, SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY);
}

/**
 * Test 8: Get the size of the transport header in front of a secured message.
 * Expected Behavior: returns the size of the TCP binding header and the cipher header.
 **/
static void libspdm_test_transport_tcp_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x8;

    assert_int_equal(libspdm_transport_tcp_get_header_size(spdm_test_context->spdm_context),
                     sizeof(spdm_tcp_binding_header_t) +
                     sizeof(spdm_secured_message_cipher_header_t));
}

/**
 * Test 9: Get the sequence number for an in-session TCP message.
 * Expected Behavior: DSP0287 carries no sequence number, so none is written.
 **/
static void libspdm_test_transport_tcp_case9(void **state)
{
    uint8_t sequence_number[8];

    libspdm_set_mem(sequence_number, sizeof(sequence_number), 0xFF);

    assert_int_equal(libspdm_tcp_get_sequence_number(UINT64_C(0x0807060504030201),
                                                     sequence_number), 0);
    assert_int_equal(sequence_number[0], 0xFF);
}

/**
 * Test 10: Get the number of random bytes for an in-session TCP message.
 * Expected Behavior: returns 0, since DSP0287 adds no random bytes.
 **/
static void libspdm_test_transport_tcp_case10(void **state)
{
    assert_int_equal(libspdm_tcp_get_max_random_number_count(), 0);
}

/**
 * Test 11: Get the secured message version that DSP0287 uses.
 * Expected Behavior: returns the DSP0277 version unchanged.
 **/
static void libspdm_test_transport_tcp_case11(void **state)
{
    spdm_version_number_t version;

    version = SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_int_equal(libspdm_tcp_get_secured_spdm_version(version), version);
}

int libspdm_transport_tcp_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_tcp_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_tcp_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_tcp_case5),
        cmocka_unit_test(libspdm_test_transport_tcp_case6),
        cmocka_unit_test(libspdm_test_transport_tcp_case7),
        cmocka_unit_test(libspdm_test_transport_tcp_case8),
        cmocka_unit_test(libspdm_test_transport_tcp_case9),
        cmocka_unit_test(libspdm_test_transport_tcp_case10),
        cmocka_unit_test(libspdm_test_transport_tcp_case11),
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
