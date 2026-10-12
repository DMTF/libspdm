/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_transport_mctp_lib.h"

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
        buffer_message = m_transport_buffer + LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE;
    } else {
        buffer_message = m_scratch_buffer + LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE;
    }
    libspdm_copy_mem(buffer_message,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE - LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
                     message, message_size);
    *transport_message = m_transport_buffer;
    *transport_message_size = sizeof(m_transport_buffer);

    return libspdm_transport_mctp_encode_message(spdm_context, session_id, is_app_message, true,
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

    return libspdm_transport_mctp_decode_message(spdm_context, session_id, is_app_message, true,
                                                 transport_message_size, transport_message,
                                                 message_size, (void **)message);
}

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
static const uint32_t m_session_id = 0x12345678;

/* An application message whose first byte is not an MCTP message type that libspdm decodes. */
static const uint8_t m_app_message[] = {0x7E, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

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
 * Expected Behavior: the MCTP message is the SPDM message after a header of message type SPDM,
 * built in place in front of the SPDM message.
 **/
static void libspdm_test_transport_mctp_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    status = encode_message(spdm_test_context->spdm_context, NULL, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message,
                     m_transport_buffer + LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE -
                     sizeof(mctp_message_header_t));
    assert_int_equal(transport_message_size,
                     sizeof(mctp_message_header_t) + sizeof(m_spdm_message));
    assert_int_equal(transport_message[0], MCTP_MESSAGE_TYPE_SPDM);
    assert_memory_equal(transport_message + sizeof(mctp_message_header_t), m_spdm_message,
                        sizeof(m_spdm_message));
}

/**
 * Test 2: Decode an MCTP message of message type SPDM.
 * Expected Behavior: returns the SPDM message that follows the header, outside a session.
 **/
static void libspdm_test_transport_mctp_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(mctp_message_header_t) + sizeof(m_spdm_message)];
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    transport_message[0] = MCTP_MESSAGE_TYPE_SPDM;
    libspdm_copy_mem(transport_message + sizeof(mctp_message_header_t),
                     sizeof(transport_message) - sizeof(mctp_message_header_t),
                     m_spdm_message, sizeof(m_spdm_message));

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            sizeof(transport_message), transport_message, &message_size,
                            &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_ptr_equal(message, transport_message + sizeof(mctp_message_header_t));
    assert_int_equal(message_size, sizeof(m_spdm_message));
}

/**
 * Test 3: Encode an SPDM message in a session, then decode it.
 * Expected Behavior: the MCTP message is secured and starts with the session ID, and decoding it
 * returns the SPDM message in that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_mctp_case3(void **state)
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
    spdm_test_context->case_id = 0x3;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message[0], MCTP_MESSAGE_TYPE_SECURED_MCTP);
    assert_int_equal(libspdm_read_uint32(transport_message + sizeof(mctp_message_header_t)),
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
static void libspdm_test_transport_mctp_case4(void **state)
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
 * Test 5: Get the sequence number for a secured MCTP message.
 * Expected Behavior: DSP0276 carries the two low-order bytes of the sequence number, in
 * little-endian order.
 **/
static void libspdm_test_transport_mctp_case5(void **state)
{
    uint8_t sequence_number[8];

    libspdm_set_mem(sequence_number, sizeof(sequence_number), 0xFF);

    assert_int_equal(libspdm_mctp_get_sequence_number(UINT64_C(0x0807060504030201),
                                                      sequence_number), 2);
    assert_int_equal(sequence_number[0], 0x01);
    assert_int_equal(sequence_number[1], 0x02);
    assert_int_equal(sequence_number[2], 0xFF);
}

/**
 * Test 6: Get the number of random bytes for a secured MCTP message.
 * Expected Behavior: returns LIBSPDM_MCTP_MAX_RANDOM_NUMBER_COUNT.
 **/
static void libspdm_test_transport_mctp_case6(void **state)
{
    assert_int_equal(libspdm_mctp_get_max_random_number_count(),
                     LIBSPDM_MCTP_MAX_RANDOM_NUMBER_COUNT);
}

/**
 * Test 7: Get the secured message version that DSP0276 uses.
 * Expected Behavior: returns the DSP0277 version unchanged, since DSP0276 uses its version
 * numbers.
 **/
static void libspdm_test_transport_mctp_case7(void **state)
{
    spdm_version_number_t version;

    version = SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_int_equal(libspdm_mctp_get_secured_spdm_version(version), version);
}

int libspdm_transport_mctp_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_mctp_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_mctp_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_mctp_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_mctp_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_mctp_case5),
        cmocka_unit_test(libspdm_test_transport_mctp_case6),
        cmocka_unit_test(libspdm_test_transport_mctp_case7),
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
