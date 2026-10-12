/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"

static const uint32_t m_session_id = 0x12345678;

/* A GET_VERSION request, whose size is a multiple of four. */
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
                                       bool is_app_message, const void *message,
                                       size_t message_size, size_t *transport_message_size,
                                       uint8_t **transport_message)
{
    uint8_t *buffer_message;

    if (session_id == NULL) {
        buffer_message = m_transport_buffer + LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE;
    } else {
        buffer_message = m_scratch_buffer + LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE;
    }
    libspdm_copy_mem(buffer_message,
                     LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE -
                     LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE,
                     message, message_size);
    *transport_message = m_transport_buffer;
    *transport_message_size = sizeof(m_transport_buffer);

    return libspdm_transport_pci_doe_encode_message(spdm_context, session_id, is_app_message,
                                                    true, message_size, buffer_message,
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

    return libspdm_transport_pci_doe_decode_message(spdm_context, session_id, is_app_message,
                                                    true, transport_message_size,
                                                    transport_message, message_size,
                                                    (void **)message);
}

/* Builds a DOE data object of the given type around a payload, with the length that the payload
 * and the header give. */
static size_t build_data_object(uint8_t data_object_type, const void *payload,
                                size_t payload_size, uint8_t *data_object)
{
    pci_doe_data_object_header_t *header;
    size_t data_object_size;

    data_object_size = sizeof(pci_doe_data_object_header_t) + payload_size;
    header = (void *)data_object;
    header->vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    header->data_object_type = data_object_type;
    header->reserved = 0;
    header->length = (uint32_t)(data_object_size / sizeof(uint32_t));
    libspdm_copy_mem(data_object + sizeof(pci_doe_data_object_header_t), payload_size,
                     payload, payload_size);

    return data_object_size;
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
 * Test 1: Encode an application message.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, since the PCI-DOE binding carries only
 * SPDM messages.
 **/
static void libspdm_test_transport_pci_doe_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    /* {ERROR} An application message. */
    status = encode_message(spdm_test_context->spdm_context, &m_session_id, true,
                            m_spdm_message, sizeof(m_spdm_message), &transport_message_size,
                            &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: Encode an SPDM message in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_pci_doe_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    /* {ERROR} No session has m_session_id. */
    status = encode_message(spdm_test_context->spdm_context, &m_session_id, false,
                            m_spdm_message, sizeof(m_spdm_message), &transport_message_size,
                            &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: Encode an SPDM message that makes the data object larger than the maximum DOE size.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_FULL.
 **/
static void libspdm_test_transport_pci_doe_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *buffer;
    size_t buffer_size;
    size_t transport_message_size;
    void *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;

    buffer_size = PCI_DOE_MAX_SIZE_IN_BYTE + sizeof(uint32_t);
    buffer = malloc(buffer_size);
    assert_non_null(buffer);
    transport_message = buffer;
    transport_message_size = buffer_size;

    /* {ERROR} The data object is one DW larger than DOE allows. */
    status = libspdm_transport_pci_doe_encode_message(
        spdm_test_context->spdm_context, NULL, false, true,
        PCI_DOE_MAX_SIZE_IN_BYTE + sizeof(uint32_t) - sizeof(pci_doe_data_object_header_t),
        buffer + sizeof(pci_doe_data_object_header_t), &transport_message_size,
        &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_FULL);
    free(buffer);
}

/**
 * Test 4: Decode a DOE data object whose vendor ID is not PCI-SIG.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_pci_doe_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x4;

    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message,
                                               sizeof(m_spdm_message), transport_message);
    /* {ERROR} The vendor ID is not PCI-SIG. */
    ((pci_doe_data_object_header_t *)transport_message)->vendor_id = 0x1234;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 5: Decode a DOE data object of a type that is neither SPDM nor secured SPDM.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_pci_doe_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x5;

    /* {ERROR} The data object is a DOE Discovery object. */
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
                                               m_spdm_message, sizeof(m_spdm_message),
                                               transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 6: Decode a DOE data object whose reserved field is not zero.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_transport_pci_doe_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x6;

    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message,
                                               sizeof(m_spdm_message), transport_message);
    /* {ERROR} The reserved field is not zero. */
    ((pci_doe_data_object_header_t *)transport_message)->reserved = 1;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 7: Decode a DOE data object whose length is one DW more than its size.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_pci_doe_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x7;

    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message,
                                               sizeof(m_spdm_message), transport_message);
    /* {ERROR} The length does not match the size. */
    ((pci_doe_data_object_header_t *)transport_message)->length++;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 8: Decode a DOE data object whose length field has a bit above the 18-bit length set.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_pci_doe_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x8;

    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message,
                                               sizeof(m_spdm_message), transport_message);
    /* {ERROR} The length is at least 2^18 DW. */
    ((pci_doe_data_object_header_t *)transport_message)->length |= PCI_DOE_MAX_SIZE_IN_DW;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 9: Decode a secured SPDM data object that ends within its session ID.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_pci_doe_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(uint32_t)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x9;

    /* {ERROR} The session ID is not followed by a secured message. */
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM,
                                               &m_session_id, sizeof(m_session_id),
                                               transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 10: Decode a secured SPDM data object in a session that the SPDM context does not have.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP, and the last SPDM error is
 * InvalidSession for that session ID.
 **/
static void libspdm_test_transport_pci_doe_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t payload[sizeof(uint32_t) + 16];
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(payload)];
    size_t transport_message_size;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;
    libspdm_error_struct_t last_spdm_error;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xA;

    libspdm_zero_mem(payload, sizeof(payload));
    /* {ERROR} No session has m_session_id. */
    libspdm_write_uint32(payload, m_session_id);
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM, payload,
                                               sizeof(payload), transport_message);

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    libspdm_get_last_spdm_error_struct(spdm_test_context->spdm_context, &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, SPDM_ERROR_CODE_INVALID_SESSION);
    assert_int_equal(last_spdm_error.session_id, m_session_id);
}

/**
 * Test 11: Decode a secured SPDM data object whose encrypted data was changed.
 * Expected Behavior: returns LIBSPDM_STATUS_CRYPTO_ERROR, and the last SPDM error is DecryptError
 * for that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_pci_doe_err_case11(void **state)
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
    spdm_test_context->case_id = 0xB;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* {ERROR} The first encrypted byte, after the session ID and the length, is changed. */
    transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(uint32_t) +
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
 * Test 12: Decode a DOE Discovery request that is a DOE data object of type SPDM.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_transport_pci_doe_err_case12(void **state)
{
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message)];
    size_t transport_message_size;
    uint8_t index;

    /* {ERROR} The data object is an SPDM message. */
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message,
                                               sizeof(m_spdm_message), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_request(transport_message_size,
                                                              transport_message, &index),
                     LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 13: Decode a DOE Discovery response that ends before the response does.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void libspdm_test_transport_pci_doe_err_case13(void **state)
{
    uint16_t response_vendor_id;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(response_vendor_id)];
    uint16_t vendor_id;
    uint8_t protocol;
    uint8_t next_index;

    /* {ERROR} Only the vendor ID follows the header. */
    response_vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, &response_vendor_id,
                      sizeof(response_vendor_id), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_response(sizeof(transport_message),
                                                               transport_message, &vendor_id,
                                                               &protocol, &next_index),
                     LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

int libspdm_transport_pci_doe_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case5,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case7,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case8,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case9,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case10,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_err_case11,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_pci_doe_err_case12),
        cmocka_unit_test(libspdm_test_transport_pci_doe_err_case13),
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
