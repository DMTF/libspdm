/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"

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
 * Test 1: Encode an SPDM message, whose size is a multiple of four, outside a session.
 * Expected Behavior: the DOE data object is the SPDM message after a PCI-SIG header of type SPDM,
 * whose length in DW includes the header, built in place in front of the SPDM message.
 **/
static void libspdm_test_transport_pci_doe_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    pci_doe_data_object_header_t *header;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;

    status = encode_message(spdm_test_context->spdm_context, NULL, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message,
                     m_transport_buffer + LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE -
                     sizeof(pci_doe_data_object_header_t));
    assert_int_equal(transport_message_size,
                     sizeof(pci_doe_data_object_header_t) + sizeof(m_spdm_message));
    header = (void *)transport_message;
    assert_int_equal(header->vendor_id, PCI_DOE_VENDOR_ID_PCISIG);
    assert_int_equal(header->data_object_type, PCI_DOE_DATA_OBJECT_TYPE_SPDM);
    assert_int_equal(header->reserved, 0);
    assert_int_equal(header->length, transport_message_size / sizeof(uint32_t));
    assert_memory_equal(transport_message + sizeof(pci_doe_data_object_header_t),
                        m_spdm_message, sizeof(m_spdm_message));
}

/**
 * Test 2: Encode an SPDM message whose size is not a multiple of four.
 * Expected Behavior: the SPDM message is padded with zeros to a whole number of DW, and the length
 * includes the padding.
 **/
static void libspdm_test_transport_pci_doe_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_get_measurements_request_t spdm_request;
    uint8_t padding[3];
    size_t transport_message_size;
    uint8_t *transport_message;
    pci_doe_data_object_header_t *header;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;

    /* A signed GET_MEASUREMENTS request is 37 bytes. */
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    spdm_request.header.param2 = 1;
    libspdm_set_mem(spdm_request.nonce, sizeof(spdm_request.nonce), 0xAA);
    spdm_request.slot_id_param = 0;
    libspdm_set_mem(m_transport_buffer, sizeof(m_transport_buffer), 0xFF);
    libspdm_zero_mem(padding, sizeof(padding));

    status = encode_message(spdm_test_context->spdm_context, NULL, false, &spdm_request,
                            sizeof(spdm_request), &transport_message_size, &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(sizeof(spdm_request) % sizeof(uint32_t), sizeof(uint32_t) - sizeof(padding));
    assert_int_equal(transport_message_size,
                     sizeof(pci_doe_data_object_header_t) + sizeof(spdm_request) +
                     sizeof(padding));
    header = (void *)transport_message;
    assert_int_equal(header->length, transport_message_size / sizeof(uint32_t));
    assert_memory_equal(transport_message + sizeof(pci_doe_data_object_header_t),
                        &spdm_request, sizeof(spdm_request));
    assert_memory_equal(transport_message + sizeof(pci_doe_data_object_header_t) +
                        sizeof(spdm_request), padding, sizeof(padding));
}

/**
 * Test 3: Encode an SPDM message that makes the data object exactly the maximum DOE size.
 * Expected Behavior: the length is 0, which means 2^18 DW.
 **/
static void libspdm_test_transport_pci_doe_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *buffer;
    size_t buffer_size;
    size_t transport_message_size;
    void *transport_message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;

    buffer_size = PCI_DOE_MAX_SIZE_IN_BYTE;
    buffer = malloc(buffer_size);
    assert_non_null(buffer);
    transport_message = buffer;
    transport_message_size = buffer_size;

    status = libspdm_transport_pci_doe_encode_message(
        spdm_test_context->spdm_context, NULL, false, true,
        PCI_DOE_MAX_SIZE_IN_BYTE - sizeof(pci_doe_data_object_header_t),
        buffer + sizeof(pci_doe_data_object_header_t), &transport_message_size,
        &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(transport_message_size, PCI_DOE_MAX_SIZE_IN_BYTE);
    assert_int_equal(((pci_doe_data_object_header_t *)transport_message)->length, 0);
    free(buffer);
}

/**
 * Test 4: Decode a DOE data object of type SPDM.
 * Expected Behavior: returns the SPDM message that follows the header, outside a session.
 **/
static void libspdm_test_transport_pci_doe_case4(void **state)
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

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            transport_message_size, transport_message, &message_size, &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_ptr_equal(message, transport_message + sizeof(pci_doe_data_object_header_t));
    assert_int_equal(message_size, sizeof(m_spdm_message));
}

/**
 * Test 5: Decode a DOE data object of the maximum size, whose length is 0.
 * Expected Behavior: returns the SPDM message that follows the header.
 **/
static void libspdm_test_transport_pci_doe_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    uint8_t *transport_message;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x5;

    transport_message = malloc(PCI_DOE_MAX_SIZE_IN_BYTE);
    assert_non_null(transport_message);
    build_data_object(PCI_DOE_DATA_OBJECT_TYPE_SPDM, m_spdm_message, sizeof(m_spdm_message),
                      transport_message);
    ((pci_doe_data_object_header_t *)transport_message)->length = 0;

    status = decode_message(spdm_test_context->spdm_context, &session_id, &is_app_message,
                            PCI_DOE_MAX_SIZE_IN_BYTE, transport_message, &message_size,
                            &message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(message, transport_message + sizeof(pci_doe_data_object_header_t));
    assert_int_equal(message_size,
                     PCI_DOE_MAX_SIZE_IN_BYTE - sizeof(pci_doe_data_object_header_t));
    free(transport_message);
}

/**
 * Test 6: Encode an SPDM message in a session, then decode it.
 * Expected Behavior: the DOE data object is of type secured SPDM and starts with the session ID,
 * and decoding it returns the SPDM message in that session.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled.
 **/
static void libspdm_test_transport_pci_doe_case6(void **state)
{
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    pci_doe_data_object_header_t *header;
    uint32_t *session_id;
    bool is_app_message;
    size_t message_size;
    uint8_t *message;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    set_session(spdm_context);

    status = encode_message(spdm_context, &m_session_id, false, m_spdm_message,
                            sizeof(m_spdm_message), &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    header = (void *)transport_message;
    assert_int_equal(header->data_object_type, PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM);
    assert_int_equal(header->length, transport_message_size / sizeof(uint32_t));
    assert_int_equal(transport_message_size % sizeof(uint32_t), 0);
    assert_int_equal(libspdm_read_uint32(transport_message +
                                         sizeof(pci_doe_data_object_header_t)),
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
 * Test 7: Encode a DOE Discovery request.
 * Expected Behavior: the DOE data object is the request after a PCI-SIG header of type DOE
 * Discovery, built in place in front of the request.
 **/
static void libspdm_test_transport_pci_doe_case7(void **state)
{
    libspdm_return_t status;
    pci_doe_discovery_request_t *request;
    size_t transport_message_size;
    void *transport_message;
    pci_doe_data_object_header_t *header;

    request = (void *)(m_transport_buffer + sizeof(pci_doe_data_object_header_t));
    request->index = 1;
    request->version = PCI_DOE_DISCOVERY_VERSION_2;
    request->reserved[0] = 0;
    request->reserved[1] = 0;
    transport_message = m_transport_buffer;
    transport_message_size = sizeof(m_transport_buffer);

    status = libspdm_pci_doe_encode_discovery(sizeof(*request), request, &transport_message_size,
                                              &transport_message);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(transport_message, m_transport_buffer);
    assert_int_equal(transport_message_size,
                     sizeof(pci_doe_data_object_header_t) + sizeof(*request));
    header = transport_message;
    assert_int_equal(header->vendor_id, PCI_DOE_VENDOR_ID_PCISIG);
    assert_int_equal(header->data_object_type, PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY);
    assert_int_equal(header->reserved, 0);
    assert_int_equal(header->length, transport_message_size / sizeof(uint32_t));
}

/**
 * Test 8: Decode the index of a DOE Discovery request.
 * Expected Behavior: returns the index in the request.
 **/
static void libspdm_test_transport_pci_doe_case8(void **state)
{
    pci_doe_discovery_request_t request;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(request)];
    size_t transport_message_size;
    uint8_t index;

    request.index = 3;
    request.version = PCI_DOE_DISCOVERY_VERSION_2;
    request.reserved[0] = 0;
    request.reserved[1] = 0;
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, &request,
                                               sizeof(request), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_request(transport_message_size,
                                                              transport_message, &index),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(index, 3);
}

/**
 * Test 9: Decode the version of a DOE Discovery request.
 * Expected Behavior: returns the DOE Discovery version in the request.
 **/
static void libspdm_test_transport_pci_doe_case9(void **state)
{
    pci_doe_discovery_request_t request;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(request)];
    size_t transport_message_size;
    uint8_t version;

    request.index = 3;
    request.version = PCI_DOE_DISCOVERY_VERSION_2;
    request.reserved[0] = 0;
    request.reserved[1] = 0;
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, &request,
                                               sizeof(request), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_request_version(transport_message_size,
                                                                      transport_message,
                                                                      &version),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(version, PCI_DOE_DISCOVERY_VERSION_2);
}

/**
 * Test 10: Decode a DOE Discovery response for the SPDM data object type.
 * Expected Behavior: returns the vendor ID, the data object type and the next index in the
 * response.
 **/
static void libspdm_test_transport_pci_doe_case10(void **state)
{
    pci_doe_discovery_response_t response;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(response)];
    size_t transport_message_size;
    uint16_t vendor_id;
    uint8_t protocol;
    uint8_t next_index;

    response.vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    response.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_SPDM;
    response.next_index = 2;
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, &response,
                                               sizeof(response), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_response(transport_message_size,
                                                               transport_message, &vendor_id,
                                                               &protocol, &next_index),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(vendor_id, PCI_DOE_VENDOR_ID_PCISIG);
    assert_int_equal(protocol, PCI_DOE_DATA_OBJECT_TYPE_SPDM);
    assert_int_equal(next_index, 2);
}

/**
 * Test 11: Get the size of the transport header in front of a secured message.
 * Expected Behavior: returns the size of the DOE header and the cipher header.
 **/
static void libspdm_test_transport_pci_doe_case11(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0xB;

    assert_int_equal(libspdm_transport_pci_doe_get_header_size(spdm_test_context->spdm_context),
                     sizeof(pci_doe_data_object_header_t) +
                     sizeof(spdm_secured_message_cipher_header_t));
}

/**
 * Test 12: Get the sequence number for a secured DOE data object.
 * Expected Behavior: the PCI-DOE binding carries no sequence number, so none is written.
 **/
static void libspdm_test_transport_pci_doe_case12(void **state)
{
    uint8_t sequence_number[8];

    libspdm_set_mem(sequence_number, sizeof(sequence_number), 0xFF);

    assert_int_equal(libspdm_pci_doe_get_sequence_number(UINT64_C(0x0807060504030201),
                                                         sequence_number), 0);
    assert_int_equal(sequence_number[0], 0xFF);
}

/**
 * Test 13: Get the number of random bytes for a secured DOE data object.
 * Expected Behavior: returns 0, since the PCI-DOE binding adds no random bytes.
 **/
static void libspdm_test_transport_pci_doe_case13(void **state)
{
    assert_int_equal(libspdm_pci_doe_get_max_random_number_count(), 0);
}

/**
 * Test 14: Get the secured message version that the PCI-DOE binding uses.
 * Expected Behavior: returns the DSP0277 version unchanged.
 **/
static void libspdm_test_transport_pci_doe_case14(void **state)
{
    spdm_version_number_t version;

    version = SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_int_equal(libspdm_pci_doe_get_secured_spdm_version(version), version);
}

/**
 * Test 15: Decode a DOE Discovery response whose vendor ID does not fit in a byte.
 * Expected Behavior: returns the whole vendor ID.
 **/
static void libspdm_test_transport_pci_doe_case15(void **state)
{
    pci_doe_discovery_response_t response;
    uint8_t transport_message[sizeof(pci_doe_data_object_header_t) + sizeof(response)];
    size_t transport_message_size;
    uint16_t vendor_id;
    uint8_t protocol;
    uint8_t next_index;

    /* The CXL vendor ID. */
    response.vendor_id = 0x1E98;
    response.data_object_type = 2;
    response.next_index = 0;
    transport_message_size = build_data_object(PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, &response,
                                               sizeof(response), transport_message);

    assert_int_equal(libspdm_pci_doe_decode_discovery_response(transport_message_size,
                                                               transport_message, &vendor_id,
                                                               &protocol, &next_index),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(vendor_id, 0x1E98);
    assert_int_equal(protocol, 2);
    assert_int_equal(next_index, 0);
}

int libspdm_transport_pci_doe_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case5,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_transport_pci_doe_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case7),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case8),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case9),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case10),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case11),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case12),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case13),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case14),
        cmocka_unit_test(libspdm_test_transport_pci_doe_case15),
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
