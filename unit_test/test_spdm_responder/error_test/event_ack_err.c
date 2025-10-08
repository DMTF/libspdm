/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static uint8_t m_spdm_request_buffer[0x1000];
static uint8_t m_spdm_response_buffer[0x1000];

static const uint32_t m_session_id = 0xffffffff;

typedef struct {
    uint32_t event_instance_id;
    uint8_t svh_id;
    uint8_t svh_vendor_id_len;
    uint8_t svh_vendor_id[4];
    uint16_t event_type_id;
    uint16_t event_detail_len;
    uint8_t event_detail[100];
} expected_event_t;

static expected_event_t m_expected_event[4];
static uint32_t m_event_counter;
static bool m_process_event_error = false;

static libspdm_return_t process_event(void *spdm_context,
                                      uint32_t session_id,
                                      uint32_t event_instance_id,
                                      uint8_t svh_id,
                                      uint8_t svh_vendor_id_len,
                                      const void *svh_vendor_id,
                                      uint16_t event_type_id,
                                      uint16_t event_detail_len,
                                      const void *event_detail)
{
    if (m_process_event_error) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    printf("Event Received\n");
    printf("Event Instance ID = [0x%x]\n", event_instance_id);
    printf("SVH ID = [0x%x], SVH VendorIDLen = [0x%x]\n", svh_id, svh_vendor_id_len);
    if (svh_vendor_id_len != 0) {
        printf("SVH VendorID\n");
        libspdm_dump_hex(svh_vendor_id, svh_vendor_id_len);
        printf("\n");
    }
    printf("EventTypeID = [0x%x], EventDetailLen = [0x%x]\n", event_type_id, event_detail_len);
    printf("Event Detail\n");
    libspdm_dump_hex(event_detail, event_detail_len);

    assert_int_equal(session_id, m_session_id);
    assert_int_equal(event_instance_id, m_expected_event[m_event_counter].event_instance_id);
    assert_int_equal(event_type_id, m_expected_event[m_event_counter].event_type_id);
    assert_int_equal(svh_id, m_expected_event[m_event_counter].svh_id);
    assert_int_equal(svh_vendor_id_len, m_expected_event[m_event_counter].svh_vendor_id_len);
    if (svh_vendor_id_len == 0) {
        assert_ptr_equal(svh_vendor_id, NULL);
    }
    assert_int_equal(event_detail_len, m_expected_event[m_event_counter].event_detail_len);
    assert_memory_equal(m_expected_event[m_event_counter].event_detail, event_detail,
                        event_detail_len);
    m_event_counter++;

    return LIBSPDM_STATUS_SUCCESS;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_register_event_callback(spdm_context, process_event);
}

/**
 * Test 1: Illegal EventCount is set to 0.
 * Expected behavior: InvalidRequest error response.
 **/
static void rsp_event_ack_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);
    uint8_t event_data_size;
    spdm_dmtf_event_type_event_lost_t event_lost;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;
    /* Illegal value for EventCount. */
    send_event->event_count = 0;

    event_lost.last_acked_event_inst_id = 0xffeeddcc;
    event_lost.last_lost_event_inst_id = 0x55667788;

    generate_dmtf_event_data(send_event + 1, &event_data_size, 0x11223344,
                             SPDM_DMTF_EVENT_TYPE_EVENT_LOST, &event_lost);

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t) + event_data_size;

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 2: Send two events with gap in event instance IDs.
 * Expected behavior: InvalidRequest error response.
 **/
static void rsp_event_ack_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);
    uint8_t event_data_size[2];
    spdm_dmtf_event_type_event_lost_t event_lost;
    spdm_dmtf_event_type_certificate_changed_t certificate_changed;
    uint8_t *ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;
    send_event->event_count = 2;

    certificate_changed.certificate_changed = 5;

    event_lost.last_acked_event_inst_id = 0xffeeddcc;
    event_lost.last_lost_event_inst_id = 0x55667788;

    ptr = (uint8_t *)(send_event + 1);

    generate_dmtf_event_data(ptr, &event_data_size[0], 0x11223343,
                             SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED, &certificate_changed);
    ptr += event_data_size[0];

    generate_dmtf_event_data(ptr, &event_data_size[1], 0x11223345,
                             SPDM_DMTF_EVENT_TYPE_EVENT_LOST, &event_lost);
    ptr += event_data_size[1];

    m_event_counter = 0;

    m_expected_event[0].event_instance_id = 0x11223343;
    m_expected_event[0].svh_id = SPDM_REGISTRY_ID_DMTF;
    m_expected_event[0].svh_vendor_id_len = 0;
    m_expected_event[0].event_type_id = SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED;

    m_expected_event[1].event_instance_id = 0x11223344;
    m_expected_event[1].svh_id = SPDM_REGISTRY_ID_DMTF;
    m_expected_event[1].svh_vendor_id_len = 0;
    m_expected_event[1].event_type_id = SPDM_DMTF_EVENT_TYPE_EVENT_LOST;

    request_size = sizeof(spdm_send_event_request_t) + event_data_size[0] + event_data_size[1];

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 3: Send one event but the value of EventCount is two.
 * Expected behavior: InvalidRequest error response.
 **/
static void rsp_event_ack_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);
    uint8_t event_data_size;
    spdm_dmtf_event_type_event_lost_t event_lost;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;
    /* Only one event but event_count is two. */
    send_event->event_count = 2;

    event_lost.last_acked_event_inst_id = 0xffeeddcc;
    event_lost.last_lost_event_inst_id = 0x55667788;

    generate_dmtf_event_data(send_event + 1, &event_data_size, 0x11223344,
                             SPDM_DMTF_EVENT_TYPE_EVENT_LOST, &event_lost);

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t) + event_data_size;

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 4: Send one event but request_size is not exact.
 * Expected behavior: InvalidRequest error response.
 **/
static void rsp_event_ack_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);
    uint8_t event_data_size;
    spdm_dmtf_event_type_event_lost_t event_lost;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;
    send_event->event_count = 1;

    event_lost.last_acked_event_inst_id = 0xffeeddcc;
    event_lost.last_lost_event_inst_id = 0x55667788;

    generate_dmtf_event_data(send_event + 1, &event_data_size, 0x11223344,
                             SPDM_DMTF_EVENT_TYPE_EVENT_LOST, &event_lost);

    m_event_counter = 0;

    /* request_size is not exact (+ 1). */
    request_size = sizeof(spdm_send_event_request_t) + event_data_size + 1;

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 5: Negotiated SPDM version does not support SEND_EVENT request message.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_event_ack_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);

    /* SPDM 1.2 does not support SEND_EVENT request message. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t);

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SEND_EVENT);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 6: SPDM version field in SEND_EVENT request message does not match the
 *         connection's negotiated version.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void rsp_event_ack_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x06;

    set_standard_state(spdm_context);

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    /* Value is not equal to the negotiated SPDM version (1.4). */
    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t);

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 7: Requester does not support EVENT_CAP.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_event_ack_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x07;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;

    /* Requester sends SEND_EVENT but does not support EVENT_CAP. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t);

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SEND_EVENT);

    assert_int_equal(m_event_counter, 0);
}

/**
 * Test 8: Call to process_event returns an error.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_event_ack_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_send_event_request_t *send_event;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size =  sizeof(m_spdm_response_buffer);
    uint8_t event_data_size;
    spdm_dmtf_event_type_event_lost_t event_lost;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    send_event = (spdm_send_event_request_t *)m_spdm_request_buffer;

    send_event->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    send_event->header.request_response_code = SPDM_SEND_EVENT;
    send_event->header.param1 = 0;
    send_event->header.param2 = 0;
    send_event->event_count = 1;

    event_lost.last_acked_event_inst_id = 0xffeeddcc;
    event_lost.last_lost_event_inst_id = 0x55667788;

    generate_dmtf_event_data(send_event + 1, &event_data_size, 0x11223344,
                             SPDM_DMTF_EVENT_TYPE_EVENT_LOST, &event_lost);

    m_event_counter = 0;

    request_size = sizeof(spdm_send_event_request_t) + event_data_size;

    /* Induce error in process_request. */
    m_process_event_error = true;

    status = libspdm_get_response_send_event(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    m_process_event_error = false;

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    assert_int_equal(m_event_counter, 0);
}

int libspdm_rsp_event_ack_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_event_ack_err_case1),
        cmocka_unit_test(rsp_event_ack_err_case2),
        cmocka_unit_test(rsp_event_ack_err_case3),
        cmocka_unit_test(rsp_event_ack_err_case4),
        cmocka_unit_test(rsp_event_ack_err_case5),
        cmocka_unit_test(rsp_event_ack_err_case6),
        cmocka_unit_test(rsp_event_ack_err_case7),
        cmocka_unit_test(rsp_event_ack_err_case8),
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

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
