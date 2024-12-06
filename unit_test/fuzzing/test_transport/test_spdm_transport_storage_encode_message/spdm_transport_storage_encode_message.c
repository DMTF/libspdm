/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_transport_storage_lib.h"
#include "industry_standard/spdm_storage_binding.h"
#include "industry_standard/pcidoe.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

/*
 * This is to workaround `set but not used warning for build configs without
 * `LIBSPDM_ASSERT() support.
 */
#define USE_VAR(x) (void)(x)

libspdm_test_context_t m_libspdm_transport_storage_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_transport_storage_encode_message(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    storage_spdm_transport_header *hdr;
    void *transport_message, *message;
    size_t transport_message_size, message_size;
    bool is_app_message, is_request_message;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(storage_spdm_transport_header)) {
        LIBSPDM_ASSERT(false);
    }

    /* Valid Parameters: SPDM Storage Message */
    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;
    is_app_message = false;
    is_request_message = true;
    message_size = 12;
    message = (uint8_t *)transport_message + sizeof(storage_spdm_transport_header);

    ret = libspdm_transport_storage_encode_message(state,
                                                   NULL,
                                                   is_app_message,
                                                   is_request_message,
                                                   message_size,
                                                   message,
                                                   &transport_message_size,
                                                   &transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    /* Trivial assertions for transport virtual header encoding */
    hdr = transport_message;
    LIBSPDM_ASSERT(hdr->security_protocol == SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    LIBSPDM_ASSERT((hdr->security_protocol_specific >> 8) == 0); /* SPSP1 */
    LIBSPDM_ASSERT((hdr->security_protocol_specific & 0xFF) != 0); /* SPSP0 */
    LIBSPDM_ASSERT(hdr->length == (message_size + sizeof(storage_spdm_transport_header)));

    /* Invalid Parameters: Message side exceeds transport buffer size */
    transport_message_size = 0;
    ret = libspdm_transport_storage_encode_message(state,
                                                   NULL,
                                                   is_app_message,
                                                   is_request_message,
                                                   message_size,
                                                   message,
                                                   &transport_message_size,
                                                   &transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_INVALID_MSG_SIZE);
    USE_VAR(ret);
    USE_VAR(hdr);
}

void libspdm_test_transport_storage_encode_management_cmd(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    storage_spdm_transport_header *hdr;
    size_t transport_message_size;
    void *transport_message;
    size_t allocation_len = 0;
    uint8_t cmd_direction;
    uint8_t transport_operation;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(storage_spdm_transport_header)) {
        LIBSPDM_ASSERT(false);
    }

    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;
    cmd_direction = LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV;
    transport_operation = SPDM_STORAGE_OPERATION_CODE_DISCOVERY;

    /* Valid Parameters: Test IF_RECV Discovery */
    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &allocation_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);
    LIBSPDM_ASSERT(allocation_len != 0);

    /* Trivial Compliance Assertions */
    hdr = transport_message;
    LIBSPDM_ASSERT(hdr->security_protocol == SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    LIBSPDM_ASSERT((hdr->security_protocol_specific >> 8) == 0); /* SPSP1 */
    LIBSPDM_ASSERT((hdr->security_protocol_specific & 0xFF) != 0); /* SPSP0 */
    LIBSPDM_ASSERT(hdr->inc_512 == false);
    LIBSPDM_ASSERT(hdr->length == sizeof(storage_spdm_transport_header));

    /* Valid Parameters: Test IF_SEND Pending Info */
    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    cmd_direction = LIBSPDM_STORAGE_CMD_DIRECTION_IF_SEND;
    transport_operation = SPDM_STORAGE_OPERATION_CODE_PENDING_INFO;
    allocation_len = 0;

    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &allocation_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);
    LIBSPDM_ASSERT(allocation_len == 0);

    /* Trivial Compliance Assertions */
    hdr = transport_message;
    LIBSPDM_ASSERT(hdr->security_protocol == SPDM_STORAGE_SECURITY_PROTOCOL_DMTF);
    LIBSPDM_ASSERT((hdr->security_protocol_specific >> 8) == 0); /* SPSP1 */
    LIBSPDM_ASSERT((hdr->security_protocol_specific & 0xFF) != 0); /* SPSP0 */
    LIBSPDM_ASSERT(hdr->inc_512 == false);
    LIBSPDM_ASSERT(hdr->length == sizeof(storage_spdm_transport_header));

    /* Bad Transport Message Size */
    transport_message_size = 0;
    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &allocation_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_INVALID_MSG_SIZE);

    /* Invalid Command Direction */
    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    cmd_direction = 0xFF;

    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &allocation_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Invalid Transport Operation*/
    cmd_direction = LIBSPDM_STORAGE_CMD_DIRECTION_IF_SEND;
    transport_operation = 0xDD;

    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &allocation_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_INVALID_MSG_FIELD);
    USE_VAR(ret);
    USE_VAR(hdr);
}

void libspdm_test_transport_storage_encode_discovery_response(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    spdm_storage_discovery_response_t *d_resp;
    size_t transport_message_size;
    void *transport_message;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(spdm_storage_discovery_response_t)) {
        LIBSPDM_ASSERT(false);
    }

    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;

    /* Valid Parameters */
    ret = libspdm_transport_storage_encode_discovery_response(
        &transport_message_size,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    d_resp = transport_message;
    LIBSPDM_ASSERT(transport_message_size == sizeof(spdm_storage_discovery_response_t));
    LIBSPDM_ASSERT(d_resp->data_length == sizeof(spdm_storage_discovery_response_t));
    LIBSPDM_ASSERT(d_resp->storage_binding_version == SPDM_STORAGE_SECURITY_BINDING_VERSION);
    LIBSPDM_ASSERT(d_resp->supported_operations != 0);

    /* Invalid Input Buffer Size */
    transport_message_size = 1;

    ret = libspdm_transport_storage_encode_discovery_response(
        &transport_message_size,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    USE_VAR(ret);
    USE_VAR(d_resp);
}

void libspdm_test_transport_storage_encode_pending_resp(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    spdm_storage_pending_info_response_t *p_resp;
    size_t transport_message_size;
    void *transport_message;
    bool resp_pending;
    uint32_t pending_response_length;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(spdm_storage_pending_info_response_t)) {
        LIBSPDM_ASSERT(false);
    }

    /* Valid Parameters: Response Pending */
    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;
    resp_pending = true;
    pending_response_length = 32;
    ret = libspdm_transport_storage_encode_pending_info_response(
        &transport_message_size,
        transport_message,
        resp_pending,
        pending_response_length
        );
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    p_resp = transport_message;
    LIBSPDM_ASSERT(transport_message_size == sizeof(spdm_storage_pending_info_response_t));
    LIBSPDM_ASSERT(p_resp->data_length == sizeof(spdm_storage_pending_info_response_t));
    LIBSPDM_ASSERT(p_resp->storage_binding_version == SPDM_STORAGE_SECURITY_BINDING_VERSION);
    LIBSPDM_ASSERT(p_resp->pending_info_flag == 1);
    LIBSPDM_ASSERT(p_resp->response_length == pending_response_length);

    /* Valid Parameters: No Response Pending */
    resp_pending = false;
    ret = libspdm_transport_storage_encode_pending_info_response(
        &transport_message_size,
        transport_message,
        resp_pending,
        pending_response_length
        );
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    p_resp = transport_message;
    LIBSPDM_ASSERT(transport_message_size == sizeof(spdm_storage_pending_info_response_t));
    LIBSPDM_ASSERT(p_resp->data_length == sizeof(spdm_storage_pending_info_response_t));
    LIBSPDM_ASSERT(p_resp->storage_binding_version == SPDM_STORAGE_SECURITY_BINDING_VERSION);
    LIBSPDM_ASSERT(p_resp->pending_info_flag == 0);
    LIBSPDM_ASSERT(p_resp->response_length == 0);

    /* Invalid Transport Message Size */
    transport_message_size = 1;
    ret = libspdm_transport_storage_encode_pending_info_response(
        &transport_message_size,
        transport_message,
        resp_pending,
        pending_response_length
        );
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_BUFFER_TOO_SMALL);

    ret = libspdm_transport_storage_encode_pending_info_response(
        NULL,
        transport_message,
        resp_pending,
        pending_response_length
        );
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_INVALID_MSG_SIZE);
    USE_VAR(ret);
    USE_VAR(p_resp);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *state;

    libspdm_setup_test_context(&m_libspdm_transport_storage_test_context);

    m_libspdm_transport_storage_test_context.test_buffer = test_buffer;
    m_libspdm_transport_storage_test_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&state);

    libspdm_test_transport_storage_encode_message(&state);
    libspdm_test_transport_storage_encode_management_cmd(&state);
    libspdm_test_transport_storage_encode_discovery_response(&state);
    libspdm_test_transport_storage_encode_pending_resp(&state);

    libspdm_unit_test_group_teardown(&state);
}
