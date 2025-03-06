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

void libspdm_test_transport_storage_decode_message(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    void *transport_message, *message, *dec_message;
    size_t transport_message_size, message_size, dec_message_size;
    uint32_t *session_id;
    bool is_app_message, dec_is_app_message, is_request_message;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(storage_spdm_transport_header)) {
        LIBSPDM_ASSERT(false);
    }

    /* Encode an SPDM Storage Message First (Test Setup) */
    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;
    is_app_message = false;
    is_request_message = true;
    message_size = 12;
    message = (uint8_t *)transport_message + sizeof(storage_spdm_transport_header);

    ret = libspdm_transport_storage_encode_message(
        state,
        NULL,
        is_app_message,
        is_request_message,
        message_size,
        message,
        &transport_message_size,
        &transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    ret = libspdm_transport_storage_decode_message(
        state,
        &session_id,
        &dec_is_app_message,
        is_request_message,
        transport_message_size,
        transport_message,
        &dec_message_size,
        &dec_message
        );
    /* Trivial Assertions */
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);
    LIBSPDM_ASSERT(dec_is_app_message == false);
    LIBSPDM_ASSERT(dec_message_size == message_size);
    USE_VAR(ret);
}

void libspdm_test_transport_storage_decode_management_cmd(void **state)
{
    libspdm_test_context_t *spdm_test_context = *state;
    void *transport_message;
    size_t transport_message_size;
    size_t alloc_len;
    uint32_t decoded_alloc_len;
    uint8_t cmd_direction;
    uint8_t transport_operation, transport_command;
    libspdm_return_t ret;

    if (m_libspdm_transport_storage_test_context.test_buffer_size <
        sizeof(storage_spdm_transport_header)) {
        LIBSPDM_ASSERT(false);
    }

    transport_message_size = LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE;
    transport_message = spdm_test_context->test_buffer;
    cmd_direction = LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV;
    transport_operation = SPDM_STORAGE_OPERATION_CODE_DISCOVERY;
    alloc_len = 0xFF;

    /* Encode a management command first (Test Setup) */
    ret = libspdm_transport_storage_encode_management_cmd(
        cmd_direction,
        transport_operation,
        0,
        &transport_message_size,
        &alloc_len,
        transport_message);
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);

    /* Attempt to decode with trivial assertions */
    ret = libspdm_transport_storage_decode_management_cmd(
        transport_message_size,
        transport_message,
        &transport_command,
        &decoded_alloc_len
        );
    LIBSPDM_ASSERT(ret == LIBSPDM_STATUS_SUCCESS);
    LIBSPDM_ASSERT(transport_command == SPDM_STORAGE_OPERATION_CODE_DISCOVERY);
    LIBSPDM_ASSERT(decoded_alloc_len == sizeof(storage_spdm_transport_header));
    USE_VAR(ret);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *state;

    libspdm_setup_test_context(&m_libspdm_transport_storage_test_context);

    m_libspdm_transport_storage_test_context.test_buffer = test_buffer;
    m_libspdm_transport_storage_test_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&state);

    libspdm_test_transport_storage_decode_management_cmd(&state);
    libspdm_test_transport_storage_decode_message(&state);

    libspdm_unit_test_group_teardown(&state);
}
