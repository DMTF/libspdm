/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_transport_tcp_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_RECEIVER_BUFFER_SIZE;
}

void libspdm_test_transport_tcp_decode_message(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    bool is_app_message;
    bool is_requester;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    is_app_message = false;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    transport_message_size = spdm_test_context->test_buffer_size;

    libspdm_transport_tcp_decode_message(spdm_context, NULL, &is_app_message, is_requester,
                                         spdm_test_context->test_buffer_size,
                                         spdm_test_context->test_buffer, &transport_message_size,
                                         (void **)&transport_message);
}

libspdm_test_context_t m_libspdm_transport_tcp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_transport_tcp_test_context);

    m_libspdm_transport_tcp_test_context.test_buffer = test_buffer;
    m_libspdm_transport_tcp_test_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    libspdm_test_transport_tcp_decode_message(&State);

    libspdm_unit_test_group_teardown(&State);
}
