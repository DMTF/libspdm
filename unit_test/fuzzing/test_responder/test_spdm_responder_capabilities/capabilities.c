/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void libspdm_test_responder_capabilities_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

void libspdm_test_responder_capabilities_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

void libspdm_test_responder_capabilities_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

spdm_test_context_t libspdm_test_responder_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;
    setup_spdm_test_context(&libspdm_test_responder_context);

    libspdm_test_responder_context.test_buffer = (void *)test_buffer;
    libspdm_test_responder_context.test_buffer_size = test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Success Case */
    libspdm_test_responder_capabilities_case1(&State);
    /* connection_state Check*/
    libspdm_test_responder_capabilities_case2(&State);
    /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY */
    libspdm_test_responder_capabilities_case3(&State);

    spdm_unit_test_group_teardown(&State);
}
