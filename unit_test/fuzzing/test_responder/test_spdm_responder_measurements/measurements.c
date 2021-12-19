/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_measurements(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->local_context.opaque_measurement_rsp_size = 0;
    spdm_context->local_context.opaque_measurement_rsp = NULL;

    response_size = sizeof(response);
    spdm_get_response_measurements(spdm_context,
                       spdm_test_context->test_buffer_size,
                       spdm_test_context->test_buffer,
                       &response_size, response);
}

spdm_test_context_t m_spdm_responder_measurements_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_measurements_test_context);

    m_spdm_responder_measurements_test_context.test_buffer = test_buffer;
    m_spdm_responder_measurements_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_responder_measurements(&State);

    spdm_unit_test_group_teardown(&State);
}
