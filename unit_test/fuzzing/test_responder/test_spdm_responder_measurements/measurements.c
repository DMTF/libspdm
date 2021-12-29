/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <stdio.h>

#define TEST_PSK_HINT_STRING "TestPskHint"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_measurements_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;

    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->local_context.opaque_measurement_rsp_size = 0;
    spdm_context->local_context.opaque_measurement_rsp = NULL;

    response_size = sizeof(response);
    spdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_measurements_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_session_info_t *session_info;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint32_t session_id;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    static uint8_t m_local_psk_hint[32];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 0;
    spdm_context->local_context.opaque_measurement_rsp_size = 0;
    spdm_context->local_context.opaque_measurement_rsp = NULL;

    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = TRUE;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, TRUE);

    response_size = sizeof(response);

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_measurements_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;

    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->local_context.opaque_measurement_rsp_size = 0;
    spdm_context->local_context.opaque_measurement_rsp = NULL;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.slot_count = SPDM_MAX_SLOT_COUNT;
    for (int i = 1; i < spdm_context->local_context.slot_count; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    response_size = sizeof(response);

    spdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_measurements_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_session_info_t *session_info;
    spdm_context_t *spdm_context;
    uintn response_size;
    uintn data_size;
    void *data;
    uint32_t session_id;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    static uint8_t m_local_psk_hint[32];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context->connection_info.version.major_version = 1;
    spdm_context->connection_info.version.minor_version = 1;
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->local_context.opaque_measurement_rsp_size = 0;
    spdm_context->local_context.opaque_measurement_rsp = NULL;

    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.slot_count = SPDM_MAX_SLOT_COUNT;
    for (int i = 1; i < spdm_context->local_context.slot_count; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = TRUE;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, TRUE);

    response_size = sizeof(response);

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer, &response_size, response);
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
    m_spdm_responder_measurements_test_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_measurements_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /*last_spdm_request_session_id_valid: TRUE*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_measurements_case2(&State);
    spdm_unit_test_group_teardown(&State);

    /*Select version based on GET_VERSION/VERSION support*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_measurements_case3(&State);
    spdm_unit_test_group_teardown(&State);

    /*Select version based on GET_VERSION/VERSION support*/
    /*last_spdm_request_session_id_valid: TRUE*/
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_measurements_case4(&State);
    spdm_unit_test_group_teardown(&State);
}
