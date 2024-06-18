/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

spdm_get_measurement_extension_log_request_t m_libspdm_get_measurement_extension_log_request1 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_MEASUREMENT_EXTENSION_LOG, 0, 0 },
    0,
    LIBSPDM_MAX_MEL_BLOCK_LEN
};
size_t m_libspdm_get_measurement_extension_log_request1_size =
    sizeof(m_libspdm_get_measurement_extension_log_request1);

/**
 * Test 1: request the first LIBSPDM_MAX_MEL_BLOCK_LEN bytes of the MEL
 * Expected Behavior: generate a correctly formed MEL message, including its portion_length and remainder_length fields
 **/
void libspdm_test_responder_measurement_extension_log_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurement_extension_log_response_t *spdm_response;
    spdm_measurement_extension_log_dmtf_t *spdm_mel;
    size_t spdm_mel_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.mel_spec =
        m_libspdm_use_mel_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_measurement_extension_log(
        spdm_context, m_libspdm_get_measurement_extension_log_request1_size,
        &m_libspdm_get_measurement_extension_log_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_mel = NULL;
    spdm_mel_len = 0;
    libspdm_measurement_extension_log_collection(
        spdm_context,
        m_libspdm_use_mel_spec,
        m_libspdm_use_measurement_spec,
        m_libspdm_use_measurement_hash_algo,
        (void **)&spdm_mel, &spdm_mel_len);

    assert_int_equal(response_size,
                     sizeof(spdm_measurement_extension_log_response_t) +
                     spdm_mel_len);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENT_EXTENSION_LOG);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->portion_length, spdm_mel_len);
    assert_int_equal(spdm_response->remainder_length, 0);
    assert_memory_equal(spdm_response + 1, spdm_mel, spdm_mel_len);
}

libspdm_test_context_t m_libspdm_responder_measurement_extension_log_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_measurement_extension_log_test_main(void)
{
    const struct CMUnitTest spdm_responder_measurement_extension_log_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_measurement_extension_log_case1),
    };

    libspdm_setup_test_context(&m_libspdm_responder_measurement_extension_log_test_context);

    return cmocka_run_group_tests(spdm_responder_measurement_extension_log_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
