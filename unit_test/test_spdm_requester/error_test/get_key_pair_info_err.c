/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

libspdm_return_t libspdm_requester_get_key_pair_info_error_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_key_pair_info_error_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_key_pair_info_error_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t key_pair_id;
    uint8_t total_key_pairs;
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];

    key_pair_id = 1;
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP;

    public_key_info_len = SPDM_MAX_PUBLIC_KEY_INFO_LEN;

    status = libspdm_get_key_pair_info(spdm_context, NULL, key_pair_id, &total_key_pairs,
                                       &capabilities, &key_usage_capabilities, &current_key_usage,
                                       &asym_algo_capabilities, &current_asym_algo,
                                       &assoc_cert_slot_mask, &public_key_info_len,
                                       public_key_info);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

libspdm_test_context_t m_libspdm_requester_get_key_pair_info_error_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_key_pair_info_error_test_send_message,
    libspdm_requester_get_key_pair_info_error_test_receive_message,
};

int libspdm_requester_get_key_pair_info_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_key_pair_info_error_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_key_pair_info_error_case1),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_key_pair_info_error_test_context);

    return cmocka_run_group_tests(spdm_requester_get_key_pair_info_error_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/
