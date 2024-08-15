/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

libspdm_return_t libspdm_requester_set_key_pair_info_err_test_send_message(
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

libspdm_return_t libspdm_requester_set_key_pair_info_err_test_receive_message(
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
void libspdm_test_requester_set_key_pair_info_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t key_pair_id;
    uint8_t operation;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    key_pair_id = 1;
    operation = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    desired_key_usage = 0;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0;

    status = libspdm_set_key_pair_info(spdm_context, NULL, key_pair_id,
                                       operation, desired_key_usage, desired_asym_algo,
                                       desired_assoc_cert_slot_mask);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

libspdm_test_context_t m_libspdm_requester_set_key_pair_info_err_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_set_key_pair_info_err_test_send_message,
    libspdm_requester_set_key_pair_info_err_test_receive_message,
};

int libspdm_requester_set_key_pair_info_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_set_key_pair_info_err_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_set_key_pair_info_err_case1),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_set_key_pair_info_err_test_context);

    return cmocka_run_group_tests(spdm_requester_set_key_pair_info_err_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/
