/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

libspdm_return_t libspdm_requester_get_key_pair_info_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_key_pair_info_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        spdm_key_pair_info_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        uint8_t total_key_pairs;
        uint8_t key_pair_id;
        uint16_t public_key_info_len;
        uint16_t capabilities;
        uint16_t key_usage_capabilities;
        uint16_t current_key_usage;
        uint32_t asym_algo_capabilities;
        uint32_t current_asym_algo;
        uint8_t assoc_cert_slot_mask;

        uint8_t public_key_info_rsa2048[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                             0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};

        key_pair_id = 1;
        total_key_pairs = 1;
        public_key_info_len = (uint16_t)sizeof(public_key_info_rsa2048);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_key_pair_info_response_t) + public_key_info_len;

        capabilities = SPDM_KEY_PAIR_CAP_GEN_KEY_CAP;
        key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
        current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;

        /*association with slot 1*/
        assoc_cert_slot_mask = 0x02;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_KEY_PAIR_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->total_key_pairs = total_key_pairs;
        spdm_response->key_pair_id = key_pair_id;
        spdm_response->capabilities = capabilities;
        spdm_response->key_usage_capabilities = key_usage_capabilities;
        spdm_response->current_key_usage = current_key_usage;
        spdm_response->asym_algo_capabilities = asym_algo_capabilities;
        spdm_response->current_asym_algo = current_asym_algo;
        spdm_response->public_key_info_len = public_key_info_len;
        spdm_response->assoc_cert_slot_mask = assoc_cert_slot_mask;

        libspdm_copy_mem((void*)(spdm_response + 1), public_key_info_len,
                         public_key_info_rsa2048, public_key_info_len);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Successful response to get key pair info
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code
 **/
void libspdm_test_requester_get_key_pair_info_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t key_pair_id;
    uint8_t associated_slot_id;
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
    associated_slot_id = 1;
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    spdm_context->connection_info.peer_key_pair_id[associated_slot_id] = key_pair_id;
    public_key_info_len = SPDM_MAX_PUBLIC_KEY_INFO_LEN;

    status = libspdm_get_key_pair_info(spdm_context, NULL, key_pair_id, &total_key_pairs,
                                       &capabilities, &key_usage_capabilities, &current_key_usage,
                                       &asym_algo_capabilities, &current_asym_algo,
                                       &assoc_cert_slot_mask, &public_key_info_len,
                                       public_key_info);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(capabilities, SPDM_KEY_PAIR_CAP_GEN_KEY_CAP);
    assert_int_equal(key_usage_capabilities, SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE);
    assert_int_equal(current_key_usage, SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE);
    assert_int_equal(asym_algo_capabilities, SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048);
    assert_int_equal(current_asym_algo, SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048);
}

libspdm_test_context_t m_libspdm_requester_get_key_pair_info_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_key_pair_info_test_send_message,
    libspdm_requester_get_key_pair_info_test_receive_message,
};

int libspdm_requester_get_key_pair_info_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_key_pair_info_tests[] = {
        /* Successful response to get key pair info, key_pair_id is 1*/
        cmocka_unit_test(libspdm_test_requester_get_key_pair_info_case1),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_key_pair_info_test_context);

    return cmocka_run_group_tests(spdm_requester_get_key_pair_info_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/
