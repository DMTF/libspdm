/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

/**
 * Test 1: Successful response to set key pair info with key pair id 4
 * Expected Behavior: get a RETURN_SUCCESS return code, and correct response message size and fields
 **/
void libspdm_test_responder_set_key_pair_info_ack_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    uint8_t key_pair_id;
    size_t set_key_pair_info_request_size;
    spdm_set_key_pair_info_request_t *set_key_pair_info_request;
    uint8_t *ptr;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;

    set_key_pair_info_request = malloc(sizeof(spdm_set_key_pair_info_request_t) +
                                       sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) +
                                       sizeof(uint8_t));

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    spdm_context->local_context.total_key_pairs = 16;
    key_pair_id = 4;

    response_size = sizeof(response);

    /*change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);

    /*erase: erase the keyusage and asymalgo*/
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);

    /*generate: generate a new key pair*/
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    ptr = (uint8_t*)(set_key_pair_info_request + 1);
    ptr += sizeof(uint8_t);

    libspdm_write_uint16(ptr, desired_key_usage);
    ptr += sizeof(uint16_t);

    libspdm_write_uint32(ptr, desired_asym_algo);
    ptr += sizeof(uint32_t);

    *ptr = desired_assoc_cert_slot_mask;

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);
    free(set_key_pair_info_request);
}

/**
 * Test 2: Successful response to set key pair info with key pair id 4: need reset
 * Expected Behavior: get a RETURN_SUCCESS return code, and correct response message size and fields
 **/
void libspdm_test_responder_set_key_pair_info_ack_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    uint8_t key_pair_id;
    size_t set_key_pair_info_request_size;
    spdm_set_key_pair_info_request_t *set_key_pair_info_request;
    uint8_t *ptr;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;

    set_key_pair_info_request = malloc(sizeof(spdm_set_key_pair_info_request_t) +
                                       sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) +
                                       sizeof(uint8_t));

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    spdm_context->local_context.total_key_pairs = 16;
    key_pair_id = 4;

    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    response_size = sizeof(response);

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, change: remove an association with slot*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);

    /*Before reset, erase: erase the keyusage and asymalgo*/
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, erase: erase the keyusage and asymalgo*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);


    /*Before reset, generate: generate a new key pair*/
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    ptr = (uint8_t*)(set_key_pair_info_request + 1);
    ptr += sizeof(uint8_t);

    libspdm_write_uint16(ptr, desired_key_usage);
    ptr += sizeof(uint16_t);

    libspdm_write_uint32(ptr, desired_asym_algo);
    ptr += sizeof(uint32_t);

    *ptr = desired_assoc_cert_slot_mask;

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, generate: generate a new key pair*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_SET_KEY_PAIR_INFO_ACK);
    free(set_key_pair_info_request);
}

/**
 * Test 2: The collection of multiple sub-cases.
 **/
void libspdm_test_responder_set_key_pair_info_ack_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    uint8_t key_pair_id;
    size_t set_key_pair_info_request_size;
    spdm_set_key_pair_info_request_t *set_key_pair_info_request;
    uint8_t *ptr;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;

    uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];
    set_key_pair_info_request = (spdm_set_key_pair_info_request_t *)temp_buf;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    spdm_context->local_context.total_key_pairs = 16;
    key_pair_id = 4;

    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /* Sub Case 1: If KeyPairErase is set, all fields after the KeyPairID field in this request should not exist. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    ptr = (uint8_t*)(set_key_pair_info_request + 1);
    ptr += sizeof(uint8_t);

    libspdm_write_uint16(ptr, desired_key_usage);
    ptr += sizeof(uint16_t);

    libspdm_write_uint32(ptr, desired_asym_algo);
    ptr += sizeof(uint32_t);

    *ptr = desired_assoc_cert_slot_mask;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_OPERATION_FAILED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Sub Case 2: When GenerateKeyPair is set, the fields of DesiredKeyUsage, DesiredAsymAlgo and DesiredAssocCertSlotMask should exist. */
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Sub Case 3: key_pair_id = 0 */
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /* Sub Case 4: DesiredAsymAlgo must not have multiple bits set. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256 |
                        SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = key_pair_id;

    ptr = (uint8_t*)(set_key_pair_info_request + 1);
    ptr += sizeof(uint8_t);

    libspdm_write_uint16(ptr, desired_key_usage);
    ptr += sizeof(uint16_t);

    libspdm_write_uint32(ptr, desired_asym_algo);
    ptr += sizeof(uint32_t);

    *ptr = desired_assoc_cert_slot_mask;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    set_key_pair_info_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    set_key_pair_info_request->header.param2 = 0;
    set_key_pair_info_request->key_pair_id = 0x1;

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_responder_set_key_pair_info_ack_test_main(void)
{
    const struct CMUnitTest spdm_responder_set_key_pair_info_ack_tests[] = {
        /* Success Case to set key pair info*/
        cmocka_unit_test(libspdm_test_responder_set_key_pair_info_ack_case1),
        /* Success Case to set key pair info with reset*/
        cmocka_unit_test(libspdm_test_responder_set_key_pair_info_ack_case2),
        /* The collection of multiple sub-cases.*/
        cmocka_unit_test(libspdm_test_responder_set_key_pair_info_ack_case3),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };
    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_responder_set_key_pair_info_ack_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/
