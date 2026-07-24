/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

/**
 * Test 1: Successful response to set key pair info with key pair id 4
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, and correct response message size and fields
 **/
static void rsp_set_key_pair_info_ack_case1(void **state)
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
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

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
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);

    /*erase: erase the keyusage and asymalgo*/
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    set_key_pair_info_request_size = sizeof(spdm_set_key_pair_info_request_t);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);

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
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);
    free(set_key_pair_info_request);
}

/**
 * Test 2: Can be populated with new test.
 **/
static void rsp_set_key_pair_info_ack_case2(void **state)
{
}

/**
 * Test 3: The collection of multiple sub-cases.
 **/
static void rsp_set_key_pair_info_ack_case3(void **state)
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
    uint8_t desired_pqc_asym_algo_len;
    uint32_t desired_pqc_asym_algo;

    uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];
    set_key_pair_info_request = (spdm_set_key_pair_info_request_t *)temp_buf;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    key_pair_id = 4;

    /*set responder need reset, spdm 1.4 */
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_RESET_CAP;

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /* Sub Case 1: If KeyPairErase is set, all fields after the KeyPairID field in this request should not exist. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    desired_pqc_asym_algo_len = sizeof(desired_pqc_asym_algo);
    desired_pqc_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t) + sizeof(uint32_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    ptr += sizeof(uint8_t);

    *ptr = desired_pqc_asym_algo_len;
    ptr += sizeof(uint8_t);

    libspdm_write_uint32(ptr, desired_pqc_asym_algo);

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_OPERATION_FAILED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Sub Case 2: When GenerateKeyPair is set, the fields of DesiredKeyUsage, DesiredAsymAlgo and DesiredAssocCertSlotMask should exist. */
    set_key_pair_info_request_size = sizeof(spdm_set_key_pair_info_request_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Sub Case 3: key_pair_id = 0 */
    set_key_pair_info_request_size = sizeof(spdm_set_key_pair_info_request_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /* Sub Case 4: DesiredAsymAlgo must not have multiple bits set. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256 |
                        SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    desired_pqc_asym_algo_len = sizeof(desired_pqc_asym_algo);
    desired_pqc_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t) + sizeof(uint32_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    ptr += sizeof(uint8_t);

    *ptr = desired_pqc_asym_algo_len;
    ptr += sizeof(uint8_t);

    libspdm_write_uint32(ptr, desired_pqc_asym_algo);

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /* Sub Case 5: DesiredPqcAsymAlgo selects a bit outside PqcAsymAlgoCapabilities. Per
     * DSP0274 Table 115 this is the same class of malformed request as an out-of-capability
     * DesiredAsymAlgo, so the Responder shall answer with InvalidRequest (not
     * UnsupportedRequest). The sample HAL supports ML-DSA but not SLH-DSA for this key pair. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = 0;
    desired_pqc_asym_algo_len = sizeof(desired_pqc_asym_algo);
    desired_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_128S;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t) + sizeof(uint32_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    ptr += sizeof(uint8_t);

    *ptr = desired_pqc_asym_algo_len;
    ptr += sizeof(uint8_t);

    libspdm_write_uint32(ptr, desired_pqc_asym_algo);

    response_size = sizeof(response);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 4: Successful response to set key pair info with key pair id 4: need reset, spdm 1.4
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, and correct response message size and fields
 **/
static void rsp_set_key_pair_info_ack_case4(void **state)
{
    /* reference case 2 */
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
    uint8_t desired_pqc_asym_algo_len;
    uint32_t desired_pqc_asym_algo;

    set_key_pair_info_request = malloc(sizeof(spdm_set_key_pair_info_request_t) +
                                       sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) +
                                       sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t));

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags = 0; /* clear flags */
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    key_pair_id = 4;

    /*set responder need reset, spdm 1.4 */
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_RESET_CAP;

    response_size = sizeof(response);

    /*Before reset, change: remove an association with slot*/
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, change: remove an association with slot*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);

    /*Before reset, erase: erase the keyusage and asymalgo*/
    set_key_pair_info_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    set_key_pair_info_request_size = sizeof(spdm_set_key_pair_info_request_t);
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, erase: erase the keyusage and asymalgo*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);


    /*Before reset, generate: generate a new key pair*/
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    desired_pqc_asym_algo_len = sizeof(desired_pqc_asym_algo);
    desired_pqc_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0x08;
    set_key_pair_info_request_size =
        sizeof(spdm_set_key_pair_info_request_t) +
        sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(uint8_t) + sizeof(uint32_t);

    libspdm_zero_mem(set_key_pair_info_request, set_key_pair_info_request_size);
    set_key_pair_info_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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
    ptr += sizeof(uint8_t);

    *ptr = desired_pqc_asym_algo_len;
    ptr += sizeof(uint8_t);

    libspdm_write_uint32(ptr, desired_pqc_asym_algo);

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*After reset, generate: generate a new key pair*/
    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, set_key_pair_info_request_size,
        set_key_pair_info_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);
    free(set_key_pair_info_request);
}

/**
 * Test 5: SET_KEY_PAIR_RESET replay where two requests differ only in DesiredPqcAsymAlgo.
 * This exercises the device_secret HAL (libspdm_write_key_pair_info) directly, since the
 * cached-request match that decides whether a post-reset replay is applied lives in the HAL.
 * Expected Behavior: a replay that changes only the PQC algorithm shall not be accepted as the
 * cached request; the correct PQC algorithm shall be applied only once the matching request is
 * replayed.
 **/
static void rsp_set_key_pair_info_ack_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t key_pair_id;
    bool need_reset;
    bool result;
    uint8_t total_key_pairs;
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint8_t assoc_cert_slot_mask;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    key_pair_id = 4;

    /* First request: GenerateKeyPair with ML-DSA-44. With need_reset = true the HAL caches the
     * request and reports that a reset is still required (not yet applied). */
    need_reset = true;
    result = libspdm_write_key_pair_info(
        spdm_context, key_pair_id, SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION,
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE, 0,
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44, 0, &need_reset);
    assert_true(result);
    assert_true(need_reset);

    /* Post-reset replay that differs only in DesiredPqcAsymAlgo (ML-DSA-65). This must NOT be
     * treated as the cached request: the HAL caches the new request and again reports that a
     * reset is required, rather than applying the stale ML-DSA-44 value. */
    need_reset = true;
    result = libspdm_write_key_pair_info(
        spdm_context, key_pair_id, SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION,
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE, 0,
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65, 0, &need_reset);
    assert_true(result);
    assert_true(need_reset);

    /* Replay the ML-DSA-65 request identically: now it matches the cached request and is
     * applied (need_reset cleared). */
    need_reset = true;
    result = libspdm_write_key_pair_info(
        spdm_context, key_pair_id, SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION,
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE, 0,
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65, 0, &need_reset);
    assert_true(result);
    assert_false(need_reset);

    /* The applied PQC algorithm shall be ML-DSA-65 (the replayed value), not ML-DSA-44. */
    assert_true(libspdm_read_key_pair_info(
                    spdm_context, key_pair_id, &total_key_pairs, &capabilities,
                    &key_usage_capabilities, &current_key_usage, &asym_algo_capabilities,
                    &current_asym_algo, &pqc_asym_algo_capabilities, &current_pqc_asym_algo,
                    &assoc_cert_slot_mask, NULL, NULL));
    assert_int_equal(current_pqc_asym_algo, SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65);
}

/**
 * Test 7: A SET_KEY_PAIR_INFO that associates a certificate slot with a KeyPairID whose current
 * asymmetric algorithm matches a DIFFERENT KeyPairID already associated with that same slot shall
 * be rejected. Within one connection a slot resolves to a single KeyPairID for the negotiated
 * algorithm (DIGESTS returns one KeyPairID per slot), so two same-algorithm KeyPairIDs must not
 * both claim one slot. libspdm rejects this with ERROR=OperationFailed. (DSP0274 does not define an
 * error code for this conflict; OperationFailed is a libspdm policy, consistent with the other
 * association-conflict cases in the SET_KEY_PAIR_INFO error-handling clause.)
 * Expected Behavior: ERROR with ErrorCode=OperationFailed.
 **/
static void rsp_set_key_pair_info_ack_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    uint8_t key_pair_id;
    uint8_t other_key_pair_id;
    uint8_t victim_key_pair_id;
    uint8_t total_key_pairs;
    uint8_t collide_slot;
    bool found_pair;
    size_t set_key_pair_info_request_size;
    spdm_set_key_pair_info_request_t *set_key_pair_info_request;
    uint8_t *ptr;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;

    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint8_t assoc_cert_slot_mask;

    uint32_t victim_asym_algo;
    uint32_t victim_pqc_asym_algo;
    uint8_t victim_assoc_cert_slot_mask;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    /* Discover a KeyPairID (victim) that owns at least one slot, and another KeyPairID of the SAME
     * current algorithm. The sample provisions a secondary key pair per algorithm, so such a pair
     * exists; discovery keeps the test independent of the compiled algorithm set. */
    key_pair_id = 0;
    total_key_pairs = 0;
    found_pair = false;
    victim_key_pair_id = 0;
    other_key_pair_id = 0;
    collide_slot = 0;
    victim_assoc_cert_slot_mask = 0;

    (void)libspdm_read_key_pair_info(
        spdm_context, 1, &total_key_pairs, &capabilities, &key_usage_capabilities,
        &current_key_usage, &asym_algo_capabilities, &current_asym_algo,
        &pqc_asym_algo_capabilities, &current_pqc_asym_algo, &assoc_cert_slot_mask, NULL, NULL);

    for (victim_key_pair_id = 1;
         (victim_key_pair_id <= total_key_pairs) && !found_pair;
         victim_key_pair_id++) {
        if (!libspdm_read_key_pair_info(
                spdm_context, victim_key_pair_id, &total_key_pairs, &capabilities,
                &key_usage_capabilities, &current_key_usage, &asym_algo_capabilities,
                &victim_asym_algo, &pqc_asym_algo_capabilities, &victim_pqc_asym_algo,
                &victim_assoc_cert_slot_mask, NULL, NULL)) {
            continue;
        }
        if (victim_assoc_cert_slot_mask == 0) {
            continue;
        }
        for (other_key_pair_id = 1; other_key_pair_id <= total_key_pairs; other_key_pair_id++) {
            if (other_key_pair_id == victim_key_pair_id) {
                continue;
            }
            if (!libspdm_read_key_pair_info(
                    spdm_context, other_key_pair_id, &total_key_pairs, &capabilities,
                    &key_usage_capabilities, &current_key_usage, &asym_algo_capabilities,
                    &current_asym_algo, &pqc_asym_algo_capabilities, &current_pqc_asym_algo,
                    &assoc_cert_slot_mask, NULL, NULL)) {
                continue;
            }
            if ((current_asym_algo == victim_asym_algo) &&
                (current_pqc_asym_algo == victim_pqc_asym_algo)) {
                uint8_t slot_index;
                for (slot_index = 0; slot_index < SPDM_MAX_SLOT_COUNT; slot_index++) {
                    if ((victim_assoc_cert_slot_mask & (1 << slot_index)) != 0) {
                        collide_slot = slot_index;
                        found_pair = true;
                        break;
                    }
                }
            }
            if (found_pair) {
                break;
            }
        }
    }
    victim_key_pair_id--;

    /* If the build has no two key pairs of the same algorithm, there is nothing to collide. */
    if (!found_pair) {
        return;
    }

    key_pair_id = other_key_pair_id;

    set_key_pair_info_request = malloc(sizeof(spdm_set_key_pair_info_request_t) +
                                       sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) +
                                       sizeof(uint8_t));

    /* ParameterChange on other_key_pair_id: associate the slot already owned by victim_key_pair_id
     * (same algorithm). Keep the algorithm unchanged (DesiredAsymAlgo = 0). */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = (uint8_t)(1 << collide_slot);
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
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_OPERATION_FAILED);
    assert_int_equal(spdm_response->header.param2, 0);

    free(set_key_pair_info_request);
}

/**
 * Test 6: After a successful no-reset SET_KEY_PAIR_INFO that changes a key pair's certificate slot
 * association, the connection-level context (local_key_pair_id and local_key_usage_bit_mask, which
 * DIGESTS reports per slot) shall be kept coherent with the new association: a newly associated
 * slot shall reflect this KeyPairID and its current key usage, and a slot removed from the
 * association shall be cleared.
 * Expected Behavior: local_key_pair_id[slot] and local_key_usage_bit_mask[slot] track the change.
 **/
static void rsp_set_key_pair_info_ack_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    uint8_t key_pair_id;
    uint8_t slot_id;
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
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    key_pair_id = 4;
    /* Slot 2 is never provisioned in the sample (only slots 0/1 for primary key pairs and slot 4
     * for the secondaries), so associating it never collides with a same-algorithm key pair. This
     * keeps the case independent of which algorithm key_pair_id 4 maps to in the build. */
    slot_id = 2;

    /* Seed the per-slot context with sentinels that differ from what a coherent sync must write,
     * so the assertions below are meaningful. */
    spdm_context->local_context.local_key_pair_id[slot_id] = 0xEE;
    spdm_context->local_context.local_key_usage_bit_mask[slot_id] = 0;

    response_size = sizeof(response);

    /* Step 1: ParameterChange associating the slot with key_pair_id 4 and KeyExUse. Do not change
     * the algorithm (DesiredAsymAlgo = 0). This is a no-reset flow (SPDM 1.3), so it applies at
     * once. */
    desired_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = (uint8_t)(1 << slot_id);
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
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);

    /* The newly associated slot must now report this KeyPairID and its current key usage. */
    assert_int_equal(spdm_context->local_context.local_key_pair_id[slot_id], key_pair_id);
    assert_int_equal(spdm_context->local_context.local_key_usage_bit_mask[slot_id],
                     SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE);

    /* Step 2: ParameterChange removing the slot association (empty mask). */
    desired_key_usage = 0;
    desired_asym_algo = 0;
    desired_assoc_cert_slot_mask = 0x00;

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
    assert_int_equal(response_size, sizeof(spdm_set_key_pair_info_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SET_KEY_PAIR_INFO_ACK);

    /* The removed slot must be cleared, since this KeyPairID owned it in the context. */
    assert_int_equal(spdm_context->local_context.local_key_pair_id[slot_id], 0);
    assert_int_equal(spdm_context->local_context.local_key_usage_bit_mask[slot_id], 0);

    free(set_key_pair_info_request);
}

int libspdm_rsp_set_key_pair_info_ack_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success Case to set key pair info*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case1),
        /* Can be populated with new test*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case2),
        /* The collection of multiple sub-cases.*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case3),
        /* Success Case to set key pair info with reset, spdm 1.4*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case4),
        /* Reset replay differing only in DesiredPqcAsymAlgo*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case5),
        /* Reject same-algorithm slot collision across KeyPairIDs*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case7),
        /* Context (DIGESTS) coherence after a no-reset association change*/
        cmocka_unit_test(rsp_set_key_pair_info_ack_case6),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };
    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/
