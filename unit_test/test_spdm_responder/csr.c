/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP

uint8_t m_csr_opaque_data[8] = "libspdm";

/*ECC 256 req_info(include right req_info attribute)*/
static uint8_t right_req_info[] = {
    0x30, 0x81, 0xBF, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74,
    0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDB, 0xC2, 0xB2, 0xB7,
    0x83, 0x3C, 0xC8, 0x85, 0xE4, 0x3D, 0xE1, 0xF3, 0xBA, 0xE2, 0xF2, 0x90, 0x8E, 0x30, 0x25, 0x14,
    0xE1, 0xF7, 0xA9, 0x82, 0x29, 0xDB, 0x9D, 0x76, 0x2F, 0x80, 0x11, 0x32, 0xEE, 0xAB, 0xE2, 0x68,
    0xD1, 0x22, 0xE7, 0xBD, 0xB4, 0x71, 0x27, 0xC8, 0x79, 0xFB, 0xDC, 0x7C, 0x9E, 0x33, 0xA6, 0x67,
    0xC2, 0x10, 0x47, 0x36, 0x32, 0xC5, 0xA1, 0xAA, 0x6B, 0x2B, 0xAA, 0xC9, 0xA0, 0x18, 0x30, 0x16,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07, 0x31, 0x09, 0x0C, 0x07, 0x74,
    0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};

/*ECC 256 req_info(include wrong req_info attribute, oid is wrong)*/
static uint8_t wrong_req_info[] = {
    0x30, 0x81, 0xBF, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74,
    0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDB, 0xC2, 0xB2, 0xB7,
    0x83, 0x3C, 0xC8, 0x85, 0xE4, 0x3D, 0xE1, 0xF3, 0xBA, 0xE2, 0xF2, 0x90, 0x8E, 0x30, 0x25, 0x14,
    0xE1, 0xF7, 0xA9, 0x82, 0x29, 0xDB, 0x9D, 0x76, 0x2F, 0x80, 0x11, 0x32, 0xEE, 0xAB, 0xE2, 0x68,
    0xD1, 0x22, 0xE7, 0xBD, 0xB4, 0x71, 0x27, 0xC8, 0x79, 0xFB, 0xDC, 0x7C, 0x9E, 0x33, 0xA6, 0x67,
    0xC2, 0x10, 0x47, 0x36, 0x32, 0xC5, 0xA1, 0xAA, 0x6B, 0x2B, 0xAA, 0xC9, 0xA0, 0x18, 0x30, 0x16,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,       0x09, 0x07, 0x31, 0x09, 0x0C, 0x07, 0x74,
    0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};

/*req_info attribute*/
char right_req_info_string[] = {0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33};

/*find destination buffer from source buffer*/
bool libspdm_find_buffer(char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t index;

    if ((src == NULL) || (dst == NULL)) {
        return false;
    }

    if (src_len < dst_len) {
        return false;
    }

    for (index = 0; index < src_len - dst_len; index++) {
        if ((*(src + index) == *dst) &&
            (libspdm_consttime_is_mem_equal(src + index, dst, dst_len) == 0)) {
            return true;
        }
    }

    return false;
}

/*get the cached csr*/
bool libspdm_test_read_cached_csr(uint32_t base_asym_algo, uint8_t **csr_pointer, size_t *csr_len)
{
    bool res;
    char *file;

    if (base_asym_algo == 0) {
        return false;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "test_csr/rsa2048.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "test_csr/rsa3072.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "test_csr/rsa4096.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "test_csr/ecp256.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "test_csr/ecp384.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "test_csr/ecp521.csr";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    res = libspdm_read_input_file(file, (void **)csr_pointer, csr_len);
    return res;
}

/*clan the cached req_info*/
void libspdm_test_clear_cached_req_info(uint32_t base_asym_algo)
{
    char *file;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048_req_info";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072_req_info";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096_req_info";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256_req_info";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384_req_info";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521_req_info";
        break;
    }

    libspdm_write_output_file(file, NULL, 0);
}


/**
 * Test 1: receives a valid GET_CSR request message from Requester
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;


    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = 0;

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 2: Wrong GET_CSR message size (larger than expected)
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;


    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = 0;

    /* Bad request size*/
    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) - 1;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 3: receives a valid GET_CSR request message from Requester with non-null right req_info
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);
    char *csr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       sizeof(right_req_info));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = sizeof(right_req_info);

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(right_req_info),
                     right_req_info, sizeof(right_req_info));

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            sizeof(right_req_info);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    csr = (char *)(spdm_response + 1);
    assert_true(libspdm_find_buffer(csr, spdm_response->csr_length,
                                    right_req_info_string, sizeof(right_req_info_string)));

    free(m_libspdm_get_csr_request);
}

/**
 * Test 4: receives a valid GET_CSR request message from Requester with non-null opaque_data
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       sizeof(m_csr_opaque_data));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = sizeof(m_csr_opaque_data);
    m_libspdm_get_csr_request->requester_info_length = 0;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(m_csr_opaque_data),
                     m_csr_opaque_data, sizeof(m_csr_opaque_data));

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            sizeof(m_csr_opaque_data);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 5: receives a valid GET_CSR request message from Requester with non-null wrong req_info
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       sizeof(wrong_req_info));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = sizeof(wrong_req_info);

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(wrong_req_info),
                     wrong_req_info, sizeof(wrong_req_info));

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            sizeof(wrong_req_info);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 6: receives a valid GET_CSR request message from Requester with need_reset
 * Expected Behavior: the first get_csr: responder return need reset;
 *                    the second get_csr: get the cached valid csr;
 **/
void libspdm_test_responder_csr_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;

    if (!libspdm_test_read_cached_csr(m_libspdm_use_asym_algo, &csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       sizeof(right_req_info));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = sizeof(right_req_info);

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(right_req_info),
                     right_req_info, sizeof(right_req_info));

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            sizeof(right_req_info);

    response_size = sizeof(response);

    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);


    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = sizeof(right_req_info);
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(right_req_info),
                     right_req_info, sizeof(right_req_info));

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR is equal the cached CSR */
    assert_memory_equal(spdm_response + 1, cached_csr, spdm_response->csr_length);

    /*clear cached req_info*/
    libspdm_test_clear_cached_req_info(m_libspdm_use_asym_algo);
    free(m_libspdm_get_csr_request);
}

libspdm_test_context_t m_libspdm_responder_csr_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_csr_test_main(void)
{
    const struct CMUnitTest spdm_responder_csr_tests[] = {
        /* Success Case for csr response  */
        cmocka_unit_test(libspdm_test_responder_csr_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_csr_case2),
        /* Success Case for csr response with non-null right req_info */
        cmocka_unit_test(libspdm_test_responder_csr_case3),
        /* Success Case for csr response with non-null opaque_data */
        cmocka_unit_test(libspdm_test_responder_csr_case4),
        /* Failed Case for csr response with non-null wrong req_info */
        cmocka_unit_test(libspdm_test_responder_csr_case5),
        /* Responder need reset to gen csr*/
        cmocka_unit_test(libspdm_test_responder_csr_case6),
    };

    libspdm_setup_test_context(&m_libspdm_responder_csr_test_context);

    return cmocka_run_group_tests(spdm_responder_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP*/
