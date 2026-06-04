/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
    case 0x2:
    case 0x3:
    case 0x4:
    case 0x5:
    case 0x6:
    case 0x7:
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_supported_subcodes_struct_t *resp_struct;
        size_t spdm_response_size;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) +
                             sizeof(spdm_slot_management_supported_subcodes_struct_t);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;
        spdm_response->header.param2 = 0;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
        spdm_response->reserved = 0;

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->resp_length =
            sizeof(spdm_slot_management_supported_subcodes_struct_t);
        resp_struct->sub_code_bitmap[0] =
            (uint8_t)((1 << SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES) |
                      (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO) |
                      (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS) |
                      (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x2: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_error_response_t);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_UNSUPPORTED_REQUEST;
        spdm_response->header.param2 = SPDM_SLOT_MANAGEMENT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        /* GetBankInfo: two BankElements. */
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_bank_info_struct_t *resp_struct;
        spdm_slot_management_bank_element_struct_t *element;
        size_t spdm_response_size;
        size_t transport_header_size;
        size_t resp_struct_size;

        resp_struct_size = sizeof(spdm_slot_management_bank_info_struct_t) +
                           2 * sizeof(spdm_slot_management_bank_element_struct_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) + resp_struct_size;

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->resp_length = (uint16_t)resp_struct_size;
        resp_struct->num_bank_elements = 2;
        element = (void *)((uint8_t *)resp_struct +
                           sizeof(spdm_slot_management_bank_info_struct_t));
        element[0].element_length = SPDM_SLOT_MANAGEMENT_BANK_ELEMENT_LENGTH;
        element[0].bank_id = 0;
        element[0].slot_mask = 0x01;
        element[1].element_length = SPDM_SLOT_MANAGEMENT_BANK_ELEMENT_LENGTH;
        element[1].bank_id = 1;
        element[1].slot_mask = 0x01;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        /* GetBankDetails: one SlotElement. The PQC fields deliberately use non-uniform lengths
         * (PqcAsymAlgoCapabilities = 4 bytes, CurrentPqcAsymAlgo = 4 bytes,
         * AvailablePqcAsymAlgo = 8 bytes) so the test exercises a Requester that does not assume
         * the Responder uses a 4-byte field. */
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_bank_details_struct_t *resp_struct;
        spdm_slot_management_slot_element_struct_t *slot_element;
        uint8_t *ptr;
        size_t spdm_response_size;
        size_t transport_header_size;
        size_t resp_struct_size;
        uint32_t hash_size;
        const uint8_t available_pqc_len = 8;

        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        resp_struct_size = sizeof(spdm_slot_management_bank_details_struct_t) +
                           (sizeof(uint8_t) + sizeof(uint32_t)) +
                           (sizeof(uint8_t) + sizeof(uint32_t)) +
                           (sizeof(uint8_t) + available_pqc_len) + 4 +
                           (sizeof(spdm_slot_management_slot_element_struct_t) + hash_size);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) + resp_struct_size;

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->resp_length = (uint16_t)resp_struct_size;
        resp_struct->bank_id = 0;
        resp_struct->num_slot_elements = 1;
        resp_struct->bank_attributes = SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED;
        resp_struct->current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;

        ptr = (uint8_t *)resp_struct + sizeof(spdm_slot_management_bank_details_struct_t);
        /* PqcAsymAlgoCapabilities: length byte 4, value ML_DSA_44 (a non-zero capability). */
        *ptr = sizeof(uint32_t);
        libspdm_write_uint32(ptr + sizeof(uint8_t), SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44);
        ptr += sizeof(uint8_t) + sizeof(uint32_t);
        /* CurrentPqcAsymAlgo: length byte 4, value 0 (this Bank uses a traditional algorithm). */
        *ptr = sizeof(uint32_t);
        ptr += sizeof(uint8_t) + sizeof(uint32_t);
        /* AvailablePqcAsymAlgo: length byte 8, value 0 (8-byte field to probe robustness). */
        *ptr = available_pqc_len;
        ptr += sizeof(uint8_t) + available_pqc_len;
        ptr += 4;
        slot_element = (void *)ptr;
        slot_element->element_length =
            (uint16_t)(sizeof(spdm_slot_management_slot_element_struct_t) + hash_size);
        slot_element->slot_id = 0;
        slot_element->slot_attributes = SPDM_SLOT_MANAGEMENT_SLOT_ATTRIBUTE_PROVISIONED;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        /* GetCertificateChain: a 0x100-byte certificate chain. */
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
        size_t spdm_response_size;
        size_t transport_header_size;
        const uint32_t cc_length = 0x100;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) +
                             sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
                             cc_length;

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->cc_length = cc_length;
        libspdm_set_mem((uint8_t *)resp_struct +
                        sizeof(spdm_slot_management_get_certificate_chain_struct_t),
                        cc_length, (uint8_t)(0xaa));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6:
    case 0x7: {
        /* ManageBank (0x6) / ManageSlot (0x7): SLOT_MANAGEMENT_RESP with no response
         * structure (MgmtStructOffset = 0). */
        spdm_slot_management_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t sub_code;

        sub_code = (spdm_test_context->case_id == 0x6) ?
                   SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK :
                   SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = sub_code;
        spdm_response->mgmt_struct_offset = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        /* GetCSR: SLOT_MANAGEMENT_RESP with a CSR response structure (0x80-byte CSR). */
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_csr_struct_t *resp_struct;
        size_t spdm_response_size;
        size_t transport_header_size;
        const uint32_t csr_length = 0x80;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) +
                             sizeof(spdm_slot_management_csr_struct_t) + csr_length;

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->csr_length = csr_length;
        libspdm_set_mem((uint8_t *)resp_struct + sizeof(spdm_slot_management_csr_struct_t),
                        csr_length, (uint8_t)(0xbb));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        /* SetCertificate: SLOT_MANAGEMENT_RESP with no response structure. */
        spdm_slot_management_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE;
        spdm_response->mgmt_struct_offset = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        /* GetCertificateChain with a malformed MgmtStructOffset that points past the end of the
         * response. The Requester must reject this rather than read out of bounds. */
        spdm_slot_management_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
        /* Offset points beyond the actual response size. */
        spdm_response->mgmt_struct_offset = (uint16_t)(spdm_response_size + 0x100);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        /* GetCertificateChain returning a 0x100-byte chain, used to exercise the caller's
         * too-small destination buffer (BUFFER_TOO_SMALL). */
        spdm_slot_management_response_t *spdm_response;
        spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
        size_t spdm_response_size;
        size_t transport_header_size;
        const uint32_t cc_length = 0x100;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_slot_management_response_t) +
                             sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
                             cc_length;

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
        spdm_response->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
        spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);

        resp_struct = (void *)((uint8_t *)spdm_response +
                               sizeof(spdm_slot_management_response_t));
        resp_struct->cc_length = cc_length;
        libspdm_set_mem((uint8_t *)resp_struct +
                        sizeof(spdm_slot_management_get_certificate_chain_struct_t),
                        cc_length, (uint8_t)(0xaa));

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
 * Test 1: Successful SLOT_MANAGEMENT SupportedSubCodes exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS and the four required SubCode bits set.
 **/
static void req_slot_management_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code_bitmap[8];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    libspdm_zero_mem(sub_code_bitmap, sizeof(sub_code_bitmap));
    status = libspdm_slot_management_get_supported_subcodes(spdm_context, NULL, sub_code_bitmap);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(sub_code_bitmap[0] & 0x0F, 0x0F);
}

/**
 * Test 2: Responder returns ERROR(UnsupportedRequest).
 * Expected Behavior: an error return code (not SUCCESS).
 **/
static void req_slot_management_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code_bitmap[8];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    libspdm_zero_mem(sub_code_bitmap, sizeof(sub_code_bitmap));
    status = libspdm_slot_management_get_supported_subcodes(spdm_context, NULL, sub_code_bitmap);

    assert_int_not_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 3: Successful SLOT_MANAGEMENT GetBankInfo exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS and two BankElements returned.
 **/
static void req_slot_management_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_slot_management_bank_element_struct_t bank_elements[8];
    uint8_t num_bank_elements;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    num_bank_elements = 8;
    status = libspdm_slot_management_get_bank_info(spdm_context, NULL,
                                                   &num_bank_elements, bank_elements);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(num_bank_elements, 2);
    assert_int_equal(bank_elements[0].bank_id, 0);
    assert_int_equal(bank_elements[1].bank_id, 1);
}

/**
 * Test 4: Successful SLOT_MANAGEMENT GetBankDetails exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS and one SlotElement reported for Bank 0.
 **/
static void req_slot_management_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t bank_attributes;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint32_t available_pqc_asym_algo;
    uint16_t num_slot_elements;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    num_slot_elements = 0;
    bank_attributes = 0;
    current_asym_algo = 0;
    pqc_asym_algo_capabilities = 0;
    current_pqc_asym_algo = 0xFFFFFFFF;
    available_pqc_asym_algo = 0xFFFFFFFF;
    status = libspdm_slot_management_get_bank_details(
        spdm_context, NULL, 0, &bank_attributes, NULL,
        &current_asym_algo, NULL, &pqc_asym_algo_capabilities, &current_pqc_asym_algo,
        &available_pqc_asym_algo, &num_slot_elements, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(num_slot_elements, 1);
    assert_int_equal(bank_attributes & SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED,
                     SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED);
    assert_int_equal(current_asym_algo, SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256);
    /* PqcAsymAlgoCapabilities was reported (4-byte field) as ML_DSA_44. */
    assert_int_equal(pqc_asym_algo_capabilities, SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44);
    /* This Bank uses a traditional algorithm, so CurrentPqcAsymAlgo is 0. The Responder reported
     * AvailablePqcAsymAlgo with an 8-byte field whose value is 0; the Requester must decode it
     * without assuming a 4-byte field. */
    assert_int_equal(current_pqc_asym_algo, 0);
    assert_int_equal(available_pqc_asym_algo, 0);
}

/**
 * Test 5: Successful SLOT_MANAGEMENT GetCertificateChain exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS and the certificate chain returned.
 **/
static void req_slot_management_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[0x200];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_slot_management_get_certificate_chain(
        spdm_context, NULL, 0, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(cert_chain_size, 0x100);
}

/**
 * Test 6: Successful SLOT_MANAGEMENT ManageBank exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS.
 **/
static void req_slot_management_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    status = libspdm_slot_management_manage_bank(
        spdm_context, NULL, 0,
        SPDM_SLOT_MANAGEMENT_MANAGE_BANK_OPERATION_CONFIG_ALGO,
        SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 7: Successful SLOT_MANAGEMENT ManageSlot exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS.
 **/
static void req_slot_management_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    status = libspdm_slot_management_manage_slot(
        spdm_context, NULL, 0, 0,
        SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 8: Successful SLOT_MANAGEMENT GetCSR exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS and the CSR returned.
 **/
static void req_slot_management_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[0x200];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    csr_len = sizeof(csr);
    status = libspdm_slot_management_get_csr(
        spdm_context, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, csr, &csr_len);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, 0x80);
}

/**
 * Test 9: Successful SLOT_MANAGEMENT SetCertificate exchange.
 * Expected Behavior: LIBSPDM_STATUS_SUCCESS.
 **/
static void req_slot_management_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[0x100];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    libspdm_set_mem(cert_chain, sizeof(cert_chain), (uint8_t)(0xcc));
    /* Single-key connection: KeyPairID and CertModel shall be 0. */
    status = libspdm_slot_management_set_certificate(
        spdm_context, NULL, 0, 0, 0, SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE,
        cert_chain, sizeof(cert_chain));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 10: SLOT_MANAGEMENT GetCertificateChain response with a malformed MgmtStructOffset that
 * points past the end of the response.
 * Expected Behavior: the Requester rejects the response (not LIBSPDM_STATUS_SUCCESS) rather than
 * reading out of bounds.
 **/
static void req_slot_management_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[0x200];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_slot_management_get_certificate_chain(
        spdm_context, NULL, 0, 0, &cert_chain_size, cert_chain);
    assert_int_not_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 11: SLOT_MANAGEMENT GetCertificateChain where the caller's destination buffer is too
 * small for the returned certificate chain.
 * Expected Behavior: the Requester returns LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void req_slot_management_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[0x10];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* The response carries a 0x100-byte chain, larger than this 0x10-byte buffer. */
    cert_chain_size = sizeof(cert_chain);
    status = libspdm_slot_management_get_certificate_chain(
        spdm_context, NULL, 0, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

int libspdm_req_slot_management_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_slot_management_case1),
        cmocka_unit_test(req_slot_management_case2),
        cmocka_unit_test(req_slot_management_case3),
        cmocka_unit_test(req_slot_management_case4),
        cmocka_unit_test(req_slot_management_case5),
        cmocka_unit_test(req_slot_management_case6),
        cmocka_unit_test(req_slot_management_case7),
        cmocka_unit_test(req_slot_management_case8),
        cmocka_unit_test(req_slot_management_case9),
        cmocka_unit_test(req_slot_management_case10),
        cmocka_unit_test(req_slot_management_case11),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */
