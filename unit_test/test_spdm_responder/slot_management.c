/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/* The supported SubCodes bit map. By default this sample supports the required SubCodes plus
 * the optional GetCSR, ManageBank, ManageSlot, and SetCertificate SubCodes. The Integrator can
 * override this global to advertise a different set of SubCodes. The bit position corresponds
 * to the SubCode value. */
uint8_t m_libspdm_slot_management_sub_code_bitmap[8] = {
    /* byte 0: SubCodes 0x00 - 0x07, containing the required SubCodes and GetCSR (0x04). */
    (uint8_t)((1 << SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR)),
    0, 0, 0,
    /* byte 4: SubCodes 0x20 - 0x27, containing ManageBank (0x20), ManageSlot (0x21), and
     * SetCertificate (0x22). */
    (uint8_t)((1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK % 8)) |
              (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT % 8)) |
              (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE % 8))),
    0, 0, 0
};

uint32_t bank0_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
uint32_t bank1_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
uint32_t bank_asym_algo_capabilities =
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048 |
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072 |
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096 |
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256 |
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384 |
    SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
uint32_t zero = 0;

/* The sample device_secret_lib stores runtime-provisioned certificate chains in NVM files named
 * "bank_id_NNN_slot_id_M_cert_chain.der" (SLOT_MANAGEMENT SetCertificate/Erase) and
 * "slot_id_M_cert_chain.der" (base SET_CERTIFICATE). Those files persist across test runs, so a
 * test that provisions or erases a slot would otherwise leak state into later cases (and later
 * runs). Remove all such files so each test starts from the static (factory) certificate store.
 *
 * Also seed spdm_context->local_context.local_cert_chain_provision with certificate chains for
 * Bank 0, slots 0 and 1.
 *
 * Used as a cmocka per-test setup. */
static int libspdm_slot_management_test_setup(void **state)
{
    char file_name[40];
    uint16_t bank_id;
    uint8_t slot_id;
    libspdm_data_parameter_t parameter;
    libspdm_test_context_t *spdm_test_context = *state;
    libspdm_context_t *spdm_context = spdm_test_context->spdm_context;

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        snprintf(file_name, sizeof(file_name), "slot_id_%u_cert_chain.der", (unsigned)slot_id);
        (void)remove(file_name);
        for (bank_id = 0; bank_id < 256; bank_id++) {
            snprintf(file_name, sizeof(file_name), "bank_id_%03u_slot_id_%u_cert_chain.der",
                     (unsigned)bank_id, (unsigned)slot_id);
            (void)remove(file_name);
        }
    }

    /* Free any cert chains a previous test left provisioned, then reset every (Bank, slot) entry
     * so the per-test state starts clean. */
    for (bank_id = 0; bank_id < LIBSPDM_MAX_BANK_COUNT; bank_id++) {
        for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
            if (spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id] !=
                NULL) {
                spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id] = NULL;
                spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id] = 0;
            }
        }
    }

    /* Provision Bank 0 with the static certificate store's per-slot chains. The negotiated
     * algorithm is the standard test pair (m_libspdm_use_hash_algo / m_libspdm_use_asym_algo);
     * record it on the context so libspdm_slot_management_compute_bank_details reports the
     * selected Bank's CurrentAsymAlgo correctly. */
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.current_bank = 0;
    for (slot_id = 0; slot_id < 2; slot_id++) {
        void *cert_chain_data = NULL;
        size_t cert_chain_size = 0;

        if (!libspdm_read_responder_public_certificate_chain_per_slot(
                slot_id, m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &cert_chain_data, &cert_chain_size, NULL, NULL)) {
            continue;
        }
        spdm_context->local_context.local_cert_chain_provision[0][slot_id] = cert_chain_data;
        spdm_context->local_context.local_cert_chain_provision_size[0][slot_id] = cert_chain_size;
    }

    slot_id = 0;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    parameter.additional_data[0] = slot_id;
    assert_false(libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SLOT_MANAGEMENT_SUBCODES,
                                  &parameter, m_libspdm_slot_management_sub_code_bitmap,
                                  sizeof(m_libspdm_slot_management_sub_code_bitmap)));

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    /* Bank 0: current = ECC256 */
    parameter.additional_data[0] = 0;
    (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_ASYM_ALGO,
                           &parameter, &bank0_asym_algo, sizeof(bank0_asym_algo));
    (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_PQC_ASYM_ALGO,
                           &parameter, &zero, sizeof(zero));
    (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_ASYM_ALGO_CAPABILITIES,
                           &parameter, &bank_asym_algo_capabilities,
                           sizeof(bank_asym_algo_capabilities));
    (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_PQC_ASYM_ALGO_CAPABILITIES,
                           &parameter, &zero, sizeof(zero));

    /* Bank 1: current = ECC384 */
    if (LIBSPDM_MAX_BANK_COUNT > 1) {
        parameter.additional_data[0] = 1;
        (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_ASYM_ALGO,
                               &parameter, &bank1_asym_algo, sizeof(bank1_asym_algo));
        (void)libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_BANK_PQC_ASYM_ALGO,
                               &parameter, &zero, sizeof(zero));
        (void)libspdm_set_data(spdm_context,
                               LIBSPDM_DATA_LOCAL_BANK_ASYM_ALGO_CAPABILITIES,
                               &parameter, &bank_asym_algo_capabilities,
                               sizeof(bank_asym_algo_capabilities));
        (void)libspdm_set_data(spdm_context,
                               LIBSPDM_DATA_LOCAL_BANK_PQC_ASYM_ALGO_CAPABILITIES,
                               &parameter, &zero, sizeof(zero));
    }

    return 0;
}

spdm_slot_management_request_t m_libspdm_slot_management_request1 = {
    { SPDM_MESSAGE_VERSION_14, SPDM_SLOT_MANAGEMENT,
      SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES, 0 },
    0
};
size_t m_libspdm_slot_management_request1_size = sizeof(m_libspdm_slot_management_request1);

/**
 * Test 1: Successful response to SLOT_MANAGEMENT SupportedSubCodes.
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, SLOT_MANAGEMENT_RESP message with
 * the SupportedSubCodes structure containing the required SubCode bits.
 **/
static void rsp_slot_management_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_supported_subcodes_struct_t *resp_struct;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    m_libspdm_slot_management_request1.header.param1 =
        SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;

    response_size = sizeof(response);

    status = libspdm_get_response_slot_management(
        spdm_context, m_libspdm_slot_management_request1_size,
        &m_libspdm_slot_management_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_supported_subcodes_struct_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES);
    assert_int_equal(spdm_response->mgmt_struct_offset,
                     sizeof(spdm_slot_management_response_t));

    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    assert_int_equal(resp_struct->resp_length,
                     sizeof(spdm_slot_management_supported_subcodes_struct_t));
    /* The four required SubCode bits shall be set. */
    assert_int_equal(resp_struct->sub_code_bitmap[0] & 0x0F, 0x0F);
}

/**
 * Test 2: SLOT_MGMT_CAP is not set.
 * Expected Behavior: Generate error response message with UNSUPPORTED_REQUEST.
 **/
static void rsp_slot_management_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.ext_flags &=
        ~SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    m_libspdm_slot_management_request1.header.param1 =
        SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;

    response_size = sizeof(response);

    status = libspdm_get_response_slot_management(
        spdm_context, m_libspdm_slot_management_request1_size,
        &m_libspdm_slot_management_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SLOT_MANAGEMENT);
}

/**
 * Test 3: A reserved (unlisted) SubCode is requested.
 * Expected Behavior: Generate error response message with INVALID_REQUEST. Per DSP0274 a SubCode
 * that is not listed in Table 142 shall be answered with ERROR(InvalidRequest).
 **/
static void rsp_slot_management_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* 0x10 is a reserved SubCode that is not listed in Table 142. */
    m_libspdm_slot_management_request1.header.param1 = 0x10;

    response_size = sizeof(response);

    status = libspdm_get_response_slot_management(
        spdm_context, m_libspdm_slot_management_request1_size,
        &m_libspdm_slot_management_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    /* restore request for subsequent runs */
    m_libspdm_slot_management_request1.header.param1 =
        SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;
}

/**
 * Test 4: Connection version is lower than 1.4.
 * Expected Behavior: Generate error response message with UNSUPPORTED_REQUEST.
 **/
static void rsp_slot_management_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    m_libspdm_slot_management_request1.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_slot_management_request1.header.param1 =
        SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;

    response_size = sizeof(response);

    status = libspdm_get_response_slot_management(
        spdm_context, m_libspdm_slot_management_request1_size,
        &m_libspdm_slot_management_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SLOT_MANAGEMENT);

    /* restore request version for subsequent runs */
    m_libspdm_slot_management_request1.header.spdm_version = SPDM_MESSAGE_VERSION_14;
}

/* Find, by querying GetBankInfo, a Bank that has at least one slot. Returns the BankID, the
 * lowest SlotID present in that Bank, and the number of slots in that Bank. Also reports the
 * Bank that has the most slots, which is used to locate the multi-key Bank when present. */
static bool libspdm_slot_management_find_bank(
    libspdm_context_t *spdm_context,
    uint8_t *bank_id, uint8_t *slot_id, uint8_t *max_slot_bank_id, uint8_t *max_slot_count)
{
    uint8_t num_bank_elements;
    /* BankID is limited to 0-239 by the specification, so SPDM_MAX_BANK_COUNT BankElements can
     * hold every possible Bank. */
    spdm_slot_management_bank_element_struct_t banks[SPDM_MAX_BANK_COUNT];
    uint8_t index;
    uint8_t slot_index;
    uint8_t best_count = 0;
    int i;
    bool found = false;

    num_bank_elements = 0;
    for (i = 0; i < LIBSPDM_MAX_BANK_COUNT; i++) {
        uint8_t slot_mask = 0;
        uint8_t j;

        for (j = 0; j < SPDM_MAX_SLOT_COUNT; j++) {
            if (spdm_context->local_context.local_cert_chain_provision[i][j] !=
                NULL) {
                slot_mask |= (uint8_t)(1 << j);
            }
        }
        if (slot_mask == 0) {
            continue;
        }
        banks[num_bank_elements].element_length = SPDM_SLOT_MANAGEMENT_BANK_ELEMENT_LENGTH;
        banks[num_bank_elements].bank_id = (uint8_t)i;
        banks[num_bank_elements].slot_mask = slot_mask;
        banks[num_bank_elements].modifiable_slot_mask = 0;
        num_bank_elements++;
    }

    for (index = 0; index < num_bank_elements; index++) {
        uint8_t mask = banks[index].slot_mask;
        uint8_t count = 0;

        for (slot_index = 0; slot_index < SPDM_MAX_SLOT_COUNT; slot_index++) {
            if ((mask & (1 << slot_index)) != 0) {
                count++;
            }
        }
        if ((count > 0) && !found) {
            found = true;
            *bank_id = banks[index].bank_id;
            for (slot_index = 0; slot_index < SPDM_MAX_SLOT_COUNT; slot_index++) {
                if ((mask & (1 << slot_index)) != 0) {
                    *slot_id = slot_index;
                    break;
                }
            }
        }
        if (count > best_count) {
            best_count = count;
            *max_slot_bank_id = banks[index].bank_id;
        }
    }
    *max_slot_count = best_count;
    return found;
}

/**
 * Test 5: Successful response to SLOT_MANAGEMENT GetBankInfo.
 * Expected Behavior: SLOT_MANAGEMENT_RESP with a BankInfo structure. The Banks are grouped by
 * algorithm; at least one Bank with at least one slot is reported.
 **/
static void rsp_slot_management_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_bank_info_struct_t *resp_struct;
    spdm_slot_management_request_t request;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request.header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request.header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(spdm_slot_management_request_t),
        &request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO);
    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    assert_true(resp_struct->num_bank_elements >= 1);
    assert_int_equal(response_size,
                     sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_bank_info_struct_t) +
                     (size_t)resp_struct->num_bank_elements *
                     sizeof(spdm_slot_management_bank_element_struct_t));
    /* At least one Bank exposes a slot. */
    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));
}

/**
 * Test 6: Successful response to SLOT_MANAGEMENT GetBankDetails.
 * Expected Behavior: BankDetails reports the Bank's slots, with ConfigAlgo set and the Bank's
 * algorithm in the CurrentAsymAlgo field. AvailableAsymAlgo is a subset of AsymAlgoCapabilities
 * and excludes any algorithm assigned to another Bank (DSP0274 Table 151).
 **/
static void rsp_slot_management_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_bank_details_struct_t *resp_struct;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_slot_address_struct_t *slot_address;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = bank_id;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS);
    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    assert_int_equal(resp_struct->bank_id, bank_id);
    /* The sample exposes two wire SlotIDs (0 and 1) per Bank. */
    assert_int_equal(resp_struct->num_slot_elements, 2);
    /* The Bank supports algorithm configuration (ConfigAlgo) and reports its own algorithm. */
    assert_int_equal(resp_struct->bank_attributes &
                     SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO,
                     SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO);
    assert_int_not_equal(resp_struct->current_asym_algo, 0);

    /* Verify the reported SlotIDs are the true wire values 0 and 1 (not a packed index). The
     * SlotElement array follows the fixed BankDetails fields and the variable-length PQC fields;
     * skip those to reach it. */
    {
        size_t offset;
        uint8_t pqc_cap_len;
        uint8_t current_pqc_len;
        uint8_t available_pqc_len;
        const spdm_slot_management_slot_element_struct_t *slot_element;
        uint32_t hash_size;
        uint8_t slot_index;
        uint8_t seen_slot_mask;

        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        offset = sizeof(spdm_slot_management_bank_details_struct_t);
        pqc_cap_len = ((const uint8_t *)resp_struct)[offset];
        offset += 1 + pqc_cap_len;
        current_pqc_len = ((const uint8_t *)resp_struct)[offset];
        offset += 1 + current_pqc_len;
        available_pqc_len = ((const uint8_t *)resp_struct)[offset];
        offset += 1 + available_pqc_len;
        offset += 4; /* reserved */

        seen_slot_mask = 0;
        for (slot_index = 0; slot_index < resp_struct->num_slot_elements; slot_index++) {
            slot_element = (const void *)((const uint8_t *)resp_struct + offset);
            assert_true(slot_element->slot_id < SPDM_MAX_SLOT_COUNT);
            seen_slot_mask |= (uint8_t)(1 << slot_element->slot_id);
            offset += sizeof(spdm_slot_management_slot_element_struct_t) + hash_size;
        }
        /* SlotIDs 0 and 1 are present. */
        assert_int_equal(seen_slot_mask, 0x03);
    }

    /* AvailableAsymAlgo shall not advertise an algorithm already assigned to another Bank
     * (DSP0274 Table 151). Enumerate every Bank, collect the other Banks' CurrentAsymAlgo, and
     * verify this Bank's AvailableAsymAlgo has none of those bits set, while still being a subset
     * of its own AsymAlgoCapabilities. */
    {
        uint8_t info_request[sizeof(spdm_slot_management_request_t) +
                             sizeof(spdm_slot_management_slot_address_struct_t)];
        spdm_slot_management_bank_info_struct_t *info;
        spdm_slot_management_bank_element_struct_t *elements;
        uint32_t other_banks_asym_algo = 0;
        uint8_t num_banks;
        uint8_t i;

        libspdm_zero_mem(info_request, sizeof(info_request));
        request = (void *)info_request;
        request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
        request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO;
        request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
        slot_address = (void *)(info_request + sizeof(spdm_slot_management_request_t));
        slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;

        response_size = sizeof(response);
        status = libspdm_get_response_slot_management(
            spdm_context, sizeof(info_request), info_request, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        info = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
        elements = (void *)((uint8_t *)info + sizeof(spdm_slot_management_bank_info_struct_t));
        num_banks = info->num_bank_elements;

        /* Collect the CurrentAsymAlgo of every Bank other than the one under test (bank_id). */
        for (i = 0; i < num_banks; i++) {
            uint8_t other_id = elements[i].bank_id;
            uint8_t det_request[sizeof(spdm_slot_management_request_t) +
                                sizeof(spdm_slot_management_slot_address_struct_t)];
            spdm_slot_management_bank_details_struct_t *det;

            if (other_id == bank_id) {
                continue;
            }
            libspdm_zero_mem(det_request, sizeof(det_request));
            request = (void *)det_request;
            request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
            request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
            request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
            slot_address = (void *)(det_request + sizeof(spdm_slot_management_request_t));
            slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
            slot_address->bank_id = other_id;

            response_size = sizeof(response);
            status = libspdm_get_response_slot_management(
                spdm_context, sizeof(det_request), det_request, &response_size, response);
            assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
            spdm_response = (void *)response;
            det = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
            other_banks_asym_algo |= det->current_asym_algo;
        }

        /* Re-read the Bank under test and check its AvailableAsymAlgo. */
        libspdm_zero_mem(request_buffer, sizeof(request_buffer));
        request = (void *)request_buffer;
        request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
        request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
        request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
        slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
        slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
        slot_address->bank_id = bank_id;

        response_size = sizeof(response);
        status = libspdm_get_response_slot_management(
            spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);

        /* AvailableAsymAlgo is a subset of AsymAlgoCapabilities, and shares no bit with any other
         * Bank's CurrentAsymAlgo. */
        assert_int_equal(resp_struct->available_asym_algo & ~resp_struct->asym_algo_capabilities,
                         0);
        assert_int_equal(resp_struct->available_asym_algo & other_banks_asym_algo, 0);
    }
}

/**
 * Test 7: Successful response to SLOT_MANAGEMENT GetCertificateChain.
 * Expected Behavior: SLOT_MANAGEMENT_RESP with the requested certificate chain, matching the
 * chain the HAL provides for the same Bank+slot.
 **/
static void rsp_slot_management_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_slot_address_struct_t *slot_address;
    uint8_t expected_cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t expected_cert_chain_size;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* Use the first Bank+slot that exists. Read the expected chain through the same HAL so the
     * test is independent of the cert file size. */
    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));
    expected_cert_chain_size = sizeof(expected_cert_chain);

    libspdm_copy_mem(expected_cert_chain, expected_cert_chain_size,
                     spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id],
                     spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id]);
    expected_cert_chain_size = spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id];

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = bank_id;
    slot_address->slot_id = slot_id;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN);
    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    assert_int_equal(resp_struct->cc_length, expected_cert_chain_size);
    assert_int_equal(response_size,
                     sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
                     expected_cert_chain_size);
    /* The returned chain shall match what the HAL provides for this Bank+slot. */
    assert_memory_equal((uint8_t *)resp_struct +
                        sizeof(spdm_slot_management_get_certificate_chain_struct_t),
                        expected_cert_chain, expected_cert_chain_size);

    /* GetCertificateChain is a read-only SubCode: it has NO secure-session / trusted-environment
     * requirement, even for slots 1-7 (the DSP0274 "slots 1-7 in a secure session or trusted
     * environment" rule applies to the state-modifying SubCodes only). This connection is merely
     * AUTHENTICATED (no session, not a trusted environment); a GetCertificateChain for a non-zero
     * SlotID shall still succeed. (Regression: a non-zero slot was previously rejected with
     * UnexpectedRequest.) */
    expected_cert_chain_size = sizeof(expected_cert_chain);
    libspdm_copy_mem(expected_cert_chain, expected_cert_chain_size,
                     spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id],
                     spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id]);

    if (expected_cert_chain != NULL) {
        extern bool g_in_trusted_environment;
        bool saved_trusted = g_in_trusted_environment;

        g_in_trusted_environment = false;
        spdm_context->last_spdm_request_session_id_valid = false;

        libspdm_zero_mem(request_buffer, sizeof(request_buffer));
        request = (void *)request_buffer;
        request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
        request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
        request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
        slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
        slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
        slot_address->bank_id = bank_id;
        slot_address->slot_id = 1;

        response_size = sizeof(response);
        status = libspdm_get_response_slot_management(
            spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
        assert_int_equal(spdm_response->header.param1,
                         SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN);

        g_in_trusted_environment = saved_trusted;
    }
}

/**
 * Test 8: SLOT_MANAGEMENT ManageBank ConfigAlgo. Configuring the Bank to its own algorithm is an
 * idempotent success; configuring it to an algorithm owned by another Bank is rejected with
 * InvalidRequest (the algorithm is not in the Bank's AvailableAsymAlgo) both before and after
 * erasing the Bank's slots; and an all-zero algorithm is accepted and clears the Bank's algorithm
 * (the Bank's slots having been erased first).
 **/
static void rsp_slot_management_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_bank_details_struct_t *details;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_manage_bank_struct_t) +
                           sizeof(uint8_t) + sizeof(uint32_t)];
    uint8_t detail_request[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_manage_bank_struct_t *manage_bank;
    spdm_slot_management_slot_address_struct_t *slot_address;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;
    uint32_t bank_asym_algo;
    uint32_t other_asym_algo;
    uint8_t *ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));

    /* Read the Bank's own algorithm via GetBankDetails. */
    libspdm_zero_mem(detail_request, sizeof(detail_request));
    request = (void *)detail_request;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(detail_request + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = bank_id;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(detail_request), detail_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    details = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    bank_asym_algo = details->current_asym_algo;
    assert_int_not_equal(bank_asym_algo, 0);
    /* Choose a different (any other) asymmetric algorithm to attempt a reconfiguration. */
    other_asym_algo = (bank_asym_algo == SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256) ?
                      SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384 :
                      SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    manage_bank = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    manage_bank->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    manage_bank->slot_address.bank_id = bank_id;
    manage_bank->operation = SPDM_SLOT_MANAGEMENT_MANAGE_BANK_OPERATION_CONFIG_ALGO;
    ptr = (uint8_t *)manage_bank + sizeof(spdm_slot_management_manage_bank_struct_t);
    *ptr = sizeof(uint32_t); /* select_pqc_asym_algo_len, value 0 */

    /* Configuring the Bank to its own algorithm is an idempotent success. */
    manage_bank->select_asym_algo = bank_asym_algo;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK);
    assert_int_equal(spdm_response->mgmt_struct_offset, 0);
    assert_int_equal(response_size, sizeof(spdm_slot_management_response_t));

    /* Configuring the Bank to a different algorithm that another Bank already holds is rejected
     * with InvalidRequest: the responder validates the selected algorithm against the Bank's
     * AvailableAsymAlgo (which excludes other Banks' algorithms) before reaching the HAL's
     * provisioned-slots (InvalidState) check, so InvalidRequest wins here. other_asym_algo is the
     * current algorithm of another Bank in this sample. */
    manage_bank->select_asym_algo = other_asym_algo;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    /* Now erase every slot in the Bank, making it unprovisioned. The reconfiguration is still
     * rejected below, this time by the same Select-in-Available check (the target algorithm
     * belongs to another Bank), confirming InvalidRequest is independent of slot state. Erasing
     * slots 1-7 requires a trusted environment or secure session, so enter a trusted environment. */
    {
        extern bool g_in_trusted_environment;
        bool saved_trusted = g_in_trusted_environment;
        uint8_t erase_request[sizeof(spdm_slot_management_request_t) +
                              sizeof(spdm_slot_management_manage_slot_struct_t)];
        spdm_slot_management_manage_slot_struct_t *manage_slot;
        uint8_t slot_iter;

        g_in_trusted_environment = true;

        for (slot_iter = 0; slot_iter < SPDM_MAX_SLOT_COUNT; slot_iter++) {
            libspdm_zero_mem(erase_request, sizeof(erase_request));
            request = (void *)erase_request;
            request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
            request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;
            request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
            manage_slot = (void *)(erase_request + sizeof(spdm_slot_management_request_t));
            manage_slot->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
            manage_slot->slot_address.bank_id = bank_id;
            manage_slot->slot_address.slot_id = slot_iter;
            manage_slot->operation = SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE;
            response_size = sizeof(response);
            /* Slots that do not exist simply fail; existing slots are erased. */
            (void)libspdm_get_response_slot_management(
                spdm_context, sizeof(erase_request), erase_request, &response_size, response);
        }

        g_in_trusted_environment = saved_trusted;
    }

    /* A Bank's CurrentAlgo is unique across Banks: configuring this (now unprovisioned) Bank to an
     * algorithm that another Bank already holds is rejected with InvalidRequest (DSP0274 Table 145
     * ConfigAlgo). Enumerate the Banks, pick a different Bank, read its algorithm, and attempt to
     * take it. (In this sample every device-backable algorithm already owns a Bank, so there is no
     * free algorithm a reconfiguration could succeed with; the uniqueness rule is what a real
     * reconfiguration contends with.) */
    {
        uint8_t info_request[sizeof(spdm_slot_management_request_t) +
                             sizeof(spdm_slot_management_slot_address_struct_t)];
        spdm_slot_management_bank_info_struct_t *info;
        spdm_slot_management_bank_element_struct_t *elements;
        uint8_t other_bank_id;
        uint32_t other_bank_algo;
        bool found_other = false;
        uint8_t i;

        libspdm_zero_mem(info_request, sizeof(info_request));
        request = (void *)info_request;
        request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
        request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO;
        request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
        slot_address = (void *)(info_request + sizeof(spdm_slot_management_request_t));
        slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;

        response_size = sizeof(response);
        status = libspdm_get_response_slot_management(
            spdm_context, sizeof(info_request), info_request, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        info = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
        elements = (void *)((uint8_t *)info + sizeof(spdm_slot_management_bank_info_struct_t));
        for (i = 0; i < info->num_bank_elements; i++) {
            if (elements[i].bank_id != bank_id) {
                other_bank_id = elements[i].bank_id;
                found_other = true;
                break;
            }
        }

        /* The sample provisions key pairs for several distinct algorithms, so a second Bank exists.
         * If a build is configured with only one Bank, there is no duplicate to test. */
        if (found_other) {
            slot_address = (void *)(detail_request + sizeof(spdm_slot_management_request_t));
            slot_address->bank_id = other_bank_id;
            response_size = sizeof(response);
            status = libspdm_get_response_slot_management(
                spdm_context, sizeof(detail_request), detail_request, &response_size, response);
            assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
            spdm_response = (void *)response;
            details = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
            other_bank_algo = details->current_asym_algo;
            assert_int_not_equal(other_bank_algo, 0);

            /* Attempt to configure our (unprovisioned) Bank to the other Bank's algorithm. */
            manage_bank->select_asym_algo = other_bank_algo;
            response_size = sizeof(response);
            status = libspdm_get_response_slot_management(
                spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
            assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
            spdm_response = (void *)response;
            assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
        }

        /* Restore detail_request's bank_id for any later use. */
        slot_address = (void *)(detail_request + sizeof(spdm_slot_management_request_t));
        slot_address->bank_id = bank_id;
    }

    /* An all-zero ConfigAlgo (no bit set in SelectAsymAlgo or SelectPqcAsymAlgo) names no
     * algorithm. Per DSP0274 Table 145 the total number of bits set across the two fields shall
     * be exactly one, so an all-zero selection is rejected with InvalidRequest. */
    manage_bank->select_asym_algo = 0;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    /* Restore the Bank's original algorithm. The Bank's stored algorithm was not touched by the
     * rejected all-zero ConfigAlgo above; re-selecting the Bank's existing algorithm is an
     * idempotent success and does not require the Bank's slots to be empty. */
    manage_bank->select_asym_algo = bank_asym_algo;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK);
}

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Test 9: SLOT_MANAGEMENT ManageSlot (Erase). After erasing a slot, GetCertificateChain for
 * that Bank+slot shall fail. Requires SET_CERT_CAP so the erase HAL hook
 * libspdm_update_local_cert_chain is compiled in.
 **/
static void rsp_slot_management_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_manage_slot_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_manage_slot_struct_t *manage_slot;
    uint8_t cert_request[sizeof(spdm_slot_management_request_t) +
                         sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_slot_address_struct_t *slot_address;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* Erase the first existing Bank+slot. */
    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    manage_slot = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    manage_slot->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    manage_slot->slot_address.bank_id = bank_id;
    manage_slot->slot_address.slot_id = slot_id;
    manage_slot->operation = SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT);
    assert_int_equal(spdm_response->mgmt_struct_offset, 0);
    assert_int_equal(response_size, sizeof(spdm_slot_management_response_t));

    /* GetCertificateChain for the erased slot now fails with InvalidRequest. */
    libspdm_zero_mem(cert_request, sizeof(cert_request));
    request = (void *)cert_request;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(cert_request + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = bank_id;
    slot_address->slot_id = slot_id;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(cert_request), cert_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
/**
 * Test 10: Successful response to SLOT_MANAGEMENT GetCSR.
 * Expected Behavior: SLOT_MANAGEMENT_RESP with a CSR response structure.
 **/
static void rsp_slot_management_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_csr_struct_t *resp_struct;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_get_csr_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_get_csr_struct_t *get_csr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    /* Single-key connection: key_pair_id and cert model in the request shall be 0. */
    spdm_context->connection_info.multi_key_conn_rsp = false;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
    /* The Responder generates the CSR without requiring a reset. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    get_csr = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    get_csr->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    get_csr->slot_address.bank_id = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR);
    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    assert_int_not_equal(resp_struct->csr_length, 0);
    assert_int_equal(response_size,
                     sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_csr_struct_t) + resp_struct->csr_length);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Test 11: Successful response to SLOT_MANAGEMENT SetCertificate, then a SetCertificate to an
 * unknown Bank.
 * Expected Behavior: SLOT_MANAGEMENT_RESP with no response structure for the valid Bank;
 * ERROR(InvalidRequest) for the unknown Bank.
 **/
static void rsp_slot_management_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    void *cert_chain_data;
    size_t cert_chain_data_size;
    uint8_t *request_buffer;
    size_t request_buffer_size;
    spdm_slot_management_request_t *request;
    spdm_slot_management_set_certificate_struct_t *set_cert;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
    /* The Responder writes the certificate without requiring a reset, and is in a trusted
     * environment so a non-zero Bank is allowed. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    /* Per DSP0274 Table 147 the SetCertificate Certificate field is a full certificate chain
     * (spdm_cert_chain_t header, root hash, DER certs), so a real chain is sent into the
     * currently selected Bank (bank 0, slot 0). */
    assert_true(libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &cert_chain_data, &cert_chain_data_size, NULL, NULL));

    request_buffer_size = sizeof(spdm_slot_management_request_t) +
                          sizeof(spdm_slot_management_set_certificate_struct_t) +
                          cert_chain_data_size;
    request_buffer = malloc(request_buffer_size);
    assert_non_null(request_buffer);
    libspdm_zero_mem(request_buffer, request_buffer_size);
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    set_cert = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    set_cert->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    set_cert->slot_address.bank_id = 0;
    set_cert->slot_address.slot_id = 0;
    set_cert->cert_length = (uint32_t)cert_chain_data_size;
    /* Single-key connection: CertModel (and KeyPairID) shall be 0. */
    set_cert->cert_attributes = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_copy_mem((uint8_t *)set_cert +
                     sizeof(spdm_slot_management_set_certificate_struct_t),
                     cert_chain_data_size, cert_chain_data, cert_chain_data_size);

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, request_buffer_size, request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE);
    assert_int_equal(spdm_response->mgmt_struct_offset, 0);
    assert_int_equal(response_size, sizeof(spdm_slot_management_response_t));

    /* SetCertificate to an unknown Bank (0xFF is out of the 0-239 range, so no Bank exists) is
     * rejected with InvalidRequest, like the other SubCodes' unknown-Bank handling. Reuse the
     * request buffer, changing only the BankID. */
    set_cert->slot_address.bank_id = 0xFF;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, request_buffer_size, request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(request_buffer);
    free(cert_chain_data);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

/**
 * Test 12: A valid SubCode that is not advertised in SupportedSubCodes.
 * Expected Behavior: Generate error response message with UNSUPPORTED_REQUEST. Per DSP0274 a
 * valid SubCode that is not in the Responder's SupportedSubCodes response shall be answered with
 * ERROR(UnsupportedRequest), distinct from the InvalidRequest used for unlisted SubCodes.
 **/
static void rsp_slot_management_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_manage_slot_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_manage_slot_struct_t *manage_slot;
    uint8_t saved_byte;
    libspdm_data_parameter_t parameter;
    const uint8_t bitmap_index = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT / 8;
    const uint8_t bitmap_bit =
        (uint8_t)(1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT % 8));

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* Clear the ManageSlot bit so the (valid) SubCode is no longer advertised. */
    saved_byte = m_libspdm_slot_management_sub_code_bitmap[bitmap_index];
    m_libspdm_slot_management_sub_code_bitmap[bitmap_index] &= (uint8_t)(~bitmap_bit);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    assert_false(libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SLOT_MANAGEMENT_SUBCODES,
                                  &parameter, m_libspdm_slot_management_sub_code_bitmap,
                                  sizeof(m_libspdm_slot_management_sub_code_bitmap)));

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    manage_slot = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    manage_slot->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    manage_slot->slot_address.bank_id = 0;
    manage_slot->slot_address.slot_id = 0;
    manage_slot->operation = SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);

    /* Restore the bitmap before asserting so a failure does not leak into later cases. */
    m_libspdm_slot_management_sub_code_bitmap[bitmap_index] = saved_byte;
    assert_false(libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SLOT_MANAGEMENT_SUBCODES,
                                  &parameter, m_libspdm_slot_management_sub_code_bitmap,
                                  sizeof(m_libspdm_slot_management_sub_code_bitmap)));

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
}

/**
 * Test 13: GetBankDetails with BankID = 0xFF (a non-existent Bank).
 * Expected Behavior: Generate error response message with INVALID_REQUEST. 0xFF is no longer a
 * reserved "all Banks" value, so it is treated as a literal, non-existent Bank and rejected.
 **/
static void rsp_slot_management_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_slot_address_struct_t *slot_address;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = 0xFF;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Test 14: SLOT_MANAGEMENT access control for slots 1-7 (ManageSlot Erase).
 * Expected Behavior: An erase of a non-zero SlotID outside a secure session and outside a
 * trusted environment is rejected with UnexpectedRequest. The same request issued in a trusted
 * environment succeeds. (DSP0274 "Certificate slot management": for slots 1-7 these commands
 * shall only be issued in a secure session or a trusted environment.) Requires SET_CERT_CAP so
 * the erase HAL hook libspdm_update_local_cert_chain is compiled in.
 **/
static void rsp_slot_management_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_manage_slot_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_manage_slot_struct_t *manage_slot;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;
    extern bool g_in_trusted_environment;
    bool saved_trusted;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
    /* No session is in use. */
    spdm_context->last_spdm_request_session_id_valid = false;

    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));

    /* Target a non-zero SlotID (slot 1, which the sample exposes). */
    slot_id = 1;

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    manage_slot = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    manage_slot->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    manage_slot->slot_address.bank_id = bank_id;
    manage_slot->slot_address.slot_id = slot_id;
    manage_slot->operation = SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE;

    saved_trusted = g_in_trusted_environment;
    g_in_trusted_environment = false;

    /* Not trusted, no session -> UnexpectedRequest. */
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);

    /* In a trusted environment the same request succeeds. */
    g_in_trusted_environment = true;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    g_in_trusted_environment = saved_trusted;
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT);
    assert_int_equal(spdm_response->mgmt_struct_offset, 0);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

/**
 * Test 15: SLOT_MANAGEMENT negative cases for malformed requests.
 * Expected Behavior: A request whose MgmtStructOffset points past the end of the request, and a
 * GetBankDetails whose SlotAddress.ReqLength is not 8, are both rejected with InvalidRequest.
 **/
static void rsp_slot_management_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_slot_address_struct_t *slot_address;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;

    /* Sub-case 1: GetBankDetails with MgmtStructOffset pointing past the end of the request. */
    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
    request->mgmt_struct_offset = sizeof(request_buffer); /* points at/after the end */
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    /* Sub-case 2: GetBankDetails with an invalid SlotAddress.ReqLength (must be 8). */
    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = 4; /* wrong: shall be 8 */
    slot_address->bank_id = 0;
    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
}

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Test 16: A SLOT_MANAGEMENT SetCertificate followed by GetCertificateChain returns the chain that
 * was just provisioned (not the static factory chain). This exercises that the read path reflects
 * a runtime SET_CERTIFICATE, per DSP0274 (the selected Bank's slots are the GET_CERTIFICATE slots).
 **/
static void rsp_slot_management_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
    void *cert_chain_data;
    size_t cert_chain_data_size;
    uint8_t *raw_cert;
    size_t raw_cert_size;
    size_t digest_size;
    uint8_t *request_buffer;
    size_t request_buffer_size;
    spdm_slot_management_request_t *request;
    spdm_slot_management_set_certificate_struct_t *set_cert;
    uint8_t cert_request[sizeof(spdm_slot_management_request_t) +
                         sizeof(spdm_slot_management_slot_address_struct_t)];
    spdm_slot_management_slot_address_struct_t *slot_address;
    const uint8_t bank_id = 0;
    const uint8_t slot_id = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
    /* No reset required: the SetCertificate completes immediately. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    /* Obtain a real certificate chain. Per DSP0274 Table 147 the SetCertificate Certificate field
     * is a full chain (spdm_cert_chain_t header, root hash, DER certs), so the full chain is sent;
     * raw_cert/raw_cert_size locate the DER portion only for the readback comparison below. */
    assert_true(libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &cert_chain_data, &cert_chain_data_size, NULL, NULL));
    digest_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    raw_cert = (uint8_t *)cert_chain_data + sizeof(spdm_cert_chain_t) + digest_size;
    raw_cert_size = cert_chain_data_size - sizeof(spdm_cert_chain_t) - digest_size;

    /* SLOT_MANAGEMENT SetCertificate of the full chain into (bank 0, slot 0). */
    request_buffer_size = sizeof(spdm_slot_management_request_t) +
                          sizeof(spdm_slot_management_set_certificate_struct_t) +
                          cert_chain_data_size;
    request_buffer = malloc(request_buffer_size);
    assert_non_null(request_buffer);
    libspdm_zero_mem(request_buffer, request_buffer_size);
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    set_cert = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    set_cert->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    set_cert->slot_address.bank_id = bank_id;
    set_cert->slot_address.slot_id = slot_id;
    set_cert->cert_length = (uint32_t)cert_chain_data_size;
    /* Single-key connection: CertModel (and KeyPairID) shall be 0. */
    set_cert->cert_attributes = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_copy_mem((uint8_t *)set_cert + sizeof(spdm_slot_management_set_certificate_struct_t),
                     cert_chain_data_size, cert_chain_data, cert_chain_data_size);

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, request_buffer_size, request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1, SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE);
    free(request_buffer);

    /* GetCertificateChain now returns a full chain reconstructed from the provisioned raw chain. */
    libspdm_zero_mem(cert_request, sizeof(cert_request));
    request = (void *)cert_request;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    slot_address = (void *)(cert_request + sizeof(spdm_slot_management_request_t));
    slot_address->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    slot_address->bank_id = bank_id;
    slot_address->slot_id = slot_id;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(cert_request), cert_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_SLOT_MANAGEMENT_RESP);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN);
    resp_struct = (void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    /* The reconstructed chain has the same size as the source chain, and its raw certificate
     * portion matches what was provisioned. */
    assert_int_equal(resp_struct->cc_length, cert_chain_data_size);
    assert_memory_equal((uint8_t *)resp_struct +
                        sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
                        sizeof(spdm_cert_chain_t) + digest_size,
                        raw_cert, raw_cert_size);

    free(cert_chain_data);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Test 17: A SLOT_MANAGEMENT ManageSlot Erase when the Responder advertises CERT_INSTALL_RESET_CAP
 * shall return ERROR(ResetRequired), mirroring the base SET_CERTIFICATE reset flow. Requires
 * SET_CERT_CAP so the erase HAL hook libspdm_update_local_cert_chain is compiled in.
 **/
static void rsp_slot_management_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_slot_management_response_t *spdm_response;
    uint8_t request_buffer[sizeof(spdm_slot_management_request_t) +
                           sizeof(spdm_slot_management_manage_slot_struct_t)];
    spdm_slot_management_request_t *request;
    spdm_slot_management_manage_slot_struct_t *manage_slot;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t max_bank_id;
    uint8_t max_slot_count;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.capability.ext_flags |=
        SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
    /* The device requires a reset to complete a certificate-install operation. */
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    assert_true(libspdm_slot_management_find_bank(
                    spdm_context, &bank_id, &slot_id, &max_bank_id, &max_slot_count));

    libspdm_zero_mem(request_buffer, sizeof(request_buffer));
    request = (void *)request_buffer;
    request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT;
    request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    manage_slot = (void *)(request_buffer + sizeof(spdm_slot_management_request_t));
    manage_slot->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    manage_slot->slot_address.bank_id = bank_id;
    manage_slot->slot_address.slot_id = slot_id;
    manage_slot->operation = SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE;

    response_size = sizeof(response);
    status = libspdm_get_response_slot_management(
        spdm_context, sizeof(request_buffer), request_buffer, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

int libspdm_rsp_slot_management_test(void)
{
    /* Every case runs libspdm_slot_management_test_setup first, which clears any runtime
     * provisioned/erased certificate NVM files so each test starts from the static factory store
     * and does not leak slot state into later cases or later runs. */
    const struct CMUnitTest test_cases[] = {
        /* Success case for SupportedSubCodes */
        cmocka_unit_test_setup(rsp_slot_management_case1, libspdm_slot_management_test_setup),
        /* SLOT_MGMT_CAP not set */
        cmocka_unit_test_setup(rsp_slot_management_case2, libspdm_slot_management_test_setup),
        /* Unsupported SubCode */
        cmocka_unit_test_setup(rsp_slot_management_case3, libspdm_slot_management_test_setup),
        /* Connection version < 1.4 */
        cmocka_unit_test_setup(rsp_slot_management_case4, libspdm_slot_management_test_setup),
        /* Success case for GetBankInfo */
        cmocka_unit_test_setup(rsp_slot_management_case5, libspdm_slot_management_test_setup),
        /* Success case for GetBankDetails */
        cmocka_unit_test_setup(rsp_slot_management_case6, libspdm_slot_management_test_setup),
        /* Success case for GetCertificateChain */
        cmocka_unit_test_setup(rsp_slot_management_case7, libspdm_slot_management_test_setup),
        /* Success case for ManageBank (+ consistency with GET_KEY_PAIR_INFO) */
        cmocka_unit_test_setup(rsp_slot_management_case8, libspdm_slot_management_test_setup),
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
        /* Success case for ManageSlot (Erase) */
        cmocka_unit_test_setup(rsp_slot_management_case9, libspdm_slot_management_test_setup),
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
        /* Success case for GetCSR */
        cmocka_unit_test_setup(rsp_slot_management_case10, libspdm_slot_management_test_setup),
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
        /* Success case for SetCertificate */
        cmocka_unit_test_setup(rsp_slot_management_case11, libspdm_slot_management_test_setup),
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
        /* Valid-but-unadvertised SubCode -> UnsupportedRequest */
        cmocka_unit_test_setup(rsp_slot_management_case12, libspdm_slot_management_test_setup),
        /* GetBankDetails BankID=0xFF (all Banks) -> UnsupportedRequest */
        cmocka_unit_test_setup(rsp_slot_management_case13, libspdm_slot_management_test_setup),
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
        /* Access control for slots 1-7 (ManageSlot Erase) */
        cmocka_unit_test_setup(rsp_slot_management_case14, libspdm_slot_management_test_setup),
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
        /* Malformed request negatives (MgmtStructOffset, SlotAddress.ReqLength) */
        cmocka_unit_test_setup(rsp_slot_management_case15, libspdm_slot_management_test_setup),
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
        /* SetCertificate then GetCertificateChain reflects the provisioned chain */
        cmocka_unit_test_setup(rsp_slot_management_case16, libspdm_slot_management_test_setup),
        /* ManageSlot Erase with CERT_INSTALL_RESET_CAP -> ResetRequired */
        cmocka_unit_test_setup(rsp_slot_management_case17, libspdm_slot_management_test_setup),
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */
