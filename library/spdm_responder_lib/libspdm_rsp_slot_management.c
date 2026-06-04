/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/**
 * Validate a SlotAddress request structure.
 *
 * Per DSP0274 Table 143, the ReqLength field of a SlotAddress shall be 8 for this version of the
 * specification.
 *
 * @retval true   the SlotAddress is well-formed.
 * @retval false  the SlotAddress shall be rejected with ERROR(InvalidRequest).
 **/
static bool libspdm_slot_management_slot_address_valid(
    const spdm_slot_management_slot_address_struct_t *slot_address)
{
    return slot_address->req_length == SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
}

/**
 * Check whether a state-modifying certificate slot management operation on the given SlotID is
 * permitted.
 *
 * Per DSP0274 "Certificate slot management", for slots 1-7 these commands shall only be issued
 * in a secure session or a trusted environment. (Slot 0 has no such requirement here; it is
 * recommended to be managed in a trusted environment, which is outside this check.) A secure
 * session is an accepted alternative to a trusted environment, matching the base SET_CERTIFICATE
 * handler.
 *
 * This applies to the SubCodes that modify state (SetCertificate, ManageSlot, and GetCSR, which
 * generates/installs a CSR). The read-only SubCodes (GetBankInfo, GetBankDetails,
 * GetCertificateChain) only retrieve information and, like base GET_CERTIFICATE / GET_DIGESTS,
 * carry no such requirement.
 *
 * @retval true   the operation on slot_id is allowed.
 * @retval false  the operation shall be rejected with ERROR(UnexpectedRequest).
 **/
static bool libspdm_slot_management_access_allowed(libspdm_context_t *spdm_context,
                                                   uint8_t slot_id)
{
    if (slot_id == 0) {
        return true;
    }
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    if (libspdm_is_in_trusted_environment(spdm_context)) {
        return true;
    }
#endif
    if (spdm_context->last_spdm_request_session_id_valid) {
        return true;
    }
    return false;
}

/**
 * Return whether a SubCode value is listed in DSP0274 Table 142 (i.e. a defined SubCode).
 *
 * A listed-but-unadvertised SubCode is answered with UnsupportedRequest, whereas an unlisted
 * (reserved) SubCode is answered with InvalidRequest, so the two cases must be distinguished.
 **/
static bool libspdm_slot_management_subcode_is_listed(uint8_t sub_code)
{
    switch (sub_code) {
    case SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT:
    case SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE:
        return true;
    default:
        return false;
    }
}

/**
 * Compute the SLOT_MANAGEMENT GetBankDetails fields for the addressed Bank from the local context
 * state (certificate chains, per-slot metadata, and per-Bank algorithm state).
 *
 * @param[in]      spdm_context             The SPDM context.
 * @param[in]      bank_id                  The Bank to query.
 * @param[out]     bank_attributes          BankAttributes: ConfigAlgo (and Selected if
 *                                          bank_id == connection_info.current_bank).
 * @param[out]     asym_algo_capabilities   local_bank_asym_algo_capabilities[bank_id].
 * @param[out]     current_asym_algo        local_bank_asym_algo[bank_id].
 * @param[out]     available_asym_algo      asym_algo_capabilities with algorithms assigned to
 *                                          other Banks cleared.
 * @param[out]     pqc_asym_algo_capabilities  local_bank_pqc_asym_algo_capabilities[bank_id].
 * @param[out]     current_pqc_asym_algo    local_bank_pqc_asym_algo[bank_id].
 * @param[out]     available_pqc_asym_algo  pqc_asym_algo_capabilities with algorithms assigned to
 *                                          other Banks cleared.
 * @param[in,out]  num_slot_elements        On input the capacity of slot_elements[]; on output
 *                                          the number of populated entries (one per provisioned
 *                                          slot).
 * @param[out]     slot_elements            SlotElement array; entries [0, *num_slot_elements)
 *                                          are populated on success.
 * @param[in,out]  slot_digest_size         On input the stride of slot_digests (bytes per
 *                                          digest); on output the negotiated hash size that was
 *                                          written.
 * @param[out]     slot_digests             Contiguous digest buffer; entry i occupies bytes
 *                                          [i * (*slot_digest_size), (i+1) * (*slot_digest_size)).
 *
 * @retval  true   the Bank exists and every out-parameter was populated.
 * @retval  false  the Bank does not exist (unknown BankID, or neither cert chains nor
 *                 Capabilities are configured), the supplied slot_digest_size is smaller than
 *                 the negotiated hash size, more slots are provisioned than *num_slot_elements
 *                 can hold, or a per-slot hash computation failed.
 **/
static bool libspdm_slot_management_compute_bank_details(
    libspdm_context_t *spdm_context,
    uint8_t bank_id,
    uint8_t *bank_attributes,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint32_t *available_asym_algo,
    uint32_t *pqc_asym_algo_capabilities,
    uint32_t *current_pqc_asym_algo,
    uint32_t *available_pqc_asym_algo,
    uint8_t *num_slot_elements,
    spdm_slot_management_slot_element_struct_t *slot_elements,
    uint32_t *slot_digest_size,
    uint8_t *slot_digests)
{
    uint8_t slot_id;
    uint8_t count;
    uint8_t other_bank;
    uint32_t hash_size;
    uint32_t other_asym_algo;
    uint32_t other_pqc_asym_algo;
    bool bank_exists = false;

    if (bank_id >= LIBSPDM_MAX_BANK_COUNT) {
        return false;
    }

    /* A Bank exists if at least one slot has a provisioned certificate chain, or if the
     * integrator has configured its Capabilities.
     */
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if (spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id] != NULL) {
            bank_exists = true;
            break;
        }
    }
    if (!bank_exists) {
        if ((spdm_context->local_context.local_bank_asym_algo_capabilities[bank_id] != 0) ||
            (spdm_context->local_context.local_bank_pqc_asym_algo_capabilities[bank_id] != 0)) {
            bank_exists = true;
        }
    }
    if (!bank_exists) {
        return false;
    }

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    if (*slot_digest_size < hash_size) {
        return false;
    }

    /* Bank attributes: ConfigAlgo is reported (the Bank can be reconfigured via ManageBank);
     * Selected is set for the currently selected Bank. */
    *bank_attributes = SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO;
    if (bank_id == spdm_context->connection_info.current_bank) {
        *bank_attributes |= SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED;
    }

    *current_asym_algo = spdm_context->local_context.local_bank_asym_algo[bank_id];
    *current_pqc_asym_algo = spdm_context->local_context.local_bank_pqc_asym_algo[bank_id];
    *asym_algo_capabilities =
        spdm_context->local_context.local_bank_asym_algo_capabilities[bank_id];
    *pqc_asym_algo_capabilities =
        spdm_context->local_context.local_bank_pqc_asym_algo_capabilities[bank_id];

    /* AvailableAsymAlgo / AvailablePqcAsymAlgo are this Bank's Capabilities with any algorithm
     * already assigned to ANOTHER Bank cleared (DSP0274 Table 151): an algorithm a different Bank
     * currently holds is not available for this Bank. */
    other_asym_algo = 0;
    other_pqc_asym_algo = 0;
    for (other_bank = 0; other_bank < LIBSPDM_MAX_BANK_COUNT; other_bank++) {
        if (other_bank == bank_id) {
            continue;
        }
        other_asym_algo |= spdm_context->local_context.local_bank_asym_algo[other_bank];
        other_pqc_asym_algo |=
            spdm_context->local_context.local_bank_pqc_asym_algo[other_bank];
    }
    *available_asym_algo = *asym_algo_capabilities & ~other_asym_algo;
    *available_pqc_asym_algo = *pqc_asym_algo_capabilities & ~other_pqc_asym_algo;

    count = 0;
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        const void *cert_chain;
        size_t cert_chain_size;

        cert_chain = spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id];
        if (cert_chain == NULL) {
            continue;
        }
        if (count >= *num_slot_elements) {
            return false;
        }
        cert_chain_size =
            spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id];

        libspdm_zero_mem(&slot_elements[count],
                         sizeof(spdm_slot_management_slot_element_struct_t));
        slot_elements[count].slot_id = slot_id;
        slot_elements[count].slot_attributes =
            SPDM_SLOT_MANAGEMENT_SLOT_ATTRIBUTE_PROVISIONED;
        slot_elements[count].key_pair_id =
            spdm_context->local_context.local_key_pair_id[slot_id];
        slot_elements[count].certificate_info =
            spdm_context->local_context.local_cert_info[bank_id][slot_id];
        slot_elements[count].key_usage =
            spdm_context->local_context.local_key_usage_bit_mask[bank_id][slot_id];
        slot_elements[count].slot_size = (uint32_t)cert_chain_size;

        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                cert_chain, cert_chain_size,
                slot_digests + (size_t)count * (*slot_digest_size))) {
            return false;
        }
        count++;
    }

    *num_slot_elements = count;
    *slot_digest_size = hash_size;
    return true;
}

/**
 * Process the SLOT_MANAGEMENT SupportedSubCodes SubCode.
 *
 * SupportedSubCodes does not use a request structure. The response carries the bit map of
 * SubCodes the Responder supports.
 **/
static libspdm_return_t libspdm_get_response_slot_management_supported_subcodes(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_supported_subcodes_struct_t *resp_struct;

    spdm_request = request;

    /* SupportedSubCodes has no request structure, so per DSP0274 MgmtStructOffset shall be 0. */
    if (spdm_request->mgmt_struct_offset != 0) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t) +
                   sizeof(spdm_slot_management_supported_subcodes_struct_t));
    libspdm_zero_mem(response, *response_size);
    *response_size = sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_supported_subcodes_struct_t);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = 0;
    spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
    spdm_response->reserved = 0;

    resp_struct = (void *)((uint8_t *)spdm_response +
                           sizeof(spdm_slot_management_response_t));
    resp_struct->resp_length = sizeof(spdm_slot_management_supported_subcodes_struct_t);
    resp_struct->reserved = 0;
    libspdm_copy_mem(resp_struct->sub_code_bitmap, sizeof(resp_struct->sub_code_bitmap),
                     spdm_context->local_context.local_slot_management_subcodes,
                     sizeof(spdm_context->local_context.local_slot_management_subcodes));

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the SLOT_MANAGEMENT GetBankInfo SubCode.
 *
 * GetBankInfo does not use a request structure. The response carries an array of BankElements.
 **/
static libspdm_return_t libspdm_get_response_slot_management_get_bank_info(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_response_t *spdm_response;
    spdm_slot_management_bank_info_struct_t *resp_struct;
    spdm_slot_management_bank_element_struct_t *element;
    uint8_t num_bank_elements;
    size_t element_capacity;
    size_t resp_struct_size;
    size_t bank_id;

    spdm_request = request;

    /* GetBankInfo has no request structure, so per DSP0274 MgmtStructOffset shall be 0. */
    if (spdm_request->mgmt_struct_offset != 0) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t) +
                   sizeof(spdm_slot_management_bank_info_struct_t));
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    resp_struct = (void *)((uint8_t *)spdm_response +
                           sizeof(spdm_slot_management_response_t));
    element = (void *)((uint8_t *)resp_struct +
                       sizeof(spdm_slot_management_bank_info_struct_t));

    /* The BankElements are written directly into the response buffer, bounded by the response
     * buffer size, so the responder does not impose a fixed maximum Bank count. BankID is
     * limited to 0-239 by the specification, so at most SPDM_MAX_BANK_COUNT Banks. */
    element_capacity = (*response_size - sizeof(spdm_slot_management_response_t) -
                        sizeof(spdm_slot_management_bank_info_struct_t)) /
                       sizeof(spdm_slot_management_bank_element_struct_t);
    if (element_capacity > SPDM_MAX_BANK_COUNT) {
        element_capacity = SPDM_MAX_BANK_COUNT;
    }

    num_bank_elements = 0;
    for (bank_id = 0; bank_id < LIBSPDM_MAX_BANK_COUNT; bank_id++) {
        uint8_t slot_mask = 0;
        uint8_t slot_id;

        for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
            if (spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id] !=
                NULL) {
                slot_mask |= (uint8_t)(1 << slot_id);
            }
        }
        if (slot_mask == 0) {
            continue;
        }
        if (num_bank_elements >= element_capacity) {
            break;
        }
        element[num_bank_elements].element_length = SPDM_SLOT_MANAGEMENT_BANK_ELEMENT_LENGTH;
        element[num_bank_elements].bank_id = (uint8_t)bank_id;
        element[num_bank_elements].slot_mask = slot_mask;
        element[num_bank_elements].modifiable_slot_mask = 0;
        num_bank_elements++;
    }

    resp_struct_size = sizeof(spdm_slot_management_bank_info_struct_t) +
                       (size_t)num_bank_elements *
                       sizeof(spdm_slot_management_bank_element_struct_t);
    *response_size = sizeof(spdm_slot_management_response_t) + resp_struct_size;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = 0;
    spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
    spdm_response->reserved = 0;

    resp_struct->resp_length = (uint16_t)resp_struct_size;
    resp_struct->reserved = 0;
    resp_struct->num_bank_elements = num_bank_elements;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the SLOT_MANAGEMENT GetBankDetails SubCode.
 *
 * GetBankDetails uses a SlotAddress request structure. The response carries the Bank's
 * algorithm fields followed by an array of SlotElements (each with its certificate digest).
 **/
static libspdm_return_t libspdm_get_response_slot_management_get_bank_details(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_response_t *spdm_response;
    const spdm_slot_management_slot_address_struct_t *slot_address;
    spdm_slot_management_bank_details_struct_t *resp_struct;
    spdm_slot_management_slot_element_struct_t slot_elements[SPDM_MAX_SLOT_COUNT];
    uint8_t slot_digests[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
    uint32_t slot_digest_size;
    uint8_t bank_id;
    uint8_t bank_attributes;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t available_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint32_t available_pqc_asym_algo;
    uint8_t num_slot_elements;
    uint8_t slot_index;
    uint32_t hash_size;
    uint8_t *ptr;
    size_t resp_struct_size;

    spdm_request = request;

    /* GetBankDetails uses a SlotAddress request structure. */
    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset +
         sizeof(spdm_slot_management_slot_address_struct_t) > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    slot_address = (const void *)((const uint8_t *)spdm_request +
                                  spdm_request->mgmt_struct_offset);
    if (!libspdm_slot_management_slot_address_valid(slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    bank_id = slot_address->bank_id;

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

    /* The slots' fixed fields are returned in slot_elements; their certificate chain digests
     * are returned separately in slot_digests, one per slot at a stride of slot_digest_size. */
    num_slot_elements = SPDM_MAX_SLOT_COUNT;
    slot_digest_size = hash_size;
    if (!libspdm_slot_management_compute_bank_details(
            spdm_context, bank_id, &bank_attributes,
            &asym_algo_capabilities, &current_asym_algo, &available_asym_algo,
            &pqc_asym_algo_capabilities, &current_pqc_asym_algo, &available_pqc_asym_algo,
            &num_slot_elements, slot_elements, &slot_digest_size, slot_digests)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* The PQC algorithm fields use a fixed 4-byte length (matching GET_KEY_PAIR_INFO):
     * three (length byte + uint32 value) fields, followed by the 4 reserved bytes,
     * precede the SlotElement array. */
    resp_struct_size = sizeof(spdm_slot_management_bank_details_struct_t) +
                       3 * (sizeof(uint8_t) + sizeof(uint32_t)) + 4 +
                       (size_t)num_slot_elements *
                       (sizeof(spdm_slot_management_slot_element_struct_t) + hash_size);

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t) + resp_struct_size);
    libspdm_zero_mem(response, *response_size);
    *response_size = sizeof(spdm_slot_management_response_t) + resp_struct_size;

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = 0;
    spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
    spdm_response->reserved = 0;

    resp_struct = (void *)((uint8_t *)spdm_response +
                           sizeof(spdm_slot_management_response_t));
    resp_struct->resp_length = (uint16_t)resp_struct_size;
    resp_struct->bank_id = bank_id;
    resp_struct->reserved = 0;
    resp_struct->num_slot_elements = num_slot_elements;
    resp_struct->bank_attributes = bank_attributes;
    resp_struct->reserved2 = 0;
    resp_struct->asym_algo_capabilities = asym_algo_capabilities;
    resp_struct->current_asym_algo = current_asym_algo;
    resp_struct->available_asym_algo = available_asym_algo;

    ptr = (uint8_t *)resp_struct + sizeof(spdm_slot_management_bank_details_struct_t);
    /* PqcAsymAlgoCapabilities (cap_len + value). */
    *ptr = sizeof(uint32_t);
    ptr += sizeof(uint8_t);
    libspdm_write_uint32(ptr, pqc_asym_algo_capabilities);
    ptr += sizeof(uint32_t);
    /* CurrentPqcAsymAlgo (len + value). */
    *ptr = sizeof(uint32_t);
    ptr += sizeof(uint8_t);
    libspdm_write_uint32(ptr, current_pqc_asym_algo);
    ptr += sizeof(uint32_t);
    /* AvailablePqcAsymAlgo (len + value). */
    *ptr = sizeof(uint32_t);
    ptr += sizeof(uint8_t);
    libspdm_write_uint32(ptr, available_pqc_asym_algo);
    ptr += sizeof(uint32_t);
    /* Reserved (4 bytes). */
    ptr += 4;

    for (slot_index = 0; slot_index < num_slot_elements; slot_index++) {
        spdm_slot_management_slot_element_struct_t *slot_element;

        /* The HAL filled the fixed SlotElement fields; the Responder sets element_length. */
        slot_element = (void *)ptr;
        libspdm_copy_mem(slot_element, sizeof(spdm_slot_management_slot_element_struct_t),
                         &slot_elements[slot_index],
                         sizeof(spdm_slot_management_slot_element_struct_t));
        slot_element->element_length =
            (uint16_t)(sizeof(spdm_slot_management_slot_element_struct_t) + hash_size);

        ptr += sizeof(spdm_slot_management_slot_element_struct_t);
        /* Digest of the certificate chain in this slot, returned separately by the HAL. The
         * digest is over the certificate chain for the Bank's configured algorithm, the same
         * chain that GetCertificateChain returns. */
        libspdm_copy_mem(ptr, hash_size,
                         slot_digests + (size_t)slot_index * slot_digest_size,
                         slot_digest_size);
        ptr += hash_size;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the SLOT_MANAGEMENT GetCertificateChain SubCode.
 *
 * GetCertificateChain uses a SlotAddress request structure. The certificate chain for the
 * addressed Bank+slot is read directly from the local context's provisioned chain
 * (local_cert_chain_provision[bank_id][slot_id]), the same byte stream the base GET_CERTIFICATE
 * handler returns.
 **/
static libspdm_return_t libspdm_get_response_slot_management_get_certificate_chain(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_response_t *spdm_response;
    const spdm_slot_management_slot_address_struct_t *slot_address;
    spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t *cert_chain;
    const void *local_cert_chain;
    size_t local_cert_chain_size;
    size_t cert_chain_capacity;

    spdm_request = request;

    /* GetCertificateChain uses a SlotAddress request structure. */
    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset +
         sizeof(spdm_slot_management_slot_address_struct_t) > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    slot_address = (const void *)((const uint8_t *)spdm_request +
                                  spdm_request->mgmt_struct_offset);
    if (!libspdm_slot_management_slot_address_valid(slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    bank_id = slot_address->bank_id;
    slot_id = slot_address->slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;

    /* GetCertificateChain only retrieves information; like the base GET_CERTIFICATE / GET_DIGESTS
     * (which require no session), it has no secure-session / trusted-environment requirement. The
     * DSP0274 "secure session or trusted environment for slots 1-7" rule applies to the slot
     * management commands that modify state (SetCertificate, GetCSR, ManageSlot, ManageBank), not
     * to the read-only SubCodes (GetBankInfo, GetBankDetails, GetCertificateChain). */

    /* The certificate chain is the one provisioned at (bank_id, slot_id). An unprovisioned slot
     * (or an out-of-range BankID) is reported as InvalidRequest, matching how the other
     * SLOT_MANAGEMENT SubCodes report an unknown addressee. */
    if (bank_id >= LIBSPDM_MAX_BANK_COUNT) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    local_cert_chain =
        spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id];
    local_cert_chain_size =
        spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id];
    if (local_cert_chain == NULL || local_cert_chain_size == 0) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t) +
                   sizeof(spdm_slot_management_get_certificate_chain_struct_t));
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    resp_struct = (void *)((uint8_t *)spdm_response +
                           sizeof(spdm_slot_management_response_t));
    cert_chain = (uint8_t *)resp_struct +
                 sizeof(spdm_slot_management_get_certificate_chain_struct_t);
    cert_chain_capacity = *response_size - sizeof(spdm_slot_management_response_t) -
                          sizeof(spdm_slot_management_get_certificate_chain_struct_t);
    if (local_cert_chain_size > cert_chain_capacity) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    libspdm_copy_mem(cert_chain, cert_chain_capacity,
                     local_cert_chain, local_cert_chain_size);

    *response_size = sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
                     local_cert_chain_size;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = 0;
    spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
    spdm_response->reserved = 0;

    resp_struct->cc_length = (uint32_t)local_cert_chain_size;
    resp_struct->reserved = 0;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Emit a SLOT_MANAGEMENT_RESP that has no SubCode response structure (MgmtStructOffset = 0),
 * used by the ManageBank and ManageSlot SubCodes.
 **/
static libspdm_return_t libspdm_slot_management_generate_empty_response(
    libspdm_context_t *spdm_context, uint8_t spdm_version, uint8_t sub_code,
    size_t *response_size, void *response)
{
    spdm_slot_management_response_t *spdm_response;

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t));
    libspdm_zero_mem(response, *response_size);
    *response_size = sizeof(spdm_slot_management_response_t);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = sub_code;
    spdm_response->header.param2 = 0;
    /* These SubCodes have no response structure. */
    spdm_response->mgmt_struct_offset = 0;
    spdm_response->reserved = 0;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the SLOT_MANAGEMENT ManageBank SubCode.
 *
 * ManageBank uses a ManageBank request structure and has no response structure.
 **/
static libspdm_return_t libspdm_get_response_slot_management_manage_bank(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    const spdm_slot_management_manage_bank_struct_t *req_struct;
    uint32_t select_asym_algo;
    uint32_t select_pqc_asym_algo;
    uint8_t select_pqc_asym_algo_len;
    size_t fixed_size;
    uint8_t bank_id;
    uint8_t slot_id;
    /* Out-params for the bank-details lookup used to validate the selected algorithm against the
     * Bank's AvailableAsymAlgo / AvailablePqcAsymAlgo. */
    spdm_slot_management_slot_element_struct_t slot_elements[SPDM_MAX_SLOT_COUNT];
    uint8_t slot_digests[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
    uint32_t slot_digest_size;
    uint8_t bank_attributes;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t available_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint32_t available_pqc_asym_algo;
    uint8_t num_slot_elements;

    spdm_request = request;

    /* The fixed portion is the ManageBank structure plus the SelectPqcAsymAlgoLen byte. */
    fixed_size = sizeof(spdm_slot_management_manage_bank_struct_t) + sizeof(uint8_t);
    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset + fixed_size > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    req_struct = (const void *)((const uint8_t *)spdm_request +
                                spdm_request->mgmt_struct_offset);
    if (!libspdm_slot_management_slot_address_valid(&req_struct->slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    select_asym_algo = req_struct->select_asym_algo;
    select_pqc_asym_algo_len =
        *((const uint8_t *)req_struct + sizeof(spdm_slot_management_manage_bank_struct_t));
    if ((size_t)spdm_request->mgmt_struct_offset + fixed_size +
        select_pqc_asym_algo_len > request_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    /* The Responder shall not assume the Requester uses any particular SelectPqcAsymAlgo field
     * size: copy only the leading bytes that fit in a uint32_t and ignore the rest, matching
     * the SET_KEY_PAIR_INFO handling. */
    select_pqc_asym_algo = 0;
    libspdm_copy_mem(&select_pqc_asym_algo, sizeof(select_pqc_asym_algo),
                     (const uint8_t *)req_struct +
                     sizeof(spdm_slot_management_manage_bank_struct_t) + sizeof(uint8_t),
                     (size_t)LIBSPDM_MIN(select_pqc_asym_algo_len, sizeof(uint32_t)));

    /* The only Operation defined by DSP0274 Table 145 is ConfigAlgo. */
    if (req_struct->operation != SPDM_SLOT_MANAGEMENT_MANAGE_BANK_OPERATION_CONFIG_ALGO) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* Per Table 145, ConfigAlgo configures the Bank for one asymmetric algorithm: the total number
     * of bits set in SelectAsymAlgo and SelectPqcAsymAlgo shall be exactly one. An all-zero
     * selection does not name an algorithm and is rejected. */
    if (!libspdm_onehot0(select_asym_algo) || !libspdm_onehot0(select_pqc_asym_algo) ||
        ((select_asym_algo != 0) == (select_pqc_asym_algo != 0))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* Per Table 145, the selected algorithm "shall match one of the algorithms that the Responder
     * supports as reported in the AsymAlgoCapabilities field of the BankDetails response", and an
     * algorithm already assigned to another Bank shall be rejected (InvalidRequest). Both reduce to
     * "the selected bit shall be set in the Bank's AvailableAsymAlgo / AvailablePqcAsymAlgo", which
     * the responder validates here against the same view GetBankDetails reports from. An unknown
     * BankID also fails the lookup and is reported as InvalidRequest. */
    bank_id = req_struct->slot_address.bank_id;
    num_slot_elements = SPDM_MAX_SLOT_COUNT;
    slot_digest_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    if (!libspdm_slot_management_compute_bank_details(
            spdm_context, bank_id, &bank_attributes,
            &asym_algo_capabilities, &current_asym_algo, &available_asym_algo,
            &pqc_asym_algo_capabilities, &current_pqc_asym_algo, &available_pqc_asym_algo,
            &num_slot_elements, slot_elements, &slot_digest_size, slot_digests)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (((select_asym_algo & available_asym_algo) != select_asym_algo) ||
        ((select_pqc_asym_algo & available_pqc_asym_algo) != select_pqc_asym_algo)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if ((select_asym_algo == spdm_context->local_context.local_bank_asym_algo[bank_id]) &&
        (select_pqc_asym_algo == spdm_context->local_context.local_bank_pqc_asym_algo[bank_id])) {
        return libspdm_slot_management_generate_empty_response(
            spdm_context, spdm_request->header.spdm_version, spdm_request->header.param1,
            response_size, response);
    }

    /* Per Table 145: "If any slots in the Bank specified by BankID have a certificate
     * provisioned, the Responder shall respond with an ERROR response with
     * ErrorCode=InvalidState."
     */
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if (spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id] != NULL) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_STATE, 0,
                                                   response_size, response);
        }
    }

    /* Per Table 145: "When the Bank configuration changes, the Responder shall clear all slot
     * settings."
     */
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        spdm_context->local_context.local_key_pair_id[slot_id] = 0;
        spdm_context->local_context.local_cert_info[bank_id][slot_id] = 0;
        spdm_context->local_context.local_key_usage_bit_mask[bank_id][slot_id] = 0;
    }

    spdm_context->local_context.local_bank_asym_algo[bank_id] = select_asym_algo;
    spdm_context->local_context.local_bank_pqc_asym_algo[bank_id] = select_pqc_asym_algo;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    }

    return libspdm_slot_management_generate_empty_response(
        spdm_context, spdm_request->header.spdm_version, spdm_request->header.param1,
        response_size, response);
}

/**
 * Process the SLOT_MANAGEMENT ManageSlot SubCode.
 *
 * ManageSlot uses a ManageSlot request structure and has no response structure.
 **/
static libspdm_return_t libspdm_get_response_slot_management_manage_slot(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;
    const spdm_slot_management_manage_slot_struct_t *req_struct;
    uint8_t bank_id;
    uint8_t slot_id;

    spdm_request = request;

    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset +
         sizeof(spdm_slot_management_manage_slot_struct_t) > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    req_struct = (const void *)((const uint8_t *)spdm_request +
                                spdm_request->mgmt_struct_offset);
    if (!libspdm_slot_management_slot_address_valid(&req_struct->slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    bank_id = req_struct->slot_address.bank_id;
    slot_id = req_struct->slot_address.slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;

    /* ManageSlot (e.g. Erase) is destructive. For slots 1-7 it shall only be issued in a secure
     * session or a trusted environment. */
    if (!libspdm_slot_management_access_allowed(spdm_context, slot_id)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }

    if (req_struct->operation != SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* The addressed (Bank, slot) shall be provisioned; an unknown BankID or an unprovisioned slot
     * is reported as InvalidRequest, the same way the other SLOT_MANAGEMENT SubCodes do. */
    if (bank_id >= LIBSPDM_MAX_BANK_COUNT) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    bool need_reset;
    bool is_busy;
    const void *old_local_cert_chain;
    size_t old_local_cert_chain_size;

    old_local_cert_chain =
        spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id];
    old_local_cert_chain_size =
        spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id];
    if (old_local_cert_chain == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* The device might require a reset to complete the operation, but only if it advertises
     * CERT_INSTALL_RESET_CAP. Pre-set need_reset to that capability and let the HAL hook decide,
     * mirroring the SET_CERTIFICATE flow. */
    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);
    is_busy = false;

    /* Erase the addressed (Bank, slot) certificate chain through the base SET_CERTIFICATE HAL hook
     * libspdm_update_local_cert_chain (cert_chain = NULL), the same way the base SET_CERTIFICATE
     * erase path uses it. The failure mapping mirrors the SET_CERTIFICATE erase: Busy -> BUSY,
     * otherwise OperationFailed. */
    if (!libspdm_update_local_cert_chain(
            spdm_context, bank_id, slot_id,
            0, 0, 0, 0,
            old_local_cert_chain, old_local_cert_chain_size,
            NULL, 0,
            0,
            &need_reset, &is_busy)) {
        if (is_busy) {
            return libspdm_generate_error_response(spdm_context, SPDM_ERROR_CODE_BUSY, 0,
                                                   response_size, response);
        }
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                               response_size, response);
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) && need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    }

    return libspdm_slot_management_generate_empty_response(
        spdm_context, spdm_request->header.spdm_version, spdm_request->header.param1,
        response_size, response);
#else
    return libspdm_generate_error_response(spdm_context,
                                           SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                           response_size, response);
#endif
}

/**
 * Process the SLOT_MANAGEMENT GetCSR SubCode.
 *
 * GetCSR uses a GetCSR request structure and returns a CSR response structure. It reuses the
 * GET_CSR HAL hook (libspdm_gen_csr) unchanged; the Bank is not passed to the hook because the
 * CSR is generated from the connection's negotiated algorithm, so Bank addressing is redundant
 * to the integrator.
 **/
static libspdm_return_t libspdm_get_response_slot_management_get_csr(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    const spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_response_t *spdm_response;
    const spdm_slot_management_get_csr_struct_t *req_struct;
    spdm_slot_management_csr_struct_t *resp_struct;
    bool result;
    size_t req_struct_offset;
    uint16_t requester_info_length;
    uint16_t opaque_data_length;
    uint8_t *requester_info;
    uint8_t *opaque_data;
    uint8_t *csr_p;
    size_t csr_len;
    bool need_reset;
    bool is_busy;
    bool unexpected_request;
    uint8_t csr_tracking_tag;
    uint8_t key_pair_id;
    uint8_t req_cert_model;
    bool overwrite;

    spdm_request = request;

    /* GetCSR uses a GetCSR request structure (SlotAddress + KeyPairID + RequestAttributes +
     * RequesterInfo + OpaqueData). */
    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset +
         sizeof(spdm_slot_management_get_csr_struct_t) > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    req_struct_offset = spdm_request->mgmt_struct_offset;
    req_struct = (const void *)((const uint8_t *)spdm_request + req_struct_offset);

    if (!libspdm_slot_management_slot_address_valid(&req_struct->slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    requester_info_length = req_struct->requester_info_length;
    opaque_data_length = req_struct->opaque_data_length;

    if (opaque_data_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (((spdm_context->connection_info.algorithm.other_params_support &
          SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE)
        && (opaque_data_length != 0)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((size_t)opaque_data_length >
        request_size - req_struct_offset - sizeof(spdm_slot_management_get_csr_struct_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((size_t)requester_info_length >
        request_size - req_struct_offset - sizeof(spdm_slot_management_get_csr_struct_t) -
        opaque_data_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    requester_info = (uint8_t *)((size_t)(req_struct + 1));
    opaque_data = requester_info + requester_info_length;
    if (opaque_data_length != 0) {
        if (!libspdm_process_general_opaque_data_check(spdm_context, opaque_data_length,
                                                       opaque_data)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }
    if (!libspdm_verify_req_info(requester_info, requester_info_length)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_slot_management_response_t) +
                   sizeof(spdm_slot_management_csr_struct_t));
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    resp_struct = (void *)((uint8_t *)spdm_response +
                           sizeof(spdm_slot_management_response_t));
    csr_p = (uint8_t *)resp_struct + sizeof(spdm_slot_management_csr_struct_t);
    csr_len = *response_size - sizeof(spdm_slot_management_response_t) -
              sizeof(spdm_slot_management_csr_struct_t);

    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);
    is_busy = false;
    unexpected_request = false;

    key_pair_id = req_struct->key_pair_id;
    req_cert_model =
        req_struct->request_attributes & SPDM_GET_CSR_REQUEST_ATTRIBUTES_CERT_MODEL_MASK;
    overwrite =
        (req_struct->request_attributes & SPDM_GET_CSR_REQUEST_ATTRIBUTES_OVERWRITE) != 0;
    csr_tracking_tag =
        (req_struct->request_attributes & SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_MASK) >>
        SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    if ((overwrite && (csr_tracking_tag != 0)) ||
        ((!need_reset) && (csr_tracking_tag != 0))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_context->connection_info.multi_key_conn_rsp) {
        if (key_pair_id == 0) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        if ((req_cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) ||
            (req_cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    } else {
        if ((key_pair_id != 0) || (req_cert_model != 0)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    result = libspdm_gen_csr(
        spdm_context,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.pqc_asym_algo,
        &need_reset, request, request_size,
        requester_info, requester_info_length,
        opaque_data, opaque_data_length,
        &csr_len, csr_p, req_cert_model,
        &csr_tracking_tag, key_pair_id,
        overwrite,
        &is_busy, &unexpected_request);

    if (!result) {
        if (is_busy) {
            return libspdm_generate_error_response(spdm_context, SPDM_ERROR_CODE_BUSY, 0,
                                                   response_size, response);
        } else if (unexpected_request) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                                   response_size, response);
        } else {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) && need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, csr_tracking_tag,
                                               response_size, response);
    }

    *response_size = sizeof(spdm_slot_management_response_t) +
                     sizeof(spdm_slot_management_csr_struct_t) + csr_len;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_SLOT_MANAGEMENT_RESP;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = 0;
    spdm_response->mgmt_struct_offset = sizeof(spdm_slot_management_response_t);
    spdm_response->reserved = 0;

    resp_struct->csr_length = (uint32_t)csr_len;
    resp_struct->reserved = 0;

    return LIBSPDM_STATUS_SUCCESS;
#else /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
    return libspdm_generate_error_response(
        spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
        SPDM_SLOT_MANAGEMENT, response_size, response);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
}

/**
 * Process the SLOT_MANAGEMENT SetCertificate SubCode.
 *
 * SetCertificate uses a SetCertificate request structure and has no response structure. Per
 * DSP0274 (Table 147), the Certificate field is a full certificate chain (spdm_cert_chain_t
 * header, root hash, then DER certificates including the root) and the SubCode conforms to the
 * SET_CERTIFICATE behavior, with the added ability to address a Bank. It therefore reuses the
 * base SET_CERTIFICATE HAL hook libspdm_update_local_cert_chain(), passing &bank_id so the HAL
 * can store the chain in that Bank. For the currently selected Bank this behaves exactly like
 * base SET_CERTIFICATE (the in-memory local_cert_chain_provision is refreshed); for a
 * non-selected Bank the HAL stores the chain without altering the SPDM context.
 **/
static libspdm_return_t libspdm_get_response_slot_management_set_certificate(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    const spdm_slot_management_request_t *spdm_request;
    const spdm_slot_management_set_certificate_struct_t *req_struct;
    const spdm_cert_chain_t *cert_chain_header;
    const void *full_cert_chain;
    size_t full_cert_chain_size;
    const void *old_local_cert_chain;
    size_t old_local_cert_chain_size;
    size_t root_cert_hash_size;
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t cert_model;
    uint8_t key_pair_id;
    bool need_reset;
    bool is_busy;
    bool result;
    size_t req_struct_offset;
    /* Out-params for the bank-existence check (libspdm_slot_management_compute_bank_details);
     * only the call's success/failure is used here. */
    spdm_slot_management_slot_element_struct_t slot_elements[SPDM_MAX_SLOT_COUNT];
    uint8_t slot_digests[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
    uint32_t slot_digest_size;
    uint8_t bank_attributes;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t available_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint32_t available_pqc_asym_algo;
    uint8_t num_slot_elements;

    spdm_request = request;

    if ((spdm_request->mgmt_struct_offset < sizeof(spdm_slot_management_request_t)) ||
        ((size_t)spdm_request->mgmt_struct_offset +
         sizeof(spdm_slot_management_set_certificate_struct_t) > request_size)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    req_struct_offset = spdm_request->mgmt_struct_offset;
    req_struct = (const void *)((const uint8_t *)spdm_request + req_struct_offset);

    if (!libspdm_slot_management_slot_address_valid(&req_struct->slot_address)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    bank_id = req_struct->slot_address.bank_id;
    slot_id = req_struct->slot_address.slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;
    cert_model = req_struct->cert_attributes &
                 SPDM_SLOT_MANAGEMENT_SET_CERTIFICATE_ATTRIBUTE_CERT_MODEL_MASK;
    key_pair_id = req_struct->key_pair_id;

    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* Validate the addressed Bank up front: an unknown BankID is an InvalidRequest, the same way
     * the other SLOT_MANAGEMENT SubCodes report it (e.g. GetBankDetails). Checking here keeps the
     * later libspdm_update_local_cert_chain failure path a pure write failure, so it can align with
     * base SET_CERTIFICATE. Only the call's success is used; the out-params are discarded. */
    num_slot_elements = SPDM_MAX_SLOT_COUNT;
    slot_digest_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    if (!libspdm_slot_management_compute_bank_details(
            spdm_context, bank_id, &bank_attributes,
            &asym_algo_capabilities, &current_asym_algo, &available_asym_algo,
            &pqc_asym_algo_capabilities, &current_pqc_asym_algo, &available_pqc_asym_algo,
            &num_slot_elements, slot_elements, &slot_digest_size, slot_digests)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /* Validate KeyPairID and CertModel exactly as base SET_CERTIFICATE does (Table 147 conforms to
     * SET_CERTIFICATE). SLOT_MANAGEMENT SetCertificate always installs (erase is the ManageSlot
     * SubCode), so the install rules apply unconditionally: when MULTI_KEY_CONN_RSP is true the
     * KeyPairID shall be non-zero and CertModel a valid non-NONE model; otherwise both shall be
     * zero and the effective model is derived from ALIAS_CERT_CAP (mirroring base SET_CERTIFICATE,
     * which never passes a zero model to the HAL). */
    if (spdm_context->connection_info.multi_key_conn_rsp) {
        if (key_pair_id == 0) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        if ((cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) ||
            (cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    } else {
        if ((key_pair_id != 0) || (cert_model != 0)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        if ((spdm_context->local_context.capability.flags &
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) != 0) {
            cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
        } else {
            cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
        }
    }

    /* Per the spec, for slots 1-7 the certificate slot management commands shall only be issued
     * in a secure session or a trusted environment. The restriction is per-slot (SlotID), and a
     * secure session is an accepted alternative to a trusted environment. This matches the base
     * SET_CERTIFICATE handler. */
    if (!libspdm_slot_management_access_allowed(spdm_context, slot_id)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }

    root_cert_hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    /* The Certificate field is a full certificate chain (Table 147 / Table 39): an
     * spdm_cert_chain_t header, the root certificate hash, then the DER certificates. Validate
     * the framing the same way the base SET_CERTIFICATE handler does. */
    if ((size_t)req_struct->cert_length >
        request_size - req_struct_offset - sizeof(spdm_slot_management_set_certificate_struct_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    cert_chain_header = (const void *)(req_struct + 1);
    full_cert_chain = cert_chain_header;
    full_cert_chain_size = req_struct->cert_length;

    if ((full_cert_chain_size < sizeof(spdm_cert_chain_t) + root_cert_hash_size) ||
        (full_cert_chain_size != cert_chain_header->length)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((full_cert_chain_size > SPDM_MAX_CERTIFICATE_CHAIN_SIZE) &&
        (!libspdm_is_capabilities_flag_supported(
             spdm_context, false, 0,
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

#if LIBSPDM_CERT_PARSE_SUPPORT
    /* Verify the certificate chain exactly as base SET_CERTIFICATE does (Table 142: SetCertificate
     * "shall conform to the requirements and behaviors described in SET_CERTIFICATE"). The check
     * runs on the DER certificates, i.e. the chain past the spdm_cert_chain_t header and root hash;
     * on failure the existing certificate is retained (no HAL write below). */
    if (!libspdm_set_cert_verify_certchain(
            libspdm_get_connection_version(spdm_context),
            (const uint8_t *)full_cert_chain + sizeof(spdm_cert_chain_t) + root_cert_hash_size,
            full_cert_chain_size - sizeof(spdm_cert_chain_t) - root_cert_hash_size,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.pqc_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_model)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
#endif /* LIBSPDM_CERT_PARSE_SUPPORT */

    old_local_cert_chain = spdm_context->local_context.local_cert_chain_provision[bank_id][slot_id];
    old_local_cert_chain_size =
        spdm_context->local_context.local_cert_chain_provision_size[bank_id][slot_id];

    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);
    is_busy = false;

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    /* Reuse the base SET_CERTIFICATE HAL hook, passing &bank_id so the chain is stored in the
     * addressed Bank (the Bank was already validated above). The failure mapping matches the base
     * SET_CERTIFICATE install path: Busy -> BUSY, otherwise OperationFailed/Unspecified. */
    result = libspdm_update_local_cert_chain(
        spdm_context,
        bank_id,
        slot_id,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.pqc_asym_algo,
        root_cert_hash_size,
        old_local_cert_chain,
        old_local_cert_chain_size,
        full_cert_chain,
        &full_cert_chain_size,
        cert_model,
        &need_reset, &is_busy);
    if (!result) {
        if (is_busy) {
            return libspdm_generate_error_response(spdm_context, SPDM_ERROR_CODE_BUSY, 0,
                                                   response_size, response);
        }
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
#else
    return libspdm_generate_error_response(spdm_context,
                                           SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                           response_size, response);
#endif

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) && need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    }

    return libspdm_slot_management_generate_empty_response(
        spdm_context, spdm_request->header.spdm_version, spdm_request->header.param1,
        response_size, response);
#else /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
    return libspdm_generate_error_response(
        spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
        SPDM_SLOT_MANAGEMENT, response_size, response);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
}

libspdm_return_t libspdm_get_response_slot_management(libspdm_context_t *spdm_context,
                                                      size_t request_size, const void *request,
                                                      size_t *response_size, void *response)
{
    const spdm_slot_management_request_t *spdm_request;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    uint8_t sub_code;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_SLOT_MANAGEMENT);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_SLOT_MANAGEMENT,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(spdm_context,
                                                       spdm_request->header.request_response_code,
                                                       response_size, response);
    }

    if (request_size < sizeof(spdm_slot_management_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_SLOT_MANAGEMENT, response_size, response);
    }

    /* -=[Dispatch on SubCode Phase]=- */
    sub_code = spdm_request->header.param1;

    /* Per DSP0274, a valid SubCode that is not present in the Responder's SupportedSubCodes
     * response shall be answered with ERROR(UnsupportedRequest). Cross-check the requested
     * SubCode against the advertised bitmap here. Reserved/unlisted SubCodes (bit values with no
     * Table 142 entry) fall through to the switch default below, which returns InvalidRequest. */
    if (libspdm_slot_management_subcode_is_listed(sub_code)) {
        const uint8_t *sub_code_bitmap = spdm_context->local_context.local_slot_management_subcodes;

        if ((sub_code_bitmap[sub_code / 8] & (uint8_t)(1 << (sub_code % 8))) == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                SPDM_SLOT_MANAGEMENT, response_size, response);
        }
    }

    switch (sub_code) {
    case SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES:
        return libspdm_get_response_slot_management_supported_subcodes(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO:
        return libspdm_get_response_slot_management_get_bank_info(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS:
        return libspdm_get_response_slot_management_get_bank_details(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN:
        return libspdm_get_response_slot_management_get_certificate_chain(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK:
        return libspdm_get_response_slot_management_manage_bank(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT:
        return libspdm_get_response_slot_management_manage_slot(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR:
        return libspdm_get_response_slot_management_get_csr(
            spdm_context, request_size, request, response_size, response);
    case SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE:
        return libspdm_get_response_slot_management_set_certificate(
            spdm_context, request_size, request, response_size, response);
    default:
        /* All SubCodes defined in Table 142 have explicit cases above, so this is reached only
         * for a reserved or otherwise unlisted SubCode value. Per DSP0274, a SubCode that is not
         * listed in Table 142 shall be answered with ERROR(InvalidRequest). (A valid-but-
         * unadvertised SubCode is a different case, answered with UnsupportedRequest.) */
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */
