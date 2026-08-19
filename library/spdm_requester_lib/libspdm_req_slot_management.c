/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/**
 * This function sends SLOT_MANAGEMENT (SupportedSubCodes) and receives SLOT_MANAGEMENT_RESP.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  session_id          Indicates if it is a secured message protected via SPDM session.
 * @param  sub_code_bitmap     A pointer to a 8-byte destination buffer to store the supported
 *                             SubCodes bitmap.
 **/
static libspdm_return_t libspdm_try_slot_management_get_supported_subcodes(
    libspdm_context_t *spdm_context,
    const uint32_t *session_id,
    uint8_t *sub_code_bitmap)
{
    libspdm_return_t status;
    spdm_slot_management_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_slot_management_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    spdm_slot_management_supported_subcodes_struct_t *resp_struct;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_slot_management_request_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    spdm_request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES;
    spdm_request->header.param2 = 0;
    /* SupportedSubCodes does not use a request structure. */
    spdm_request->mgmt_struct_offset = 0;
    spdm_request->reserved = 0;
    spdm_request_size = sizeof(spdm_slot_management_request_t);

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SLOT_MANAGEMENT, SPDM_SLOT_MANAGEMENT_RESP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SLOT_MANAGEMENT_RESP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    if (spdm_response->header.param1 != SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    if (spdm_response_size < sizeof(spdm_slot_management_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* MgmtStructOffset shall point at the SlotMgmtRespStruct and the struct shall fit. */
    if ((spdm_response->mgmt_struct_offset < sizeof(spdm_slot_management_response_t)) ||
        (spdm_response->mgmt_struct_offset +
         sizeof(spdm_slot_management_supported_subcodes_struct_t) > spdm_response_size)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    resp_struct = (void *)((uint8_t *)spdm_response +
                           spdm_response->mgmt_struct_offset);
    if (resp_struct->resp_length <
        sizeof(spdm_slot_management_supported_subcodes_struct_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    libspdm_copy_mem(sub_code_bitmap, 8,
                     resp_struct->sub_code_bitmap, sizeof(resp_struct->sub_code_bitmap));

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_slot_management_get_supported_subcodes(void *spdm_context,
                                                                const uint32_t *session_id,
                                                                uint8_t *sub_code_bitmap)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_slot_management_get_supported_subcodes(context, session_id,
                                                                    sub_code_bitmap);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

/**
 * Send a SLOT_MANAGEMENT request with the given SubCode and optional request structure, and
 * copy the SlotMgmtRespStruct from the SLOT_MANAGEMENT_RESP response into resp_struct.
 *
 * @param  resp_struct_size  On input, the capacity of resp_struct. On output, the number of
 *                           bytes copied.
 **/
static libspdm_return_t libspdm_try_slot_management_command(
    libspdm_context_t *spdm_context,
    const uint32_t *session_id,
    uint8_t sub_code,
    const void *req_struct,
    size_t req_struct_size,
    uint8_t *resp_struct,
    size_t *resp_struct_size)
{
    libspdm_return_t status;
    spdm_slot_management_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_slot_management_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    size_t mgmt_struct_size;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_slot_management_request_t) + req_struct_size);
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    spdm_request->header.param1 = sub_code;
    spdm_request->header.param2 = 0;
    spdm_request->reserved = 0;
    if ((req_struct != NULL) && (req_struct_size != 0)) {
        spdm_request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
        libspdm_copy_mem((uint8_t *)spdm_request + sizeof(spdm_slot_management_request_t),
                         spdm_request_size - sizeof(spdm_slot_management_request_t),
                         req_struct, req_struct_size);
        spdm_request_size = sizeof(spdm_slot_management_request_t) + req_struct_size;
    } else {
        spdm_request->mgmt_struct_offset = 0;
        spdm_request_size = sizeof(spdm_slot_management_request_t);
    }

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SLOT_MANAGEMENT, SPDM_SLOT_MANAGEMENT_RESP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SLOT_MANAGEMENT_RESP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.param1 != sub_code) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_slot_management_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* A MgmtStructOffset of 0 indicates the SubCode has no response structure. Otherwise it
     * shall point at the SlotMgmtRespStruct and the struct shall fit. */
    if (spdm_response->mgmt_struct_offset == 0) {
        mgmt_struct_size = 0;
    } else {
        if ((spdm_response->mgmt_struct_offset < sizeof(spdm_slot_management_response_t)) ||
            (spdm_response->mgmt_struct_offset > spdm_response_size)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
        mgmt_struct_size = spdm_response_size - spdm_response->mgmt_struct_offset;
    }

    /* -=[Process Response Phase]=- */
    if (mgmt_struct_size > *resp_struct_size) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }
    if (mgmt_struct_size != 0) {
        libspdm_copy_mem(resp_struct, *resp_struct_size,
                         (uint8_t *)spdm_response + spdm_response->mgmt_struct_offset,
                         mgmt_struct_size);
    }
    *resp_struct_size = mgmt_struct_size;

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

static libspdm_return_t libspdm_slot_management_command(
    libspdm_context_t *context,
    const uint32_t *session_id,
    uint8_t sub_code,
    const void *req_struct,
    size_t req_struct_size,
    uint8_t *resp_struct,
    size_t *resp_struct_size)
{
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;
    size_t resp_capacity;

    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    resp_capacity = *resp_struct_size;
    do {
        *resp_struct_size = resp_capacity;
        status = libspdm_try_slot_management_command(context, session_id, sub_code,
                                                     req_struct, req_struct_size,
                                                     resp_struct, resp_struct_size);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_slot_management_get_bank_info(
    void *spdm_context, const uint32_t *session_id,
    uint8_t *num_bank_elements,
    spdm_slot_management_bank_element_struct_t *bank_elements)
{
    libspdm_return_t status;
    uint8_t resp_buffer[sizeof(spdm_slot_management_bank_info_struct_t) +
                        255 * sizeof(spdm_slot_management_bank_element_struct_t)];
    size_t resp_size;
    const spdm_slot_management_bank_info_struct_t *resp_struct;
    const spdm_slot_management_bank_element_struct_t *element;
    uint8_t count;
    uint8_t index;

    if ((num_bank_elements == NULL) || (bank_elements == NULL)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    resp_size = sizeof(resp_buffer);
    status = libspdm_slot_management_command(spdm_context, session_id,
                                             SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO,
                                             NULL, 0, resp_buffer, &resp_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (resp_size < sizeof(spdm_slot_management_bank_info_struct_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    resp_struct = (const void *)resp_buffer;
    count = resp_struct->num_bank_elements;
    if (sizeof(spdm_slot_management_bank_info_struct_t) +
        (size_t)count * sizeof(spdm_slot_management_bank_element_struct_t) > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (count > *num_bank_elements) {
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    element = (const void *)(resp_buffer + sizeof(spdm_slot_management_bank_info_struct_t));
    for (index = 0; index < count; index++) {
        bank_elements[index] = element[index];
    }
    *num_bank_elements = count;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_slot_management_get_bank_details(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id,
    uint8_t *bank_attributes,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint32_t *available_asym_algo,
    uint32_t *pqc_asym_algo_capabilities,
    uint32_t *current_pqc_asym_algo,
    uint32_t *available_pqc_asym_algo,
    uint16_t *num_slot_elements,
    size_t *slot_elements_size,
    void *slot_elements)
{
    libspdm_return_t status;
    spdm_slot_management_slot_address_struct_t req_struct;
    /* Bank details: header + three (length byte + uint32) PQC fields + 4 reserved + one
     * SlotElement (incl. its digest) per certificate slot. */
    uint8_t resp_buffer[sizeof(spdm_slot_management_bank_details_struct_t) +
                        3 * (sizeof(uint8_t) + sizeof(uint32_t)) + 4 +
                        SPDM_MAX_SLOT_COUNT *
                        (sizeof(spdm_slot_management_slot_element_struct_t) +
                         LIBSPDM_MAX_HASH_SIZE)];
    size_t resp_size;
    const spdm_slot_management_bank_details_struct_t *resp_struct;
    const uint8_t *ptr;
    size_t offset;
    uint8_t pqc_cap_len;
    uint8_t current_pqc_len;
    uint8_t available_pqc_len;
    uint32_t rsp_pqc_asym_algo_capabilities;
    uint32_t rsp_current_pqc_asym_algo;
    uint32_t rsp_available_pqc_asym_algo;

    libspdm_zero_mem(&req_struct, sizeof(req_struct));
    req_struct.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct.bank_id = bank_id;
    req_struct.slot_id = 0;

    resp_size = sizeof(resp_buffer);
    status = libspdm_slot_management_command(spdm_context, session_id,
                                             SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS,
                                             &req_struct, sizeof(req_struct),
                                             resp_buffer, &resp_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (resp_size < sizeof(spdm_slot_management_bank_details_struct_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    resp_struct = (const void *)resp_buffer;

    if (bank_attributes != NULL) {
        *bank_attributes = resp_struct->bank_attributes;
    }
    if (asym_algo_capabilities != NULL) {
        *asym_algo_capabilities = resp_struct->asym_algo_capabilities;
    }
    if (current_asym_algo != NULL) {
        *current_asym_algo = resp_struct->current_asym_algo;
    }
    if (available_asym_algo != NULL) {
        *available_asym_algo = resp_struct->available_asym_algo;
    }
    if (num_slot_elements != NULL) {
        *num_slot_elements = resp_struct->num_slot_elements;
    }

    /* Read the variable-length PQC algorithm fields to reach the SlotElement array. The
     * Requester shall not assume the Responder uses any particular field size: each field is
     * preceded by a length byte, only the leading bytes that fit in a uint32_t are captured
     * (the rest is ignored), and the cursor always advances by the full reported length. This
     * mirrors libspdm_get_key_pair_info(). */
    rsp_pqc_asym_algo_capabilities = 0;
    rsp_current_pqc_asym_algo = 0;
    rsp_available_pqc_asym_algo = 0;

    offset = sizeof(spdm_slot_management_bank_details_struct_t);
    if (offset + 1 > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    pqc_cap_len = resp_buffer[offset];
    if (offset + 1 + pqc_cap_len > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    libspdm_copy_mem(&rsp_pqc_asym_algo_capabilities, sizeof(rsp_pqc_asym_algo_capabilities),
                     resp_buffer + offset + 1,
                     (size_t)LIBSPDM_MIN(pqc_cap_len, sizeof(uint32_t)));
    offset += 1 + pqc_cap_len;

    if (offset + 1 > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    current_pqc_len = resp_buffer[offset];
    if (offset + 1 + current_pqc_len > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    libspdm_copy_mem(&rsp_current_pqc_asym_algo, sizeof(rsp_current_pqc_asym_algo),
                     resp_buffer + offset + 1,
                     (size_t)LIBSPDM_MIN(current_pqc_len, sizeof(uint32_t)));
    offset += 1 + current_pqc_len;

    if (offset + 1 > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    available_pqc_len = resp_buffer[offset];
    if (offset + 1 + available_pqc_len > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    libspdm_copy_mem(&rsp_available_pqc_asym_algo, sizeof(rsp_available_pqc_asym_algo),
                     resp_buffer + offset + 1,
                     (size_t)LIBSPDM_MIN(available_pqc_len, sizeof(uint32_t)));
    offset += 1 + available_pqc_len;

    /* Reserved (4 bytes) precedes the SlotElement array. */
    offset += 4;
    if (offset > resp_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (pqc_asym_algo_capabilities != NULL) {
        *pqc_asym_algo_capabilities = rsp_pqc_asym_algo_capabilities;
    }
    if (current_pqc_asym_algo != NULL) {
        *current_pqc_asym_algo = rsp_current_pqc_asym_algo;
    }
    if (available_pqc_asym_algo != NULL) {
        *available_pqc_asym_algo = rsp_available_pqc_asym_algo;
    }

    if (slot_elements != NULL) {
        if (slot_elements_size == NULL) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }
        ptr = resp_buffer + offset;
        if ((resp_size - offset) > *slot_elements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        libspdm_copy_mem(slot_elements, *slot_elements_size, ptr, resp_size - offset);
        *slot_elements_size = resp_size - offset;
    } else if (slot_elements_size != NULL) {
        *slot_elements_size = resp_size - offset;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t libspdm_try_slot_management_get_certificate_chain(
    libspdm_context_t *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id,
    size_t *cert_chain_size, void *cert_chain)
{
    libspdm_return_t status;
    spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_slot_address_struct_t *req_struct;
    size_t spdm_request_size;
    spdm_slot_management_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    const spdm_slot_management_get_certificate_chain_struct_t *resp_struct;
    uint32_t cc_length;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_slot_management_request_t) +
                   sizeof(spdm_slot_management_slot_address_struct_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    spdm_request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN;
    spdm_request->header.param2 = 0;
    spdm_request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    spdm_request->reserved = 0;
    req_struct = (void *)((uint8_t *)spdm_request + sizeof(spdm_slot_management_request_t));
    libspdm_zero_mem(req_struct, sizeof(*req_struct));
    req_struct->req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct->bank_id = bank_id;
    req_struct->slot_id = slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;
    spdm_request_size = sizeof(spdm_slot_management_request_t) +
                        sizeof(spdm_slot_management_slot_address_struct_t);

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SLOT_MANAGEMENT, SPDM_SLOT_MANAGEMENT_RESP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SLOT_MANAGEMENT_RESP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.param1 != SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_slot_management_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if ((spdm_response->mgmt_struct_offset < sizeof(spdm_slot_management_response_t)) ||
        ((size_t)spdm_response->mgmt_struct_offset +
         sizeof(spdm_slot_management_get_certificate_chain_struct_t) > spdm_response_size)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    resp_struct = (const void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    cc_length = resp_struct->cc_length;
    if ((size_t)spdm_response->mgmt_struct_offset +
        sizeof(spdm_slot_management_get_certificate_chain_struct_t) +
        (size_t)cc_length > spdm_response_size) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (cc_length > *cert_chain_size) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    libspdm_copy_mem(cert_chain, *cert_chain_size,
                     (const uint8_t *)resp_struct +
                     sizeof(spdm_slot_management_get_certificate_chain_struct_t),
                     cc_length);
    *cert_chain_size = cc_length;

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_slot_management_get_certificate_chain(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id,
    size_t *cert_chain_size,
    void *cert_chain)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;
    size_t cert_chain_capacity;

    if ((cert_chain_size == NULL) || (cert_chain == NULL)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    context = spdm_context;
    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    cert_chain_capacity = *cert_chain_size;
    do {
        *cert_chain_size = cert_chain_capacity;
        status = libspdm_try_slot_management_get_certificate_chain(
            context, session_id, bank_id, slot_id, cert_chain_size, cert_chain);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_slot_management_manage_bank(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t operation,
    uint32_t select_asym_algo, uint32_t select_pqc_asym_algo)
{
    uint8_t req_buffer[sizeof(spdm_slot_management_manage_bank_struct_t) +
                       sizeof(uint8_t) + sizeof(uint32_t)];
    spdm_slot_management_manage_bank_struct_t *req_struct;
    uint8_t *ptr;
    size_t resp_size;

    libspdm_zero_mem(req_buffer, sizeof(req_buffer));
    req_struct = (void *)req_buffer;
    req_struct->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct->slot_address.bank_id = bank_id;
    req_struct->operation = operation;
    req_struct->select_asym_algo = select_asym_algo;
    /* SelectPqcAsymAlgo uses a fixed 4-byte length (matching GET_KEY_PAIR_INFO). */
    ptr = req_buffer + sizeof(spdm_slot_management_manage_bank_struct_t);
    *ptr = sizeof(uint32_t);
    ptr += sizeof(uint8_t);
    libspdm_write_uint32(ptr, select_pqc_asym_algo);

    resp_size = 0;
    return libspdm_slot_management_command(spdm_context, session_id,
                                           SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK,
                                           req_buffer, sizeof(req_buffer), NULL, &resp_size);
}

libspdm_return_t libspdm_slot_management_manage_slot(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id, uint8_t operation)
{
    spdm_slot_management_manage_slot_struct_t req_struct;
    size_t resp_size;

    libspdm_zero_mem(&req_struct, sizeof(req_struct));
    req_struct.slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct.slot_address.bank_id = bank_id;
    req_struct.slot_address.slot_id = slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;
    req_struct.operation = operation;

    resp_size = 0;
    return libspdm_slot_management_command(spdm_context, session_id,
                                           SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT,
                                           &req_struct, sizeof(req_struct), NULL, &resp_size);
}

static libspdm_return_t libspdm_try_slot_management_get_csr(
    libspdm_context_t *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id, uint8_t key_pair_id, uint8_t request_attributes,
    const void *requester_info, uint16_t requester_info_length,
    const void *opaque_data, uint16_t opaque_data_length,
    void *csr, size_t *csr_len)
{
    libspdm_return_t status;
    spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_get_csr_struct_t *req_struct;
    size_t spdm_request_size;
    spdm_slot_management_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    const spdm_slot_management_csr_struct_t *resp_struct;
    uint8_t *ptr;
    uint32_t csr_length;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_slot_management_request_t) +
                   sizeof(spdm_slot_management_get_csr_struct_t) +
                   requester_info_length + opaque_data_length);
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    spdm_request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR;
    spdm_request->header.param2 = 0;
    spdm_request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    spdm_request->reserved = 0;
    req_struct = (void *)((uint8_t *)spdm_request + sizeof(spdm_slot_management_request_t));
    libspdm_zero_mem(req_struct, sizeof(*req_struct));
    req_struct->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct->slot_address.bank_id = bank_id;
    req_struct->slot_address.slot_id = slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;
    req_struct->key_pair_id = key_pair_id;
    req_struct->request_attributes = request_attributes;
    req_struct->requester_info_length = requester_info_length;
    req_struct->opaque_data_length = opaque_data_length;
    ptr = (uint8_t *)req_struct + sizeof(spdm_slot_management_get_csr_struct_t);
    if (requester_info_length != 0) {
        libspdm_copy_mem(ptr, requester_info_length, requester_info, requester_info_length);
        ptr += requester_info_length;
    }
    if (opaque_data_length != 0) {
        libspdm_copy_mem(ptr, opaque_data_length, opaque_data, opaque_data_length);
        ptr += opaque_data_length;
    }
    spdm_request_size = sizeof(spdm_slot_management_request_t) +
                        sizeof(spdm_slot_management_get_csr_struct_t) +
                        requester_info_length + opaque_data_length;

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SLOT_MANAGEMENT, SPDM_SLOT_MANAGEMENT_RESP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SLOT_MANAGEMENT_RESP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.param1 != SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_slot_management_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if ((spdm_response->mgmt_struct_offset < sizeof(spdm_slot_management_response_t)) ||
        ((size_t)spdm_response->mgmt_struct_offset +
         sizeof(spdm_slot_management_csr_struct_t) > spdm_response_size)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    resp_struct = (const void *)((uint8_t *)spdm_response + spdm_response->mgmt_struct_offset);
    csr_length = resp_struct->csr_length;
    if ((size_t)spdm_response->mgmt_struct_offset +
        sizeof(spdm_slot_management_csr_struct_t) + (size_t)csr_length > spdm_response_size) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (csr_length > *csr_len) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    libspdm_copy_mem(csr, *csr_len,
                     (const uint8_t *)resp_struct + sizeof(spdm_slot_management_csr_struct_t),
                     csr_length);
    *csr_len = csr_length;

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_slot_management_get_csr(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id, uint8_t key_pair_id, uint8_t request_attributes,
    void *requester_info, uint16_t requester_info_length,
    void *opaque_data, uint16_t opaque_data_length,
    void *csr, size_t *csr_len)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;
    size_t csr_capacity;

    if ((csr_len == NULL) || (csr == NULL)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    context = spdm_context;
    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    csr_capacity = *csr_len;
    do {
        *csr_len = csr_capacity;
        status = libspdm_try_slot_management_get_csr(
            context, session_id, bank_id, slot_id, key_pair_id, request_attributes,
            requester_info, requester_info_length, opaque_data, opaque_data_length,
            csr, csr_len);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

static libspdm_return_t libspdm_try_slot_management_set_certificate(
    libspdm_context_t *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id, uint8_t key_pair_id, uint8_t cert_attributes,
    const void *cert_chain, size_t cert_chain_size)
{
    libspdm_return_t status;
    spdm_slot_management_request_t *spdm_request;
    spdm_slot_management_set_certificate_struct_t *req_struct;
    size_t spdm_request_size;
    spdm_slot_management_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_14) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_ext_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    if (spdm_request_size < sizeof(spdm_slot_management_request_t) +
        sizeof(spdm_slot_management_set_certificate_struct_t) + cert_chain_size) {
        libspdm_release_sender_buffer (spdm_context);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SLOT_MANAGEMENT;
    spdm_request->header.param1 = SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE;
    spdm_request->header.param2 = 0;
    spdm_request->mgmt_struct_offset = sizeof(spdm_slot_management_request_t);
    spdm_request->reserved = 0;
    req_struct = (void *)((uint8_t *)spdm_request + sizeof(spdm_slot_management_request_t));
    libspdm_zero_mem(req_struct, sizeof(*req_struct));
    req_struct->slot_address.req_length = SPDM_SLOT_MANAGEMENT_SLOT_ADDRESS_REQ_LENGTH;
    req_struct->slot_address.bank_id = bank_id;
    req_struct->slot_address.slot_id = slot_id & SPDM_SLOT_MANAGEMENT_SLOT_ID_MASK;
    req_struct->cert_length = (uint32_t)cert_chain_size;
    req_struct->cert_attributes = cert_attributes;
    req_struct->key_pair_id = key_pair_id;
    libspdm_copy_mem((uint8_t *)req_struct +
                     sizeof(spdm_slot_management_set_certificate_struct_t),
                     cert_chain_size, cert_chain, cert_chain_size);
    spdm_request_size = sizeof(spdm_slot_management_request_t) +
                        sizeof(spdm_slot_management_set_certificate_struct_t) + cert_chain_size;

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SLOT_MANAGEMENT, SPDM_SLOT_MANAGEMENT_RESP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SLOT_MANAGEMENT_RESP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.param1 != SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_slot_management_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_slot_management_set_certificate(
    void *spdm_context, const uint32_t *session_id,
    uint8_t bank_id, uint8_t slot_id, uint8_t key_pair_id, uint8_t cert_attributes,
    const void *cert_chain, size_t cert_chain_size)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    if ((cert_chain == NULL) || (cert_chain_size == 0)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    context = spdm_context;
    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_slot_management_set_certificate(
            context, session_id, bank_id, slot_id, key_pair_id, cert_attributes,
            cert_chain, cert_chain_size);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */
