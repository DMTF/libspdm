/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

void libspdm_register_encap_flow_handler(void *spdm_context,
                                         libspdm_encap_flow_handler_func encap_flow_handler)
{
    libspdm_context_t *context;

    context = spdm_context;

    context->encap_flow_handler_callback = (void *)encap_flow_handler;
}

libspdm_return_t libspdm_get_encap_payload_size(void *spdm_context,
                                                const uint32_t *session_id,
                                                size_t *payload_size)
{
    libspdm_encap_context_t *encap_context;

    encap_context = libspdm_get_encap_context(spdm_context, session_id);
    if (encap_context == NULL) {
        /* session_id does not refer to an existing session. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    *payload_size = encap_context->payload_buffer_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the encapsulated response received from the Requester. Dispatches to the correct
 * response processing function based on the last request code.
 **/
static libspdm_return_t libspdm_dispatch_process_encap_response(
    libspdm_context_t *spdm_context, uint8_t last_request_code,
    size_t encap_response_size, const void *encap_response, bool *need_continue)
{
    switch (last_request_code) {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case SPDM_GET_DIGESTS:
        return libspdm_process_encap_response_digest(
            spdm_context, encap_response_size, encap_response, need_continue);
    case SPDM_GET_CERTIFICATE:
        return libspdm_process_encap_response_certificate(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
    case SPDM_CHALLENGE:
        return libspdm_process_encap_response_challenge_auth(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif
    case SPDM_KEY_UPDATE:
        return libspdm_process_encap_response_key_update(
            spdm_context, encap_response_size, encap_response, need_continue);
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
    case SPDM_GET_ENDPOINT_INFO:
        return libspdm_process_encap_response_endpoint_info(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    case SPDM_SEND_EVENT:
        return libspdm_process_encap_response_event_ack(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
}

/**
 * Determine whether processing the encapsulated response failed because of the Responder's own
 * state or resources rather than because of anything the Requester sent.
 *
 * @param  status  The status that libspdm_dispatch_process_encap_response returned.
 *
 * @retval true   The failure is local, so the Requester is not at fault.
 * @retval false  The Requester's encapsulated response could not be processed.
 **/
static bool libspdm_is_local_process_failure(libspdm_return_t status)
{
    return (status == LIBSPDM_STATUS_BUFFER_TOO_SMALL) ||
           (status == LIBSPDM_STATUS_BUFFER_FULL) ||
           (status == LIBSPDM_STATUS_INVALID_STATE_LOCAL) ||
           (status == LIBSPDM_STATUS_UNSUPPORTED_CAP) ||
           (status == LIBSPDM_STATUS_CRYPTO_ERROR);
}

/**
 * When a multi-message operation (GET_CERTIFICATE or KEY_UPDATE) requires a follow-up request,
 * build the next request without calling the Integrator's handler.
 **/
static libspdm_return_t libspdm_dispatch_encap_need_continue(
    libspdm_context_t *spdm_context, const uint32_t *session_id, uint8_t last_request_code,
    size_t *encap_request_size, void *encap_request)
{
    libspdm_encap_context_t *encap_context;

    encap_context = libspdm_get_encap_context(spdm_context, session_id);

    /* session_id comes from the request that libspdm is responding to, so it is necessarily
     * valid. */
    LIBSPDM_ASSERT(encap_context != NULL);

    switch (last_request_code) {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case SPDM_GET_CERTIFICATE:
        return libspdm_get_encap_request_get_certificate_continue(
            spdm_context, session_id, encap_context->req_slot_id,
            encap_request_size, encap_request);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    case SPDM_KEY_UPDATE:
        return libspdm_get_encap_request_key_update(
            spdm_context, *session_id, SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY,
            encap_request_size, encap_request);
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
}

/**
 * Determine whether an encapsulated request is legal for the flow it would be sent in.
 *
 * Encapsulated requests are limited by message type and by whether the flow belongs to a session.
 *
 * @param  flow_type     The encapsulated flow that is in progress.
 * @param  in_session    True if the flow belongs to a session. Note that this is not the same as
 *                       the messages being sent within that session, as session-based mutual
 *                       authentication is conducted outside of a session when both endpoints have
 *                       set HANDSHAKE_IN_THE_CLEAR_CAP.
 * @param  request_code  The request code that the Integrator's handler produced.
 *
 * @retval true   The request is legal for this flow.
 * @retval false  The request is not legal and must not be sent.
 **/
static bool libspdm_is_encap_request_legal(libspdm_encap_flow_type_t flow_type,
                                           bool in_session,
                                           uint8_t request_code)
{
    switch (flow_type) {
    case LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH:
        /* All messages are sent outside of a session. */
        if (in_session) {
            return false;
        }
        return (request_code == SPDM_CHALLENGE) || (request_code == SPDM_GET_DIGESTS) ||
               (request_code == SPDM_GET_CERTIFICATE);
    case LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH:
        /* All messages belong to the same session, and are only to retrieve the Requester's
         * certificate chain. */
        if (!in_session) {
            return false;
        }
        return (request_code == SPDM_GET_DIGESTS) || (request_code == SPDM_GET_CERTIFICATE);
    case LIBSPDM_ENCAP_FLOW_REQ_INITIATED:
        switch (request_code) {
        case SPDM_GET_DIGESTS:
        case SPDM_GET_CERTIFICATE:
        case SPDM_GET_ENDPOINT_INFO:
            return true;
        case SPDM_SEND_EVENT:
        case SPDM_KEY_UPDATE:
            /* Only legal within a session. */
            return in_session;
        default:
            return false;
        }
    default:
        return false;
    }
}


void libspdm_reset_all_encap_state(libspdm_context_t *spdm_context)
{
    size_t index;

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    #if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
    #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        spdm_context->session_info[index].encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        spdm_context->session_info[index].encap_context.response_not_ready = false;
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    }
}

#define MAX_ERROR_MSG_SIZE 36

/**
 * Propagate an ERROR response that the Integrator's handler produced in place of an encapsulated
 * request. The ERROR replaces the ENCAPSULATED_REQUEST or ENCAPSULATED_RESPONSE_ACK that would
 * otherwise have been sent.
 *
 * @param  response          The response buffer. It overlaps encap_error.
 * @param  response_size     On input the size of the response buffer, on output the size of the
 *                           ERROR response. Unchanged if this function returns an error.
 * @param  encap_error       The ERROR message that the handler produced.
 * @param  encap_error_size  Size, in bytes, of encap_error.
 *
 * @retval LIBSPDM_STATUS_SUCCESS           The ERROR response was placed in the response buffer.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE  encap_error_size is not a plausible ERROR size.
 **/
static libspdm_return_t libspdm_propagate_encap_error(void *response, size_t *response_size,
                                                      const void *encap_error,
                                                      size_t encap_error_size)
{
    uint8_t error_response_buffer[MAX_ERROR_MSG_SIZE];

    /* The handler supplies encap_error_size, so it is bounded here before it reaches
     * libspdm_copy_mem, which does not clamp. */
    if ((encap_error_size < sizeof(spdm_error_response_t)) ||
        (encap_error_size > sizeof(error_response_buffer)) ||
        (encap_error_size > *response_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "encapsulated ERROR size 0x%zx is not valid\n", encap_error_size));
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    /* Copy through a temporary buffer since the source and destination overlap and memmove is
     * not available. */
    libspdm_copy_mem(error_response_buffer, sizeof(error_response_buffer),
                     encap_error, encap_error_size);
    libspdm_copy_mem(response, *response_size, error_response_buffer, encap_error_size);
    *response_size = encap_error_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/* Tracks the session's encapsulated DIGESTS window, so it does nothing outside a session.
 * libspdm_reset_message_buffer_via_request_code() is not used here, as an encapsulated
 * request the Responder sends must not reset its own transcripts. */
static void libspdm_reset_transcript_via_encap_request(libspdm_context_t *spdm_context,
                                                       const uint32_t *session_id,
                                                       const void *encap_request)
{
    if (session_id == NULL) {
        return;
    }

    libspdm_reset_message_buffer_via_encap_request_code(
        spdm_context,
        libspdm_get_session_info_via_session_id(spdm_context, *session_id),
        ((const spdm_message_header_t *)encap_request)->request_response_code);
}

libspdm_return_t libspdm_get_response_encapsulated_request(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    spdm_encapsulated_request_response_t *spdm_response;
    void *encap_request;
    size_t encap_request_size;
    libspdm_return_t status;
    const spdm_get_encapsulated_request_request_t *spdm_request;
    spdm_error_response_t *error_response;
    bool terminate_flow;
    bool recovering;
    const uint32_t *session_id;
    libspdm_encap_context_t *encap_context;

    spdm_request = request;
    encap_context = libspdm_get_encap_context_via_last_request(spdm_context);
    recovering = false;

    /* LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_ENCAPSULATED_REQUEST);
     */

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_GET_ENCAPSULATED_REQUEST,
                                               response_size, response);
    }

    if (!libspdm_is_encap_supported(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_ENCAPSULATED_REQUEST, response_size, response);
    }

    if (spdm_context->encap_flow_handler_callback == NULL) {
        /* If ENCAP_CAP is set then the handler must also be registered. */
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
    }

    if (request_size < sizeof(spdm_get_encapsulated_request_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    if (encap_context->flow_type == LIBSPDM_ENCAP_FLOW_NONE) {
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        if (encap_context->response_not_ready) {
            /* Resume the flow that an encapsulated ERROR(ResponseNotReady) terminated. The
             * outstanding request is left in last_encap_request_header so that the response, when
             * it eventually arrives, is dispatched to the request that asked for it. Entering the
             * flow consumes the ResponseNotReady. */
            encap_context->flow_type = encap_context->response_not_ready_flow_type;
            encap_context->response_not_ready = false;
            recovering = true;
        }
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

        if (!recovering) {
            /* Requester-initiated encap flow; initialize the encap context. The mutual
             * authentication flows have already set flow_type in CHALLENGE_AUTH or
             * KEY_EXCHANGE_RSP. */
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
            encap_context->request_id = 0;
            encap_context->last_encap_request_size = 0;
            libspdm_zero_mem(&encap_context->last_encap_request_header,
                             sizeof(encap_context->last_encap_request_header));
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size > sizeof(spdm_encapsulated_request_response_t));
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_ENCAPSULATED_REQUEST;
    spdm_response->header.param1 = encap_context->request_id;
    spdm_response->header.param2 = 0;

    encap_request_size = *response_size - sizeof(spdm_encapsulated_request_response_t);
    encap_request = spdm_response + 1;
    terminate_flow = false;

    /* This is the session the flow belongs to, which is not necessarily the session the message
     * arrived on. See libspdm_get_encap_session_id_via_last_request. */
    session_id = libspdm_get_encap_session_id_via_last_request(spdm_context);

    #if LIBSPDM_RESPOND_IF_READY_SUPPORT
    if (recovering) {
        /* The Requester asked for more time rather than declining the request, so libspdm reissues
         * the outstanding request itself. The Integrator's handler is not consulted, as the flow
         * continues with the request it already has. */
        status = libspdm_get_encap_request_respond_if_ready(
            spdm_context, session_id, &encap_request_size, encap_request);

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            /* The failure is local to the Responder; nothing was wrong with the Requester's
             * message. */
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }

        /* The Request ID is unchanged, since this reissues the request that already carries it. */
        *response_size = sizeof(spdm_encapsulated_request_response_t) + encap_request_size;

        return LIBSPDM_STATUS_SUCCESS;
    }
    #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    LIBSPDM_ASSERT(encap_context->flow_type != LIBSPDM_ENCAP_FLOW_NONE);

    status = ((libspdm_encap_flow_handler_func)spdm_context->encap_flow_handler_callback)(
        spdm_context, session_id, encap_context->flow_type, 0, 0,
        &terminate_flow, &encap_request_size, encap_request);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        /* The failure is local to the Responder; nothing was wrong with the Requester's
         * message. */
        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    error_response = (spdm_error_response_t *)encap_request;

    if (error_response->header.request_response_code == SPDM_ERROR) {
        /* Handler generated an error response; propagate it directly. */
        status = libspdm_propagate_encap_error(response, response_size,
                                               encap_request, encap_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }
        return LIBSPDM_STATUS_SUCCESS;
    } else if (terminate_flow) {
        if (encap_context->flow_type != LIBSPDM_ENCAP_FLOW_REQ_INITIATED) {
            /* The Responder asked for this flow in CHALLENGE_AUTH or KEY_EXCHANGE_RSP, so it
             * cannot then report that it has no request pending. */
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "encapsulated flow type %d cannot terminate without a request\n",
                           encap_context->flow_type));
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }

        /* The Requester polled and the Responder has nothing to send, so no flow is in progress. */
        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;

        if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_13) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_NO_PENDING_REQUESTS, 0,
                response_size, response);
        } else {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    } else {
        if ((encap_request_size != 0) &&
            !libspdm_is_encap_request_legal(encap_context->flow_type,
                                            session_id != NULL,
                                            error_response->header.request_response_code)) {
            /* The Integrator produced a request that is not permitted in this flow. */
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "encapsulated request 0x%x is not legal in flow type %d\n",
                           error_response->header.request_response_code,
                           encap_context->flow_type));
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }
        if (encap_request_size != 0) {
            libspdm_reset_transcript_via_encap_request(spdm_context, session_id, encap_request);
        }
        *response_size = sizeof(spdm_encapsulated_request_response_t) + encap_request_size;
    }

    if (encap_request_size == 0) {
        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_response_encapsulated_response_ack(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_deliver_encapsulated_response_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    const void *encap_response;
    size_t encap_response_size;
    void *encap_request;
    size_t encap_request_size;
    libspdm_return_t status;
    size_t ack_header_size;
    bool terminate_flow;
    bool need_continue;
    bool response_not_ready;
    bool encap_error_received;
    uint8_t last_request_code;
    uint8_t error_code;
    const uint32_t *session_id;
    libspdm_encap_context_t *encap_context;

    spdm_request = request;
    encap_context = libspdm_get_encap_context_via_last_request(spdm_context);

    /* LIBSPDM_ASSERT(spdm_request->header.request_response_code ==
     *                SPDM_DELIVER_ENCAPSULATED_RESPONSE); */

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_DELIVER_ENCAPSULATED_RESPONSE,
                                               response_size, response);
    }

    if (!libspdm_is_encap_supported(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_DELIVER_ENCAPSULATED_RESPONSE, response_size, response);
    }

    if (spdm_context->encap_flow_handler_callback == NULL) {
        /* If ENCAP_CAP is set then the handler must also be registered. */
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    if (encap_context->flow_type == LIBSPDM_ENCAP_FLOW_NONE) {
        /* No encapsulated flow is in progress on this channel. Note that the first
         * DELIVER_ENCAPSULATED_RESPONSE after KEY_EXCHANGE_RSP with bit 2 set is legal, as
         * flow_type was set to LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH at that time. */
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (request_size <= sizeof(spdm_deliver_encapsulated_response_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    spdm_request_size = request_size;

    if (spdm_request->header.param1 != encap_context->request_id) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    encap_response = spdm_request + 1;
    encap_response_size = spdm_request_size - sizeof(spdm_deliver_encapsulated_response_request_t);

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        ack_header_size = sizeof(spdm_encapsulated_response_ack_response_t);
    } else {
        ack_header_size = sizeof(spdm_message_header_t);
    }

    LIBSPDM_ASSERT(*response_size > ack_header_size);
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_ENCAPSULATED_RESPONSE_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;

    encap_request_size = *response_size - ack_header_size;
    encap_request = (uint8_t *)spdm_response + ack_header_size;
    if (encap_response_size < sizeof(spdm_message_header_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    terminate_flow = false;
    need_continue = false;
    response_not_ready = false;
    encap_error_received = false;
    error_code = 0;
    last_request_code = encap_context->last_encap_request_header.request_response_code;
    /* This is the session the flow belongs to, which is not necessarily the session the message
     * arrived on. See libspdm_get_encap_session_id_via_last_request. */
    session_id = libspdm_get_encap_session_id_via_last_request(spdm_context);

    if (last_request_code != 0) {
        /* Process the encapsulated response from the Requester before calling the handler. */
        status = libspdm_dispatch_process_encap_response(
            spdm_context, last_request_code,
            encap_response_size, encap_response, &need_continue);

        if ((session_id != NULL) &&
            (libspdm_get_session_info_via_session_id(spdm_context, *session_id) == NULL)) {
            /* Processing the encapsulated response ended the session that the flow belongs to,
             * which also discarded encap_context. There is no flow left to continue and no state
             * to give the Integrator. */
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            const spdm_error_response_t *encap_error = encap_response;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
            const spdm_error_data_response_not_ready_t *not_ready_data;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

            if ((encap_response_size < sizeof(spdm_error_response_t)) ||
                (encap_error->header.request_response_code != SPDM_ERROR)) {
                /* The encapsulated response was not an ERROR, so processing it genuinely failed
                * and there is no ErrorCode to report to the handler. A failure of the Responder's
                * own state or resources, such as a payload larger than the buffer the Integrator
                * supplied, is not reported as though the Requester's response were at fault. */
                uint8_t process_error_code;

                if (libspdm_is_local_process_failure(status)) {
                    process_error_code = SPDM_ERROR_CODE_UNSPECIFIED;
                } else {
                    process_error_code = SPDM_ERROR_CODE_INVALID_RESPONSE_CODE;
                }

                encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                return libspdm_generate_error_response(
                    spdm_context, process_error_code, 0, response_size, response);
            }

            if (encap_error->header.param1 == 0) {
                /* ErrorCode 0x00 is reserved, so this ERROR is malformed. It also cannot be
                 * reported to the handler, as an error_code of 0 is how the absence of an
                 * encapsulated ERROR is conveyed. */
                encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
                    response_size, response);
            }

            /* The Requester delivered an encapsulated ERROR. Report its code to the handler so
             * that the Integrator learns why the flow ended. */
            encap_error_received = true;
            error_code = encap_error->header.param1;

            if (status == LIBSPDM_STATUS_NOT_READY_PEER) {
                response_not_ready = true;

                #if LIBSPDM_RESPOND_IF_READY_SUPPORT
                /* The encapsulated request is still outstanding, so retain the flow it belongs to
                 * and the fields needed to reissue it with RESPOND_IF_READY once the Requester
                 * returns with GET_ENCAPSULATED_REQUEST. */
                if (encap_response_size <
                    (sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t))) {
                    encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
                        response_size, response);
                }
                not_ready_data = (const void *)((const uint8_t *)encap_response +
                                                sizeof(spdm_error_response_t));

                /* The Requester echoes the request it is deferring, and the Responder knows which
                 * request that is. A mismatch, or a retry interval the Responder cannot honour,
                 * means the extended data cannot be used to reissue the request. */
                if ((not_ready_data->request_code != last_request_code) ||
                    (not_ready_data->rd_tm <= 1) ||
                    (not_ready_data->rd_exponent > LIBSPDM_MAX_RDT_EXPONENT)) {
                    encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
                        response_size, response);
                }

                libspdm_copy_mem(&encap_context->response_not_ready_data,
                                 sizeof(encap_context->response_not_ready_data),
                                 not_ready_data,
                                 sizeof(spdm_error_data_response_not_ready_t));
                encap_context->response_not_ready_flow_type = encap_context->flow_type;
                encap_context->response_not_ready = true;
                #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
            }
        }

        if (need_continue) {
            /* Build the follow-up request (next GET_CERTIFICATE chunk or VerifyNewKey)
             * without invoking the handler. */
            status = libspdm_dispatch_encap_need_continue(
                spdm_context, session_id, last_request_code,
                &encap_request_size, encap_request);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                /* The failure is local to the Responder; nothing was wrong with the Requester's
                 * encapsulated response. */
                encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
                    response_size, response);
            }
            goto set_ack_fields;
        }

        #if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
        if (!encap_error_received && (last_request_code == SPDM_CHALLENGE)) {
            /* Basic mutual authentication concludes with the encapsulated CHALLENGE_AUTH
             * response. The Responder must then terminate the encapsulated flow by clearing
             * ENCAPSULATED_RESPONSE_ACK.Param2, so the Integrator's handler is not consulted
             * and cannot continue the flow. */
            terminate_flow = true;
            goto set_ack_fields;
        }
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */
    }

    LIBSPDM_ASSERT(encap_context->flow_type != LIBSPDM_ENCAP_FLOW_NONE);

    /* All response data processed; ask the Integrator what to do next. */
    status = ((libspdm_encap_flow_handler_func)spdm_context->encap_flow_handler_callback)(
        spdm_context, session_id, encap_context->flow_type,
        last_request_code, error_code, &terminate_flow, &encap_request_size, encap_request);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        /* The failure is local to the Responder; nothing was wrong with the Requester's
         * encapsulated response. */
        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
    }

    if (encap_error_received) {
        /* An encapsulated ERROR ends the flow, so the Integrator acknowledges it rather than
         * supplying another request. */
        LIBSPDM_ASSERT(terminate_flow);
        terminate_flow = true;
        encap_request_size = 0;
        goto set_ack_fields;
    }

    if ((encap_request_size != 0) &&
        (((const spdm_message_header_t *)encap_request)->request_response_code == SPDM_ERROR)) {
        /* Handler generated an error response instead of an encapsulated request; propagate it
         * directly. This is checked before the legality test below, as SPDM_ERROR is not a
         * request code and would otherwise be rejected there. */
        status = libspdm_propagate_encap_error(response, response_size,
                                               encap_request, encap_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (!terminate_flow && (encap_request_size != 0) &&
        !libspdm_is_encap_request_legal(
            encap_context->flow_type, session_id != NULL,
            ((const spdm_message_header_t *)encap_request)->request_response_code)) {
        /* The Integrator produced a request that is not permitted in this flow. */
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "encapsulated request 0x%x is not legal in flow type %d\n",
                       ((const spdm_message_header_t *)encap_request)->request_response_code,
                       encap_context->flow_type));
        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
    }

    if (!terminate_flow && (encap_request_size != 0)) {
        libspdm_reset_transcript_via_encap_request(spdm_context, session_id, encap_request);
    }

set_ack_fields:
    *response_size = ack_header_size + encap_request_size;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response->ack_request_id = spdm_request->header.param1;
    }

    if (!terminate_flow && (encap_request_size != 0)) {
        if (encap_context->request_id == UINT8_MAX) {
            encap_context->request_id = 1;
        } else {
            encap_context->request_id++;
        }
        spdm_response->header.param1 = encap_context->request_id;
    } else {
        /* No further encapsulated request, so this is the final message of the flow. */
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
        *response_size = ack_header_size;

        if ((encap_context->flow_type == LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH) && !response_not_ready) {
            /* When MutAuthRequested bit 1 or bit 2 is set, the Responder must designate the
             * Requester's certificate slot in the final ENCAPSULATED_RESPONSE_ACK, as
             * KEY_EXCHANGE_RSP.ReqSlotID could not convey it. */
            spdm_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
            *response_size = ack_header_size + 1;
            *((uint8_t *)spdm_response + ack_header_size) = encap_context->mut_auth_req_slot_id;
        }

        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_handle_encap_error_response_main(uint8_t error_code)
{
    if (error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return LIBSPDM_STATUS_NOT_READY_PEER;
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
