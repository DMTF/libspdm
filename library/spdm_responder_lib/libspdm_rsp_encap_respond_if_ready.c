/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_RESPOND_IF_READY_SUPPORT)

libspdm_return_t libspdm_get_encap_request_respond_if_ready(void *context,
                                                            const uint32_t *session_id,
                                                            size_t *encap_request_size,
                                                            void *encap_request)
{
    libspdm_context_t *spdm_context;
    libspdm_encap_context_t *encap_context;
    spdm_response_if_ready_request_t *spdm_request;

    spdm_context = context;

    encap_context = libspdm_get_encap_context(spdm_context, session_id);
    if (encap_context == NULL) {
        /* session_id does not refer to an existing session. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (encap_context->last_encap_request_size == 0) {
        /* There is no outstanding encapsulated request to ask about. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (*encap_request_size < sizeof(spdm_response_if_ready_request_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    *encap_request_size = sizeof(spdm_response_if_ready_request_t);

    spdm_request = encap_request;
    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_RESPOND_IF_READY;
    spdm_request->header.param1 = encap_context->response_not_ready_data.request_code;
    spdm_request->header.param2 = encap_context->response_not_ready_data.token;

    /* last_encap_request_header is deliberately left alone. It still identifies the request that
     * this RESPOND_IF_READY is asking about, so that the response, when it arrives, is dispatched
     * to the correct handler. */

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_RESPOND_IF_READY_SUPPORT) */
