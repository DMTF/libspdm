/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

/**
 * This function allocates half of session ID for a Requester.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 *
 * @return Half of session ID for a requester.
 **/
uint16_t libspdm_allocate_req_session_id(libspdm_context_t *spdm_context)
{
    uint16_t req_session_id;
    libspdm_session_info_t *session_info;
    size_t index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF0000) == (INVALID_SESSION_ID & 0xFFFF0000)) {
            req_session_id = (uint16_t)(0xFFFF - index);
            return req_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_req_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}
