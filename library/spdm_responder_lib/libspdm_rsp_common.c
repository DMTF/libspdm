/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

uint16_t libspdm_allocate_rsp_session_id(const libspdm_context_t *spdm_context)
{
    uint16_t rsp_session_id;
    const libspdm_session_info_t *session_info;
    size_t index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF) == (INVALID_SESSION_ID & 0xFFFF)) {
            rsp_session_id = (uint16_t)(0xFFFF - index);
            return rsp_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_rsp_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF);
}
