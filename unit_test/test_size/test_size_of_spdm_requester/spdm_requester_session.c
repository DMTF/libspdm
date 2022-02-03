/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

return_status do_session_via_spdm(IN void *spdm_context)
{
    return_status status;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_start_session(
        spdm_context,
        false, /* KeyExchange*/
        SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, 0,
        &session_id, &heartbeat_period, measurement_hash);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_ERROR, "libspdm_start_session - %r\n", status));
        return status;
    }


    /* TBD - Set key*/


    status = libspdm_stop_session(spdm_context, session_id, 0);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_ERROR, "libspdm_stop_session - %r\n", status));
        return status;
    }

    return status;
}
