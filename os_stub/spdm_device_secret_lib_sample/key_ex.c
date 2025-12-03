/**
 *  Copyright Notice:
 *  Copyright 2024-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "internal/libspdm_common_lib.h"

uint8_t g_key_exchange_start_mut_auth = 0;
bool g_mandatory_mut_auth = false;

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP)
extern uint8_t libspdm_key_exchange_start_mut_auth(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *req_slot_id,
    uint8_t session_policy,
    size_t opaque_data_length,
    const void *opaque_data,
    bool *mandatory_mut_auth
)
{
    *req_slot_id = 0;
    *mandatory_mut_auth = g_mandatory_mut_auth;

    return g_key_exchange_start_mut_auth;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) */
