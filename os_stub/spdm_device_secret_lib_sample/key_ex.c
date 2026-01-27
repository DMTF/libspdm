/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "internal/libspdm_common_lib.h"

uint8_t g_key_exchange_start_mut_auth = 0;
bool g_mandatory_mut_auth = false;

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
size_t libspdm_secret_lib_key_exchange_opaque_data_size;
bool g_generate_key_exchange_opaque_data = false;
size_t libspdm_secret_lib_finish_opaque_data_size;
bool g_generate_finish_opaque_data = false;

bool libspdm_key_exchange_rsp_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_hash_type,
    uint8_t slot_id,
    uint8_t session_policy,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    if (g_generate_key_exchange_opaque_data) {
        LIBSPDM_ASSERT(libspdm_secret_lib_key_exchange_opaque_data_size <= *opaque_data_size);

        *opaque_data_size = libspdm_secret_lib_key_exchange_opaque_data_size;

        if (opaque_data != NULL) {
            for (size_t index = 0; index < *opaque_data_size; index++)
            {
                ((uint8_t *)opaque_data)[index] = (uint8_t)(index + 1);
            }
        }

        return true;
    }
    return false;
}

bool libspdm_finish_rsp_opaque_data(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t req_slot_id,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    if (g_generate_finish_opaque_data) {
        LIBSPDM_ASSERT(libspdm_secret_lib_finish_opaque_data_size <= *opaque_data_size);

        *opaque_data_size = libspdm_secret_lib_finish_opaque_data_size;

        if (opaque_data != NULL) {
            for (size_t index = 0; index < *opaque_data_size; index++)
            {
                ((uint8_t *)opaque_data)[index] = (uint8_t)(index + 1);
            }
        }
    } else {
        *opaque_data_size = 0;
    }

    return true;
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
extern uint8_t libspdm_key_exchange_start_mut_auth(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *req_slot_id,
    uint8_t session_policy,
    size_t opaque_data_length,
    const void *opaque_data,
    bool *mandatory_mut_auth)
{
    *req_slot_id = 0;
    *mandatory_mut_auth = g_mandatory_mut_auth;

    return g_key_exchange_start_mut_auth;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
