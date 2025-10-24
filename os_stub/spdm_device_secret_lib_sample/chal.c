/**
 *  Copyright Notice:
 *  Copyright 2024-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
size_t libspdm_secret_lib_challenge_opaque_data_size;
bool g_check_challenge_request_context = false;
uint64_t g_challenge_request_context;

bool libspdm_challenge_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    size_t request_context_size,
    const void *request_context,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    if (g_check_challenge_request_context) {
        if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
            LIBSPDM_ASSERT(request_context_size == SPDM_REQ_CONTEXT_SIZE);
            LIBSPDM_ASSERT(libspdm_read_uint64(request_context) == g_challenge_request_context);
        } else {
            LIBSPDM_ASSERT(request_context_size == 0);
            LIBSPDM_ASSERT(request_context == NULL);
        }
    }

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

bool libspdm_encap_challenge_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    size_t request_context_size,
    const void *request_context,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    if (g_check_challenge_request_context) {
        if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
            LIBSPDM_ASSERT(request_context_size == SPDM_REQ_CONTEXT_SIZE);
            LIBSPDM_ASSERT(libspdm_read_uint64(request_context) == g_challenge_request_context);
        } else {
            LIBSPDM_ASSERT(request_context_size == 0);
            LIBSPDM_ASSERT(request_context == NULL);
        }
    }

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */
