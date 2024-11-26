/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
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

bool libspdm_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
bool libspdm_encap_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */
