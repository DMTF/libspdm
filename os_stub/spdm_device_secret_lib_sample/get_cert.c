/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
uint32_t libspdm_get_cert_chain_slot_storage_size(
    void *spdm_context, uint8_t slot_id)
{
    return SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */
