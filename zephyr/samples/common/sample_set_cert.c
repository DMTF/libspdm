/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * SetCert / certificate-provisioning hooks for the libspdm samples on
 * Zephyr. Dummy implementation.
 */

#include <stdint.h>
#include <stddef.h>

#include <zephyr/kernel.h>

#include "sample_support.h"

bool libspdm_is_in_trusted_environment(void *spdm_context)
{
    ARG_UNUSED(spdm_context);
    return false;
}

bool libspdm_update_local_cert_chain(void *spdm_context,
                                     uint8_t slot_id,
                                     uint32_t base_hash_algo,
                                     uint32_t base_asym_algo,
                                     uint32_t pqc_asym_algo,
                                     size_t hash_size,
                                     const void *old_cert_chain,
                                     size_t old_cert_chain_size,
                                     const void *cert_chain,
                                     size_t *cert_chain_size,
                                     uint8_t cert_model,
                                     bool *need_reset, bool *is_busy)
{
    ARG_UNUSED(spdm_context);
    ARG_UNUSED(slot_id);
    ARG_UNUSED(base_hash_algo);
    ARG_UNUSED(base_asym_algo);
    ARG_UNUSED(pqc_asym_algo);
    ARG_UNUSED(hash_size);
    ARG_UNUSED(old_cert_chain);
    ARG_UNUSED(old_cert_chain_size);
    ARG_UNUSED(cert_chain);
    ARG_UNUSED(cert_chain_size);
    ARG_UNUSED(cert_model);
    if (need_reset) {
        *need_reset = false;
    }
    if (is_busy) {
        *is_busy = false;
    }
    return false;
}

uint32_t libspdm_get_cert_chain_slot_storage_size(void *spdm_context,
                                                  uint8_t slot_id)
{
    ARG_UNUSED(spdm_context);
    ARG_UNUSED(slot_id);
    return 0;
}
