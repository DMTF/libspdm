/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_GETCERTLIB_H
#define RESPONDER_GETCERTLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
/**
 * Get the size of storage space for a certificate chain in a specific slot.
 *
 * @param[in]  spdm_context  A pointer to the SPDM context.
 * @param[in]  slot_id       The number of slot for the certificate chain.
 *
 * @return size of storage space for the certificate chain.
 **/
uint32_t libspdm_get_cert_chain_slot_storage_size(
    void *spdm_context,
    uint8_t slot_id);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */

#endif /* RESPONDER_GETCERTLIB_H */
