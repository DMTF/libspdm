/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_CRYPT_LIB_INTERNAL_H
#define SPDM_CRYPT_LIB_INTERNAL_H

#include "library/spdm_crypt_lib.h"
#include "hal/library/cryptlib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

/**
 * Create SPDM signing context, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  spdm_signing_context                 SPDM signing context
 **/
void libspdm_create_signing_context (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    void *spdm_signing_context);

/**
 * Get the SPDM signing context string, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  context_size                         SPDM signing context size
 **/
const void *libspdm_get_signing_context_string (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    size_t *context_size);

#endif /* SPDM_CRYPT_LIB_INTERNAL_H */
