/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef REQUESTER_SECRETLIB_H
#define REQUESTER_SECRETLIB_H

#include "hal/library/secretlib/secretlib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
/**
 * Sign an SPDM message data.
 *
 * @param  req_base_asym_alg Indicates the signing algorithm.
 * @param  base_hash_algo    Indicates the hash algorithm.
 * @param  is_data_hash      Indicates the message type.
 *                           If true, raw message before hash.
 *                           If false, message hash.
 * @param  message           A pointer to a message to be signed.
 * @param  message_size      The size in bytes of the message to be signed.
 * @param  signature         A pointer to a destination buffer to store the signature.
 * @param  sig_size          On input, indicates the size, in bytes, of the destination buffer to
 *                           store the signature.
 *                           On output, indicates the size, in bytes, of the signature in the
 *                           buffer.
 *
 * @retval true  signing success.
 * @retval false signing fail.
 **/
extern bool libspdm_requester_data_sign(
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

#endif /* REQUESTER_SECRETLIB_H */
