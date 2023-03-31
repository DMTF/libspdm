/**
 *  Copyright Notice:
 *  Copyright 2021-2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SECRETLIB_H
#define SECRETLIB_H

#include "internal/libspdm_lib_config.h"
#include "hal/base.h"
#include "industry_standard/spdm.h"
#include "library/spdm_return_status.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF
 * algorithm.
 *
 * @param  base_hash_algo  Indicates the hash algorithm.
 * @param  psk_hint        Pointer to the peer-provided PSK Hint.
 * @param  psk_hint_size   PSK Hint size in bytes.
 * @param  info            Pointer to the application specific info.
 * @param  info_size       Info size in bytes.
 * @param  out             Pointer to buffer to receive HKDF value.
 * @param  out_size        Size of HKDF bytes to generate.
 *
 * @retval true   HKDF generated successfully.
 * @retval false  HKDF generation failed.
 **/
extern bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo, const uint8_t *psk_hint,
    size_t psk_hint_size, const uint8_t *info,
    size_t info_size, uint8_t *out, size_t out_size);

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF
 * algorithm.
 *
 * @param  base_hash_algo  Indicates the hash algorithm.
 * @param  psk_hint        Pointer to the peer-provided PSK Hint.
 * @param  psk_hint_size   PSK Hint size in bytes.
 * @param  info            Pointer to the application specific info.
 * @param  info_size       Info size in bytes.
 * @param  out             Pointer to buffer to receive HKDF value.
 * @param  out_size        Size of HKDF bytes to generate.
 *
 * @retval true   HKDF generated successfully.
 * @retval false  HKDF generation failed.
 **/
extern bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint, size_t psk_hint_size,
    const uint8_t *info, size_t info_size,
    uint8_t *out, size_t out_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * Writes a certificate chain to non-volatile memory.
 *
 * @param[in]  slot_id          The number of slot for the certificate chain.
 * @param[in]  cert_chain       The pointer for the certificate chain to set.
 * @param[in]  cert_chain_size  The size of the certificate chain to set.
 *
 * @retval true   Success write to non-volatile memory.
 * @retval false  Unsuccessful write to non-volatile memory.
 **/
extern bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void *cert_chain,
                                             size_t cert_chain_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#endif /* SECRETLIB_H */
