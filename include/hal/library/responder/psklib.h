/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_PSKLIB_H
#define RESPONDER_PSKLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
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

/**
 * Generates the OpaqueData field of the PSK_EXCHANGE_RSP message.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  psk_hint                   Pointer to the peer-provided PSK Hint.
 * @param  psk_hint_size              PSK Hint size in bytes.
 * @param  spdm_version               Indicates the negotiated version.
 * @param  measurement_hash_type      The measurement hash type in the PSK_EXCHANGE request.
 * @param  req_opaque_data            The OpaqueData field in the PSK_EXCHANGE request.
 * @param  req_opaque_data_size       Size, in bytes, of req_opaque_data.
 * @param  opaque_data                The buffer to store the OpaqueData field in the
 *                                    PSK_EXCHANGE_RSP response.
 * @param  opaque_data_size           On input, size, in bytes, of the opaque_data buffer.
 *                                    On output, size, in bytes, of copied data in the
 *                                    opaque_data buffer.
 *
 * @retval true   OpaqueData field is generated successfully.
 *                If return true, responder will not generate any opaque data,
 *                including secured message version.
 * @retval false  OpaqueData field generation failed.
 */
extern bool libspdm_psk_exchange_rsp_opaque_data(
    void *spdm_context,
    const void *psk_hint,
    uint16_t psk_hint_size,
    spdm_version_number_t spdm_version,
    uint8_t measurement_hash_type,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size);

/**
 * Processes the OpaqueData field of the PSK_FINISH_RSP message.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  session_id              Secure session identifier.
 * @param  spdm_version            Indicates the negotiated version.
 * @param  req_opaque_data         The OpaqueData field in the PSK_FINISH request.
 * @param  req_opaque_data_size    Size, in bytes, of req_opaque_data.
 * @param  opaque_data             The buffer to store the OpaqueData field in the PSK_FINISH_RSP response.
 * @param  opaque_data_size        On input, size, in bytes, of the opaque_data buffer.
 *                                 On output, size, in bytes, of copied data in the opaque_data buffer.
 *
 * @retval true   OpaqueData field is processed successfully.
 * @retval false  OpaqueData field processing failed.
 */
extern bool libspdm_psk_finish_rsp_opaque_data(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size);

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#endif /* RESPONDER_PSKLIB_H */
