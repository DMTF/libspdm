/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include "library/spdm_device_secret_lib.h"

/**
 * Collect the device measurement.
 *
 * @param  measurement_specification     Indicates the measurement specification.
 *                                     It must align with measurement_specification (SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_*)
 * @param  measurement_hash_algo          Indicates the measurement hash algorithm.
 *                                     It must align with measurement_hash_algo (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
 * @param  device_measurement_count       The count of the device measurement block.
 * @param  device_measurement            A pointer to a destination buffer to store the concatenation of all device measurement blocks.
 * @param  device_measurement_size        On input, indicates the size in bytes of the destination buffer.
 *                                     On output, indicates the size in bytes of all device measurement blocks in the buffer.
 *
 * @retval RETURN_SUCCESS             Successfully returned measurement_count and optionally measurements, measurements_size.
 * @retval RETURN_***                 Any other RETURN_error code indicating the type of measurement collection failure.
 **/
libspdm_return_t libspdm_measurement_collection(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t mesurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *device_measurement_count,
    void *device_measurement,
    size_t *device_measurement_size)
{
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

/**
 * This function calculates the measurement summary hash.
 *
 * @param  spdm_version                  The spdm version.
 * @param  base_hash_algo                The hash algo to use on summary.
 * @param  measurement_specification     Indicates the measurement specification.
 *                                      It must align with measurement_specification
 *                                      (SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_*)
 * @param  measurement_hash_algo         Indicates the measurement hash algorithm.
 *                                      It must align with measurement_hash_alg
 *                                      (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
 *
 * @param  measurement_summary_hash_type   The type of the measurement summary hash.
 * @param  measurement_summary_hash        The buffer to store the measurement summary hash.
 * @param  measurement_summary_hash_size   The size in bytes of the buffer.
 *
 * @retval true  measurement summary hash is generated or skipped.
 * @retval false measurement summary hash is not generated.
 **/
bool
libspdm_generate_measurement_summary_hash(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t  *measurement_summary_hash,
    size_t *measurement_summary_hash_size)
{
    return false;
}

/**
 * Sign an SPDM message data.
 *
 * @param  req_base_asym_alg               Indicates the signing algorithm.
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  is_data_hash                   Indicate the message type. true: raw message before hash, false: message hash.
 * @param  message                      A pointer to a message to be signed.
 * @param  message_size                  The size in bytes of the message to be signed.
 * @param  signature                    A pointer to a destination buffer to store the signature.
 * @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
 *                                     On output, indicates the size in bytes of the signature in the buffer.
 *
 * @retval true  signing success.
 * @retval false signing fail.
 **/
bool libspdm_requester_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}

/**
 * Sign an SPDM message data.
 *
 * @param  base_asym_algo                 Indicates the signing algorithm.
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  is_data_hash                   Indicate the message type. true: raw message before hash, false: message hash.
 * @param  message                      A pointer to a message to be signed.
 * @param  message_size                  The size in bytes of the message to be signed.
 * @param  signature                    A pointer to a destination buffer to store the signature.
 * @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
 *                                     On output, indicates the size in bytes of the signature in the buffer.
 *
 * @retval true  signing success.
 * @retval false signing fail.
 **/
bool libspdm_responder_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  psk_hint                      Pointer to the user-supplied PSK Hint.
 * @param  psk_hint_size                  PSK Hint size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    return false;
}

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  psk_hint                      Pointer to the user-supplied PSK Hint.
 * @param  psk_hint_size                  PSK Hint size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    return false;
}
