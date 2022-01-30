/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_DEVICE_SECRET_LIB_H__
#define __SPDM_DEVICE_SECRET_LIB_H__

#ifndef LIBSPDM_CONFIG
#include "spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#include "hal/base.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"
#include "library/spdm_crypt_lib.h"

/**
 * Collect the device measurement.
 *
 * libspdm will call this function to retrieve the measurements for a device.
 * The "measurement_index" parameter indicates the measurement requested.
 *
 * @param  measurement_specification     Indicates the measurement specification.
 * Must be a SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_* value in spdm.h.
 *
 * @param  measurement_hash_algo         Indicates the measurement hash algorithm.
 * Must be SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_* value in spdm.h.
 *
 * @param  measurement_index      The index of the measurement to collect.
 *
 * A value of [0x0] requests only the total number of measurements to be returned
 * in "measurements_count". The parameters "measurements" and
 * "measurements_size" will be left unmodified.
 *
 * A value of [1-0xFE] requests a single measurement for that measurement index
 * be returned. On success, "measurements_count" will be set to 1 and the
 * "measurements" and "measurements_size" fields will be set based
 * on the single measurement. An invalid measurement index will cause
 * "measurements_count" to return 0.
 *
 * A value of [0xFF] requests all measurements be returned.
 * On success, "measurements_count", "measurements", and "measurements_size"
 * fields will be set with data from all measurements.
 *
 * @param  measurements_count
 *
 * When "measurement_index" is zero, returns the total count of
 * measurements available for the device. None of the actual measurements are
 * returned however, and "measurements" and "measurements_size" are unmodified.
 *
 * When "measurement_index" is non-zero, returns the number of measurements
 * returned in "measurements" and "measurements_size". If "measurements_index"
 * is an invalid index not supported by the device, "measurements_count" will
 * return 0.
 *
 * @param  measurements
 *
 * A pointer to a destination buffer to store the concatenation of all device
 * measurement blocks. This buffer will only be modified if
 * "measurement_index" is non-zero.
 *
 * @param  measurements_size
 *
 * On input, indicates the size in bytes of the destination buffer.
 * On output, indicates the total size in bytes of all device measurement
 * blocks in the buffer. This field should only be modified if
 * "measurement_index" is non-zero.
 *
 * @retval RETURN_SUCCESS             Successfully returned measurement_count,
 *                                   measurements, measurements_size.
 * @retval RETURN_BUFFER_TOO_SMALL    measurements buffer too small for measurements.
 * @retval RETURN_INVALID_PARAMETER   Invalid parameter passed to function.
 * @retval RETURN_NOT_FOUND           Unsupported measurement index.
 * @retval RETURN_***                 Any other RETURN_ error from base.h
 *                                   indicating the type of failure
 **/
return_status libspdm_measurement_collection(
    IN spdm_version_number_t spdm_version,
    IN uint8_t measurement_specification,
    IN uint32_t measurement_hash_algo,
    IN uint8_t measurement_index,
    IN uint8_t request_attribute,
    OUT uint8_t *content_changed,
    OUT uint8_t *measurements_count,
    OUT void *measurements,
    IN OUT uintn *measurements_size);

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
 * @retval TRUE  measurement summary hash is generated or skipped.
 * @retval FALSE measurement summary hash is not generated.
 **/
boolean
libspdm_generate_measurement_summary_hash(
    IN spdm_version_number_t spdm_version,
    IN uint32_t base_hash_algo,
    IN uint8_t measurement_specification,
    IN uint32_t measurement_hash_algo,
    IN uint8_t measurement_summary_hash_type,
    OUT uint8_t  *measurement_summary_hash,
    IN OUT uintn *measurement_summary_hash_size);

/**
 * Sign an SPDM message data.
 *
 * @param  req_base_asym_alg               Indicates the signing algorithm.
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  is_data_hash                   Indicate the message type. TRUE: raw message before hash, FALSE: message hash.
 * @param  message                      A pointer to a message to be signed.
 * @param  message_size                  The size in bytes of the message to be signed.
 * @param  signature                    A pointer to a destination buffer to store the signature.
 * @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
 *                                     On output, indicates the size in bytes of the signature in the buffer.
 *
 * @retval TRUE  signing success.
 * @retval FALSE signing fail.
 **/
boolean libspdm_requester_data_sign(
    IN spdm_version_number_t spdm_version,
    IN uint8_t op_code,
    IN uint16_t req_base_asym_alg,
    IN uint32_t base_hash_algo, IN boolean is_data_hash,
    IN const uint8_t *message, IN uintn message_size,
    OUT uint8_t *signature, IN OUT uintn *sig_size);

/**
 * Sign an SPDM message data.
 *
 * @param  base_asym_algo                 Indicates the signing algorithm.
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  is_data_hash                   Indicate the message type. TRUE: raw message before hash, FALSE: message hash.
 * @param  message                      A pointer to a message to be signed.
 * @param  message_size                  The size in bytes of the message to be signed.
 * @param  signature                    A pointer to a destination buffer to store the signature.
 * @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
 *                                     On output, indicates the size in bytes of the signature in the buffer.
 *
 * @retval TRUE  signing success.
 * @retval FALSE signing fail.
 **/
boolean libspdm_responder_data_sign(
    IN spdm_version_number_t spdm_version,
    IN uint8_t op_code,
    IN uint32_t base_asym_algo,
    IN uint32_t base_hash_algo, IN boolean is_data_hash,
    IN const uint8_t *message, IN uintn message_size,
    OUT uint8_t *signature, IN OUT uintn *sig_size);

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
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 **/
boolean libspdm_psk_handshake_secret_hkdf_expand(
    IN spdm_version_number_t spdm_version,
    IN uint32_t base_hash_algo, IN const uint8_t *psk_hint,
    OPTIONAL IN uintn psk_hint_size, OPTIONAL IN const uint8_t *info,
    IN uintn info_size, OUT uint8_t *out, IN uintn out_size);

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
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 **/
boolean libspdm_psk_master_secret_hkdf_expand(
    IN spdm_version_number_t spdm_version,
    IN uint32_t base_hash_algo,
    IN const uint8_t *psk_hint,
    OPTIONAL IN uintn psk_hint_size,
    OPTIONAL IN const uint8_t *info,
    IN uintn info_size, OUT uint8_t *out,
    IN uintn out_size);

#endif
