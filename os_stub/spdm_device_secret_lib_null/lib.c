/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SPDM common library.
  It follows the SPDM Specification.
**/

#include <library/spdm_device_secret_lib.h>

/**
  Collect the device measurement.

  @param  measurement_specification     Indicates the measurement specification.
                                       It must align with measurement_specification (SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_*)
  @param  measurement_hash_algo          Indicates the measurement hash algorithm.
                                       It must align with measurement_hash_algo (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
  @param  device_measurement_count       The count of the device measurement block.
  @param  device_measurement            A pointer to a destination buffer to store the concatenation of all device measurement blocks.
  @param  device_measurement_size        On input, indicates the size in bytes of the destination buffer.
                                       On output, indicates the size in bytes of all device measurement blocks in the buffer.

  @retval TRUE  the device measurement collection success and measurement is returned.
  @retval FALSE the device measurement collection fail.
**/
boolean spdm_measurement_collection(
				    IN spdm_version_number_t spdm_version,
				    IN uint8 measurement_specification,
				    IN uint32 measurement_hash_algo,
				    OUT uint8 *device_measurement_count,
				    OUT void *device_measurement,
				    IN OUT uintn *device_measurement_size)
{
	return FALSE;
}

/**
  Sign an SPDM message data.

  @param  req_base_asym_alg               Indicates the signing algorithm.
  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  is_data_hash                   Indicate the message type. TRUE: raw message before hash, FALSE: message hash.
  @param  message                      A pointer to a message to be signed.
  @param  message_size                  The size in bytes of the message to be signed.
  @param  signature                    A pointer to a destination buffer to store the signature.
  @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
boolean spdm_requester_data_sign(
				 IN spdm_version_number_t spdm_version, IN uint8 op_code,
				 IN uint16 req_base_asym_alg,
				 IN uint32 base_hash_algo, IN boolean is_data_hash,
				 IN const uint8 *message, IN uintn message_size,
				 OUT uint8 *signature, IN OUT uintn *sig_size)
{
	return FALSE;
}

/**
  Sign an SPDM message data.

  @param  base_asym_algo                 Indicates the signing algorithm.
  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  is_data_hash                   Indicate the message type. TRUE: raw message before hash, FALSE: message hash.
  @param  message                      A pointer to a message to be signed.
  @param  message_size                  The size in bytes of the message to be signed.
  @param  signature                    A pointer to a destination buffer to store the signature.
  @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
boolean spdm_responder_data_sign(
				 IN spdm_version_number_t spdm_version, IN uint8 op_code,
				 IN uint32 base_asym_algo,
				 IN uint32 base_hash_algo, IN boolean is_data_hash,
				 IN const uint8 *message, IN uintn message_size,
				 OUT uint8 *signature, IN OUT uintn *sig_size)
{
	return FALSE;
}

/**
  Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  psk_hint                      Pointer to the user-supplied PSK Hint.
  @param  psk_hint_size                  PSK Hint size in bytes.
  @param  info                         Pointer to the application specific info.
  @param  info_size                     info size in bytes.
  @param  out                          Pointer to buffer to receive hkdf value.
  @param  out_size                      size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
boolean spdm_psk_handshake_secret_hkdf_expand(
					      IN spdm_version_number_t spdm_version,
					      IN uint32 base_hash_algo,
					      IN const uint8 *psk_hint,
					      OPTIONAL IN uintn psk_hint_size,
					      OPTIONAL IN const uint8 *info,
					      IN uintn info_size,
					      OUT uint8 *out, IN uintn out_size)
{
	return FALSE;
}

/**
  Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  psk_hint                      Pointer to the user-supplied PSK Hint.
  @param  psk_hint_size                  PSK Hint size in bytes.
  @param  info                         Pointer to the application specific info.
  @param  info_size                     info size in bytes.
  @param  out                          Pointer to buffer to receive hkdf value.
  @param  out_size                      size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
boolean spdm_psk_master_secret_hkdf_expand(
					   IN spdm_version_number_t spdm_version,
					   IN uint32 base_hash_algo,
					   IN const uint8 *psk_hint,
					   OPTIONAL IN uintn psk_hint_size,
					   OPTIONAL IN const uint8 *info,
					   IN uintn info_size, OUT uint8 *out,
					   IN uintn out_size)
{
	return FALSE;
}
