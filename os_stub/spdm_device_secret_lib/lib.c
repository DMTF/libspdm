/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SPDM common library.
  It follows the SPDM Specification.
**/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#undef NULL
#include <base.h>
#include <library/memlib.h>
#include "spdm_device_secret_lib_internal.h"

boolean read_responder_private_certificate(IN uint32 base_asym_algo,
					   OUT void **data, OUT uintn *size)
{
	boolean res;
	char8 *file;

	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
		file = "rsa2048/end_responder.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
		file = "rsa3072/end_responder.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		file = "ecp256/end_responder.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		file = "ecp384/end_responder.key";
		break;
	default:
		ASSERT(FALSE);
		return FALSE;
	}
	res = read_input_file(file, data, size);
	return res;
}

boolean read_requester_private_certificate(IN uint16 req_base_asym_alg,
					   OUT void **data, OUT uintn *size)
{
	boolean res;
	char8 *file;

	switch (req_base_asym_alg) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
		file = "rsa2048/end_requester.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
		file = "rsa3072/end_requester.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		file = "ecp256/end_requester.key";
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		file = "ecp384/end_requester.key";
		break;
	default:
		ASSERT(FALSE);
		return FALSE;
	}
	res = read_input_file(file, data, size);
	return res;
}

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
boolean spdm_measurement_collection(IN uint8 measurement_specification,
				    IN uint32 measurement_hash_algo,
				    OUT uint8 *device_measurement_count,
				    OUT void *device_measurement,
				    IN OUT uintn *device_measurement_size)
{
	spdm_measurement_block_dmtf_t *MeasurementBlock;
	uintn hash_size;
	uint8 index;
	uint8 data[MEASUREMENT_MANIFEST_SIZE];
	uintn total_size;

	ASSERT(measurement_specification ==
	       SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
	if (measurement_specification !=
	    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
		return FALSE;
	}

	hash_size = spdm_get_measurement_hash_size(measurement_hash_algo);
	ASSERT(hash_size != 0);

	*device_measurement_count = MEASUREMENT_BLOCK_NUMBER;
	if (hash_size != 0xFFFFFFFF) {
		total_size =
			(MEASUREMENT_BLOCK_NUMBER - 1) *
				(sizeof(spdm_measurement_block_dmtf_t) +
				 hash_size) +
			(sizeof(spdm_measurement_block_dmtf_t) + sizeof(data));
	} else {
		total_size =
			(MEASUREMENT_BLOCK_NUMBER - 1) *
				(sizeof(spdm_measurement_block_dmtf_t) +
				 sizeof(data)) +
			(sizeof(spdm_measurement_block_dmtf_t) + sizeof(data));
	}
	ASSERT(*device_measurement_size >= total_size);
	*device_measurement_size = total_size;

	MeasurementBlock = device_measurement;
	for (index = 0; index < MEASUREMENT_BLOCK_NUMBER; index++) {
		MeasurementBlock->Measurement_block_common_header.index =
			index + 1;
		MeasurementBlock->Measurement_block_common_header
			.measurement_specification =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		if ((index < 4) && (hash_size != 0xFFFFFFFF)) {
			MeasurementBlock->Measurement_block_dmtf_header
				.dmtf_spec_measurement_value_type = index;
			MeasurementBlock->Measurement_block_dmtf_header
				.dmtf_spec_measurement_value_size =
				(uint16)hash_size;
		} else {
			MeasurementBlock->Measurement_block_dmtf_header
				.dmtf_spec_measurement_value_type =
				index |
				SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
			MeasurementBlock->Measurement_block_dmtf_header
				.dmtf_spec_measurement_value_size =
				(uint16)sizeof(data);
		}
		MeasurementBlock->Measurement_block_common_header
			.measurement_size =
			(uint16)(sizeof(spdm_measurement_block_dmtf_header_t) +
				 MeasurementBlock->Measurement_block_dmtf_header
					 .dmtf_spec_measurement_value_size);
		set_mem(data, sizeof(data), (uint8)(index + 1));
		if ((index < 4) && (hash_size != 0xFFFFFFFF)) {
			spdm_measurement_hash_all(
				measurement_hash_algo, data, sizeof(data),
				(void *)(MeasurementBlock + 1));
			MeasurementBlock =
				(void *)((uint8 *)MeasurementBlock +
					 sizeof(spdm_measurement_block_dmtf_t) +
					 hash_size);
		} else {
			copy_mem((void *)(MeasurementBlock + 1), data,
				 sizeof(data));
			MeasurementBlock =
				(void *)((uint8 *)MeasurementBlock +
					 sizeof(spdm_measurement_block_dmtf_t) +
					 sizeof(data));
		}
	}

	return TRUE;
}

/**
  Sign an SPDM message data.

  @param  req_base_asym_alg               Indicates the signing algorithm.
  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  message                      A pointer to a message to be signed (before hash).
  @param  message_size                  The size in bytes of the message to be signed.
  @param  signature                    A pointer to a destination buffer to store the signature.
  @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
boolean spdm_requester_data_sign(IN uint16 req_base_asym_alg,
				 IN uint32 base_hash_algo, IN boolean is_data_hash,
				 IN const uint8 *message, IN uintn message_size,
				 OUT uint8 *signature, IN OUT uintn *sig_size)
{
	void *context;
	void *private_pem;
	uintn private_pem_size;
	boolean result;

	result = read_requester_private_certificate(
		req_base_asym_alg, &private_pem, &private_pem_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_req_asym_get_private_key_from_pem(req_base_asym_alg,
							private_pem,
							private_pem_size, NULL,
							&context);
	if (!result) {
		return FALSE;
	}
	if (is_data_hash) {
		result = spdm_req_asym_sign_hash(req_base_asym_alg, base_hash_algo, context,
						message, message_size, signature, sig_size);
	} else {
		result = spdm_req_asym_sign(req_base_asym_alg, base_hash_algo, context,
						message, message_size, signature, sig_size);
	}
	spdm_req_asym_free(req_base_asym_alg, context);
	free(private_pem);

	return result;
}

/**
  Sign an SPDM message data.

  @param  base_asym_algo                 Indicates the signing algorithm.
  @param  base_hash_algo                 Indicates the hash algorithm.
  @param  message                      A pointer to a message to be signed (before hash).
  @param  message_size                  The size in bytes of the message to be signed.
  @param  signature                    A pointer to a destination buffer to store the signature.
  @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
boolean spdm_responder_data_sign(IN uint32 base_asym_algo,
				 IN uint32 base_hash_algo, IN boolean is_data_hash,
				 IN const uint8 *message, IN uintn message_size,
				 OUT uint8 *signature, IN OUT uintn *sig_size)
{
	void *context;
	void *private_pem;
	uintn private_pem_size;
	boolean result;

	result = read_responder_private_certificate(
		base_asym_algo, &private_pem, &private_pem_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_asym_get_private_key_from_pem(
		base_asym_algo, private_pem, private_pem_size, NULL, &context);
	if (!result) {
		return FALSE;
	}
	if (is_data_hash) {
		result = spdm_asym_sign_hash(base_asym_algo, base_hash_algo, context,
					message, message_size, signature, sig_size);
	} else {
		result = spdm_asym_sign(base_asym_algo, base_hash_algo, context,
					message, message_size, signature, sig_size);
	}
	spdm_asym_free(base_asym_algo, context);
	free(private_pem);

	return result;
}

uint8 m_my_zero_filled_buffer[64];
uint8 m_bin_str0[0x11] = {
	0x00, 0x00, // length - to be filled
	0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20, // version: 'spdm1.1 '
	0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, // label: 'derived'
};

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
boolean spdm_psk_handshake_secret_hkdf_expand(IN uint32 base_hash_algo,
					      IN const uint8 *psk_hint,
					      OPTIONAL IN uintn psk_hint_size,
					      OPTIONAL IN const uint8 *info,
					      IN uintn info_size,
					      OUT uint8 *out, IN uintn out_size)
{
	void *psk;
	uintn psk_size;
	uintn hash_size;
	boolean result;
	uint8 handshake_secret[64];

	if ((psk_hint == NULL) && (psk_hint_size == 0)) {
		psk = TEST_PSK_DATA_STRING;
		psk_size = sizeof(TEST_PSK_DATA_STRING);
	} else if ((psk_hint != NULL) && (psk_hint_size != 0) &&
		   (strcmp((const char *)psk_hint, TEST_PSK_HINT_STRING) ==
		    0) &&
		   (psk_hint_size == sizeof(TEST_PSK_HINT_STRING))) {
		psk = TEST_PSK_DATA_STRING;
		psk_size = sizeof(TEST_PSK_DATA_STRING);
	} else {
		return FALSE;
	}
	printf("[PSK]: ");
	dump_hex_str(psk, psk_size);
	printf("\n");

	hash_size = spdm_get_hash_size(base_hash_algo);

	result = spdm_hmac_all(base_hash_algo, m_my_zero_filled_buffer,
			       hash_size, psk, psk_size, handshake_secret);
	if (!result) {
		return result;
	}

	result = spdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
				  info, info_size, out, out_size);
	zero_mem(handshake_secret, hash_size);

	return result;
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
boolean spdm_psk_master_secret_hkdf_expand(IN uint32 base_hash_algo,
					   IN const uint8 *psk_hint,
					   OPTIONAL IN uintn psk_hint_size,
					   OPTIONAL IN const uint8 *info,
					   IN uintn info_size, OUT uint8 *out,
					   IN uintn out_size)
{
	void *psk;
	uintn psk_size;
	uintn hash_size;
	boolean result;
	uint8 handshake_secret[64];
	uint8 salt1[64];
	uint8 master_secret[64];

	if ((psk_hint == NULL) && (psk_hint_size == 0)) {
		psk = TEST_PSK_DATA_STRING;
		psk_size = sizeof(TEST_PSK_DATA_STRING);
	} else if ((psk_hint != NULL) && (psk_hint_size != 0) &&
		   (strcmp((const char *)psk_hint, TEST_PSK_HINT_STRING) ==
		    0) &&
		   (psk_hint_size == sizeof(TEST_PSK_HINT_STRING))) {
		psk = TEST_PSK_DATA_STRING;
		psk_size = sizeof(TEST_PSK_DATA_STRING);
	} else {
		return FALSE;
	}

	hash_size = spdm_get_hash_size(base_hash_algo);

	result = spdm_hmac_all(base_hash_algo, m_my_zero_filled_buffer,
			       hash_size, psk, psk_size, handshake_secret);
	if (!result) {
		return result;
	}

	*(uint16 *)m_bin_str0 = (uint16)hash_size;
	result = spdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
				  m_bin_str0, sizeof(m_bin_str0), salt1,
				  hash_size);
	zero_mem(handshake_secret, hash_size);
	if (!result) {
		return result;
	}

	result = spdm_hmac_all(base_hash_algo, m_my_zero_filled_buffer,
			       hash_size, salt1, hash_size, master_secret);
	zero_mem(salt1, hash_size);
	if (!result) {
		return result;
	}

	result = spdm_hkdf_expand(base_hash_algo, master_secret, hash_size,
				  info, info_size, out, out_size);
	zero_mem(master_secret, hash_size);

	return result;
}
