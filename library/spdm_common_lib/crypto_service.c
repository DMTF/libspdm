/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_common_lib_internal.h"

/**
  This function returns peer certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer including spdm_cert_chain_t header is returned.
  @retval FALSE Peer certificate chain buffer including spdm_cert_chain_t header is not found.
**/
boolean spdm_get_peer_cert_chain_buffer(IN void *context,
					OUT void **cert_chain_buffer,
					OUT uintn *cert_chain_buffer_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	if (spdm_context->connection_info.peer_used_cert_chain_buffer_size !=
	    0) {
		*cert_chain_buffer = spdm_context->connection_info
					     .peer_used_cert_chain_buffer;
		*cert_chain_buffer_size =
			spdm_context->connection_info
				.peer_used_cert_chain_buffer_size;
		return TRUE;
	}
	if (spdm_context->local_context.peer_cert_chain_provision_size != 0) {
		*cert_chain_buffer =
			spdm_context->local_context.peer_cert_chain_provision;
		*cert_chain_buffer_size =
			spdm_context->local_context
				.peer_cert_chain_provision_size;
		return TRUE;
	}
	return FALSE;
}

/**
  This function returns peer certificate chain data without spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.

  @retval TRUE  Peer certificate chain data without spdm_cert_chain_t header is returned.
  @retval FALSE Peer certificate chain data without spdm_cert_chain_t header is not found.
**/
boolean spdm_get_peer_cert_chain_data(IN void *context,
				      OUT void **cert_chain_data,
				      OUT uintn *cert_chain_data_size)
{
	spdm_context_t *spdm_context;
	boolean result;
	uintn hash_size;

	spdm_context = context;

	result = spdm_get_peer_cert_chain_buffer(spdm_context, cert_chain_data,
						 cert_chain_data_size);
	if (!result) {
		return FALSE;
	}

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	*cert_chain_data = (uint8 *)*cert_chain_data +
			   sizeof(spdm_cert_chain_t) + hash_size;
	*cert_chain_data_size =
		*cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);
	return TRUE;
}

/**
  This function returns local used certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Local used certificate chain buffer including spdm_cert_chain_t header is returned.
  @retval FALSE Local used certificate chain buffer including spdm_cert_chain_t header is not found.
**/
boolean spdm_get_local_cert_chain_buffer(IN void *context,
					 OUT void **cert_chain_buffer,
					 OUT uintn *cert_chain_buffer_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	if (spdm_context->connection_info.local_used_cert_chain_buffer_size !=
	    0) {
		*cert_chain_buffer = spdm_context->connection_info
					     .local_used_cert_chain_buffer;
		*cert_chain_buffer_size =
			spdm_context->connection_info
				.local_used_cert_chain_buffer_size;
		return TRUE;
	}
	return FALSE;
}

/**
  This function returns local used certificate chain data without spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.

  @retval TRUE  Local used certificate chain data without spdm_cert_chain_t header is returned.
  @retval FALSE Local used certificate chain data without spdm_cert_chain_t header is not found.
**/
boolean spdm_get_local_cert_chain_data(IN void *context,
				       OUT void **cert_chain_data,
				       OUT uintn *cert_chain_data_size)
{
	spdm_context_t *spdm_context;
	boolean result;
	uintn hash_size;

	spdm_context = context;

	result = spdm_get_local_cert_chain_buffer(spdm_context, cert_chain_data,
						  cert_chain_data_size);
	if (!result) {
		return FALSE;
	}

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	*cert_chain_data = (uint8 *)*cert_chain_data +
			   sizeof(spdm_cert_chain_t) + hash_size;
	*cert_chain_data_size =
		*cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);
	return TRUE;
}

/*
  This function calculates m1m2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_mut                        Indicate if this is from mutual authentication.
  @param  m1m2_buffer_size               size in bytes of the m1m2
  @param  m1m2_buffer                   The buffer to store the m1m2

  @retval RETURN_SUCCESS  m1m2 is calculated.
*/
boolean spdm_calculate_m1m2(IN void *context, IN boolean is_mut,
			    IN OUT uintn *m1m2_buffer_size,
			    OUT void *m1m2_buffer)
{
	spdm_context_t *spdm_context;
	return_status status;
	uint32 hash_size;
	uint8 hash_data[MAX_HASH_SIZE];
	large_managed_buffer_t m1m2;

	spdm_context = context;

	init_managed_buffer(&m1m2, MAX_SPDM_MESSAGE_BUFFER_SIZE);

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	if (is_mut) {
		DEBUG((DEBUG_INFO, "message_mut_b data :\n"));
		internal_dump_hex(
			get_managed_buffer(
				&spdm_context->transcript.message_mut_b),
			get_managed_buffer_size(
				&spdm_context->transcript.message_mut_b));
		status = append_managed_buffer(
			&m1m2,
			get_managed_buffer(
				&spdm_context->transcript.message_mut_b),
			get_managed_buffer_size(
				&spdm_context->transcript.message_mut_b));
		if (RETURN_ERROR(status)) {
			return FALSE;
		}

		DEBUG((DEBUG_INFO, "message_mut_c data :\n"));
		internal_dump_hex(
			get_managed_buffer(
				&spdm_context->transcript.message_mut_c),
			get_managed_buffer_size(
				&spdm_context->transcript.message_mut_c));
		status = append_managed_buffer(
			&m1m2,
			get_managed_buffer(
				&spdm_context->transcript.message_mut_c),
			get_managed_buffer_size(
				&spdm_context->transcript.message_mut_c));
		if (RETURN_ERROR(status)) {
			return FALSE;
		}

		// debug only
		spdm_hash_all(
			spdm_context->connection_info.algorithm.bash_hash_algo,
			get_managed_buffer(&m1m2),
			get_managed_buffer_size(&m1m2), hash_data);
		DEBUG((DEBUG_INFO, "m1m2 Mut hash - "));
		internal_dump_data(hash_data, hash_size);
		DEBUG((DEBUG_INFO, "\n"));

	} else {
		DEBUG((DEBUG_INFO, "message_a data :\n"));
		internal_dump_hex(
			get_managed_buffer(&spdm_context->transcript.message_a),
			get_managed_buffer_size(
				&spdm_context->transcript.message_a));
		status = append_managed_buffer(
			&m1m2,
			get_managed_buffer(&spdm_context->transcript.message_a),
			get_managed_buffer_size(
				&spdm_context->transcript.message_a));
		if (RETURN_ERROR(status)) {
			return FALSE;
		}

		DEBUG((DEBUG_INFO, "message_b data :\n"));
		internal_dump_hex(
			get_managed_buffer(&spdm_context->transcript.message_b),
			get_managed_buffer_size(
				&spdm_context->transcript.message_b));
		status = append_managed_buffer(
			&m1m2,
			get_managed_buffer(&spdm_context->transcript.message_b),
			get_managed_buffer_size(
				&spdm_context->transcript.message_b));
		if (RETURN_ERROR(status)) {
			return FALSE;
		}

		DEBUG((DEBUG_INFO, "message_c data :\n"));
		internal_dump_hex(
			get_managed_buffer(&spdm_context->transcript.message_c),
			get_managed_buffer_size(
				&spdm_context->transcript.message_c));
		status = append_managed_buffer(
			&m1m2,
			get_managed_buffer(&spdm_context->transcript.message_c),
			get_managed_buffer_size(
				&spdm_context->transcript.message_c));
		if (RETURN_ERROR(status)) {
			return FALSE;
		}

		// debug only
		spdm_hash_all(
			spdm_context->connection_info.algorithm.bash_hash_algo,
			get_managed_buffer(&m1m2),
			get_managed_buffer_size(&m1m2), hash_data);
		DEBUG((DEBUG_INFO, "m1m2 hash - "));
		internal_dump_data(hash_data, hash_size);
		DEBUG((DEBUG_INFO, "\n"));
	}

	*m1m2_buffer_size = get_managed_buffer_size(&m1m2);
	copy_mem(m1m2_buffer, get_managed_buffer(&m1m2), *m1m2_buffer_size);

	return TRUE;
}

/*
  This function calculates l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  l1l2_buffer_size               size in bytes of the l1l2
  @param  l1l2_buffer                   The buffer to store the l1l2

  @retval RETURN_SUCCESS  l1l2 is calculated.
*/
boolean spdm_calculate_l1l2(IN void *context, IN OUT uintn *l1l2_buffer_size,
			    OUT void *l1l2_buffer)
{
	spdm_context_t *spdm_context;
	uint32 hash_size;
	uint8 hash_data[MAX_HASH_SIZE];

	spdm_context = context;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	DEBUG((DEBUG_INFO, "message_m data :\n"));
	internal_dump_hex(
		get_managed_buffer(&spdm_context->transcript.message_m),
		get_managed_buffer_size(&spdm_context->transcript.message_m));

	// debug only
	spdm_hash_all(
		spdm_context->connection_info.algorithm.bash_hash_algo,
		get_managed_buffer(&spdm_context->transcript.message_m),
		get_managed_buffer_size(&spdm_context->transcript.message_m),
		hash_data);
	DEBUG((DEBUG_INFO, "l1l2 hash - "));
	internal_dump_data(hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	*l1l2_buffer_size =
		get_managed_buffer_size(&spdm_context->transcript.message_m);
	copy_mem(l1l2_buffer,
		 get_managed_buffer(&spdm_context->transcript.message_m),
		 *l1l2_buffer_size);

	return TRUE;
}

/**
  This function generates the certificate chain hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                    The slot index of the certificate chain.
  @param  signature                    The buffer to store the certificate chain hash.

  @retval TRUE  certificate chain hash is generated.
  @retval FALSE certificate chain hash is not generated.
**/
boolean spdm_generate_cert_chain_hash(IN spdm_context_t *spdm_context,
				      IN uintn slot_id, OUT uint8 *hash)
{
	ASSERT(slot_id < spdm_context->local_context.slot_count);
	spdm_hash_all(
		spdm_context->connection_info.algorithm.bash_hash_algo,
		spdm_context->local_context.local_cert_chain_provision[slot_id],
		spdm_context->local_context
			.local_cert_chain_provision_size[slot_id],
		hash);
	return TRUE;
}

/**
  This function verifies the digest.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  digest                       The digest data buffer.
  @param  digest_size                   size in bytes of the digest data buffer.

  @retval TRUE  digest verification pass.
  @retval FALSE digest verification fail.
**/
boolean spdm_verify_peer_digests(IN spdm_context_t *spdm_context,
				 IN void *digest, IN uintn digest_size)
{
	uintn hash_size;
	uint8 cert_chain_buffer_hash[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;

	cert_chain_buffer =
		spdm_context->local_context.peer_cert_chain_provision;
	cert_chain_buffer_size =
		spdm_context->local_context.peer_cert_chain_provision_size;
	if ((cert_chain_buffer != NULL) && (cert_chain_buffer_size != 0)) {
		hash_size = spdm_get_hash_size(
			spdm_context->connection_info.algorithm.bash_hash_algo);
		spdm_hash_all(
			spdm_context->connection_info.algorithm.bash_hash_algo,
			cert_chain_buffer, cert_chain_buffer_size,
			cert_chain_buffer_hash);

		if (const_compare_mem(digest, cert_chain_buffer_hash, hash_size) !=
		    0) {
			DEBUG((DEBUG_INFO,
			       "!!! verify_peer_digests - FAIL !!!\n"));
			return FALSE;
		}
	}

	DEBUG((DEBUG_INFO, "!!! verify_peer_digests - PASS !!!\n"));

	return TRUE;
}

/**
  This function verifies peer certificate chain buffer including spdm_cert_chain_t header.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer verification passed.
  @retval FALSE Peer certificate chain buffer verification failed.
**/
boolean spdm_verify_peer_cert_chain_buffer(IN spdm_context_t *spdm_context,
					   IN void *cert_chain_buffer,
					   IN uintn cert_chain_buffer_size)
{
	uint8 *cert_chain_data;
	uintn cert_chain_data_size;
	uintn hash_size;
	uint8 *root_cert_hash;
	uintn root_cert_hash_size;
	boolean result;

	result = spdm_verify_certificate_chain_buffer(
		spdm_context->connection_info.algorithm.bash_hash_algo,
		cert_chain_buffer, cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	root_cert_hash =
		spdm_context->local_context.peer_root_cert_hash_provision;
	root_cert_hash_size =
		spdm_context->local_context.peer_root_cert_hash_provision_size;
	cert_chain_data = spdm_context->local_context.peer_cert_chain_provision;
	cert_chain_data_size =
		spdm_context->local_context.peer_cert_chain_provision_size;

	if ((root_cert_hash != NULL) && (root_cert_hash_size != 0)) {
		hash_size = spdm_get_hash_size(
			spdm_context->connection_info.algorithm.bash_hash_algo);
		if (root_cert_hash_size != hash_size) {
			DEBUG((DEBUG_INFO,
			       "!!! verify_peer_cert_chain_buffer - FAIL (hash size mismatch) !!!\n"));
			return FALSE;
		}
		if (const_compare_mem((uint8 *)cert_chain_buffer +
					sizeof(spdm_cert_chain_t),
				root_cert_hash, hash_size) != 0) {
			DEBUG((DEBUG_INFO,
			       "!!! verify_peer_cert_chain_buffer - FAIL (root hash mismatch) !!!\n"));
			return FALSE;
		}
	} else if ((cert_chain_data != NULL) && (cert_chain_data_size != 0)) {
		if (cert_chain_data_size != cert_chain_buffer_size) {
			DEBUG((DEBUG_INFO,
			       "!!! verify_peer_cert_chain_buffer - FAIL !!!\n"));
			return FALSE;
		}
		if (const_compare_mem(cert_chain_buffer, cert_chain_data,
				cert_chain_buffer_size) != 0) {
			DEBUG((DEBUG_INFO,
			       "!!! verify_peer_cert_chain_buffer - FAIL !!!\n"));
			return FALSE;
		}
	}

	DEBUG((DEBUG_INFO, "!!! verify_peer_cert_chain_buffer - PASS !!!\n"));

	return TRUE;
}

/**
  This function generates the challenge signature based upon m1m2 for authentication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Indicate of the signature generation for a requester or a responder.
  @param  signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
boolean spdm_generate_challenge_auth_signature(IN spdm_context_t *spdm_context,
					       IN boolean is_requester,
					       OUT uint8 *signature)
{
	boolean result;
	uintn signature_size;
	uint8 m1m2_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn m1m2_buffer_size;

	m1m2_buffer_size = sizeof(m1m2_buffer);
	result = spdm_calculate_m1m2(spdm_context, is_requester,
				     &m1m2_buffer_size, &m1m2_buffer);
	if (!result) {
		return FALSE;
	}

	if (is_requester) {
		signature_size = spdm_get_req_asym_signature_size(
			spdm_context->connection_info.algorithm
				.req_base_asym_alg);
		result = spdm_requester_data_sign(
			spdm_context->connection_info.algorithm
				.req_base_asym_alg,
			spdm_context->connection_info.algorithm.bash_hash_algo,
			m1m2_buffer, m1m2_buffer_size, signature,
			&signature_size);
	} else {
		signature_size = spdm_get_asym_signature_size(
			spdm_context->connection_info.algorithm.base_asym_algo);
		result = spdm_responder_data_sign(
			spdm_context->connection_info.algorithm.base_asym_algo,
			spdm_context->connection_info.algorithm.bash_hash_algo,
			m1m2_buffer, m1m2_buffer_size, signature,
			&signature_size);
	}

	return result;
}

/**
  This function verifies the certificate chain hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  certificate_chain_hash         The certificate chain hash data buffer.
  @param  certificate_chain_hash_size     size in bytes of the certificate chain hash data buffer.

  @retval TRUE  hash verification pass.
  @retval FALSE hash verification fail.
**/
boolean spdm_verify_certificate_chain_hash(IN spdm_context_t *spdm_context,
					   IN void *certificate_chain_hash,
					   IN uintn certificate_chain_hash_size)
{
	uintn hash_size;
	uint8 cert_chain_buffer_hash[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	boolean result;

	result = spdm_get_peer_cert_chain_buffer(spdm_context,
						 (void **)&cert_chain_buffer,
						 &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	spdm_hash_all(spdm_context->connection_info.algorithm.bash_hash_algo,
		      cert_chain_buffer, cert_chain_buffer_size,
		      cert_chain_buffer_hash);

	if (hash_size != certificate_chain_hash_size) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_certificate_chain_hash - FAIL !!!\n"));
		return FALSE;
	}
	if (const_compare_mem(certificate_chain_hash, cert_chain_buffer_hash,
			certificate_chain_hash_size) != 0) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_certificate_chain_hash - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_certificate_chain_hash - PASS !!!\n"));
	return TRUE;
}

/**
  This function verifies the challenge signature based upon m1m2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Indicate of the signature verification for a requester or a responder.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_challenge_auth_signature(IN spdm_context_t *spdm_context,
					     IN boolean is_requester,
					     IN void *sign_data,
					     IN uintn sign_data_size)
{
	boolean result;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	void *context;
	uint8 *cert_chain_data;
	uintn cert_chain_data_size;
	uint8 m1m2_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn m1m2_buffer_size;

	m1m2_buffer_size = sizeof(m1m2_buffer);
	result = spdm_calculate_m1m2(spdm_context, !is_requester,
				     &m1m2_buffer_size, &m1m2_buffer);
	if (!result) {
		return FALSE;
	}

	result = spdm_get_peer_cert_chain_data(
		spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
	if (!result) {
		return FALSE;
	}

	//
	// Get leaf cert from cert chain
	//
	result = x509_get_cert_from_cert_chain(cert_chain_data,
					       cert_chain_data_size, -1,
					       &cert_buffer, &cert_buffer_size);
	if (!result) {
		return FALSE;
	}

	if (is_requester) {
		result = spdm_asym_get_public_key_from_x509(
			spdm_context->connection_info.algorithm.base_asym_algo,
			cert_buffer, cert_buffer_size, &context);
		if (!result) {
			return FALSE;
		}

		result = spdm_asym_verify(
			spdm_context->connection_info.algorithm.base_asym_algo,
			spdm_context->connection_info.algorithm.bash_hash_algo,
			context, m1m2_buffer, m1m2_buffer_size, sign_data,
			sign_data_size);
		spdm_asym_free(
			spdm_context->connection_info.algorithm.base_asym_algo,
			context);
	} else {
		result = spdm_req_asym_get_public_key_from_x509(
			spdm_context->connection_info.algorithm
				.req_base_asym_alg,
			cert_buffer, cert_buffer_size, &context);
		if (!result) {
			return FALSE;
		}

		result = spdm_req_asym_verify(
			spdm_context->connection_info.algorithm
				.req_base_asym_alg,
			spdm_context->connection_info.algorithm.bash_hash_algo,
			context, m1m2_buffer, m1m2_buffer_size, sign_data,
			sign_data_size);
		spdm_req_asym_free(spdm_context->connection_info.algorithm
					   .req_base_asym_alg,
				   context);
	}

	if (!result) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_challenge_signature - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_challenge_signature - PASS !!!\n"));

	return TRUE;
}

/**
  This function calculate the measurement summary hash size.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  measurement_summary_hash_type   The type of the measurement summary hash.

  @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
  @return measurement summary hash size according to type.
**/
uint32
spdm_get_measurement_summary_hash_size(IN spdm_context_t *spdm_context,
				       IN boolean is_requester,
				       IN uint8 measurement_summary_hash_type)
{
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, is_requester, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
		return 0;
	}

	switch (measurement_summary_hash_type) {
	case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
		return 0;
		break;

	case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
	case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
		return spdm_get_hash_size(
			spdm_context->connection_info.algorithm.bash_hash_algo);
		break;
	}

	return 0;
}

/**
  This function calculate the measurement summary hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  measurement_summary_hash_type   The type of the measurement summary hash.
  @param  measurement_summary_hash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated or skipped.
  @retval FALSE measurement summary hash is not generated.
**/
boolean
spdm_generate_measurement_summary_hash(IN spdm_context_t *spdm_context,
				       IN boolean is_requester,
				       IN uint8 measurement_summary_hash_type,
				       OUT uint8 *measurement_summary_hash)
{
	uint8 measurement_data[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	uintn index;
	spdm_measurement_block_dmtf_t *cached_measurment_block;
	uintn measurment_data_size;
	uintn measurment_block_size;
	uint8 device_measurement[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	uint8 device_measurement_count;
	uintn device_measurement_size;
	boolean ret;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, is_requester, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
		return TRUE;
	}

	switch (measurement_summary_hash_type) {
	case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
		break;

	case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
	case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
		// get all measurement data
		device_measurement_size = sizeof(device_measurement);
		ret = spdm_measurement_collection(
			spdm_context->connection_info.algorithm.measurement_spec,
			spdm_context->connection_info.algorithm
				.measurement_hash_algo,
			&device_measurement_count, device_measurement,
			&device_measurement_size);
		if (!ret) {
			return ret;
		}

		ASSERT(device_measurement_count <=
		       MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

		// double confirm that MeasurmentData internal size is correct
		measurment_data_size = 0;
		cached_measurment_block = (void *)device_measurement;
		for (index = 0; index < device_measurement_count; index++) {
			measurment_block_size =
				sizeof(spdm_measurement_block_common_header_t) +
				cached_measurment_block
					->Measurement_block_common_header
					.measurement_size;
			ASSERT(cached_measurment_block
				       ->Measurement_block_common_header
				       .measurement_size ==
			       sizeof(spdm_measurement_block_dmtf_header_t) +
				       cached_measurment_block
					       ->Measurement_block_dmtf_header
					       .dmtf_spec_measurement_value_size);
			measurment_data_size +=
				cached_measurment_block
					->Measurement_block_common_header
					.measurement_size;
			cached_measurment_block =
				(void *)((uintn)cached_measurment_block +
					 measurment_block_size);
		}

		ASSERT(measurment_data_size <=
		       MAX_SPDM_MEASUREMENT_RECORD_SIZE);

		// get required data and hash them
		cached_measurment_block = (void *)device_measurement;
		measurment_data_size = 0;
		for (index = 0; index < device_measurement_count; index++) {
			measurment_block_size =
				sizeof(spdm_measurement_block_common_header_t) +
				cached_measurment_block
					->Measurement_block_common_header
					.measurement_size;
			// filter unneeded data
			if (((measurement_summary_hash_type ==
			      SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH) &&
			     ((cached_measurment_block
				       ->Measurement_block_dmtf_header
				       .dmtf_spec_measurement_value_type &
			       SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) <
			      SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST)) ||
			    ((cached_measurment_block
				      ->Measurement_block_dmtf_header
				      .dmtf_spec_measurement_value_type &
			      SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
			     SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
				copy_mem(
					&measurement_data[measurment_data_size],
					&cached_measurment_block
						 ->Measurement_block_dmtf_header,
					cached_measurment_block
						->Measurement_block_common_header
						.measurement_size);
			}
			measurment_data_size +=
				cached_measurment_block
					->Measurement_block_common_header
					.measurement_size;
			cached_measurment_block =
				(void *)((uintn)cached_measurment_block +
					 measurment_block_size);
		}
		spdm_hash_all(
			spdm_context->connection_info.algorithm.bash_hash_algo,
			measurement_data, measurment_data_size,
			measurement_summary_hash);
		break;
	default:
		return FALSE;
		break;
	}
	return TRUE;
}

/**
  This function generates the measurement signature to response message based upon l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  signature                    The buffer to store the signature.

  @retval TRUE  measurement signature is generated.
  @retval FALSE measurement signature is not generated.
**/
boolean spdm_generate_measurement_signature(IN spdm_context_t *spdm_context,
					    OUT uint8 *signature)
{
	uintn signature_size;
	boolean result;
	uint8 l1l2_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn l1l2_buffer_size;

	l1l2_buffer_size = sizeof(l1l2_buffer);
	result = spdm_calculate_l1l2(spdm_context, &l1l2_buffer_size,
				     l1l2_buffer);
	if (!result) {
		return FALSE;
	}

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	result = spdm_responder_data_sign(
		spdm_context->connection_info.algorithm.base_asym_algo,
		spdm_context->connection_info.algorithm.bash_hash_algo,
		l1l2_buffer, l1l2_buffer_size, signature, &signature_size);
	return result;
}

/**
  This function verifies the measurement signature based upon l1l2.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_measurement_signature(IN spdm_context_t *spdm_context,
					  IN void *sign_data,
					  IN uintn sign_data_size)
{
	boolean result;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	void *context;
	uint8 *cert_chain_data;
	uintn cert_chain_data_size;
	uint8 l1l2_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn l1l2_buffer_size;

	l1l2_buffer_size = sizeof(l1l2_buffer);
	result = spdm_calculate_l1l2(spdm_context, &l1l2_buffer_size,
				     l1l2_buffer);
	if (!result) {
		return FALSE;
	}

	result = spdm_get_peer_cert_chain_data(
		spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
	if (!result) {
		return FALSE;
	}

	//
	// Get leaf cert from cert chain
	//
	result = x509_get_cert_from_cert_chain(cert_chain_data,
					       cert_chain_data_size, -1,
					       &cert_buffer, &cert_buffer_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_asym_get_public_key_from_x509(
		spdm_context->connection_info.algorithm.base_asym_algo,
		cert_buffer, cert_buffer_size, &context);
	if (!result) {
		return FALSE;
	}

	result = spdm_asym_verify(
		spdm_context->connection_info.algorithm.base_asym_algo,
		spdm_context->connection_info.algorithm.bash_hash_algo, context,
		l1l2_buffer, l1l2_buffer_size, sign_data, sign_data_size);
	spdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
		       context);
	if (!result) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_measurement_signature - FAIL !!!\n"));
		return FALSE;
	}

	DEBUG((DEBUG_INFO, "!!! verify_measurement_signature - PASS !!!\n"));
	return TRUE;
}
