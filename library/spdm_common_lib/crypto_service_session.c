/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_common_lib_internal.h"

/*
  This function calculates current TH data with message A and message K.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
  @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean spdm_calculate_th_for_exchange(
	IN void *context, IN void *spdm_session_info, IN uint8 *cert_chain_buffer,
	OPTIONAL IN uintn cert_chain_buffer_size,
	OPTIONAL IN OUT uintn *th_data_buffer_size, OUT void *th_data_buffer)
{
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
	uint8 cert_chain_buffer_hash[MAX_HASH_SIZE];
	uint32 hash_size;
	return_status status;
	large_managed_buffer_t th_curr;

	spdm_context = context;
	session_info = spdm_session_info;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	ASSERT(*th_data_buffer_size >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

	DEBUG((DEBUG_INFO, "message_a data :\n"));
	internal_dump_hex(
		get_managed_buffer(&spdm_context->transcript.message_a),
		get_managed_buffer_size(&spdm_context->transcript.message_a));
	status = append_managed_buffer(
		&th_curr,
		get_managed_buffer(&spdm_context->transcript.message_a),
		get_managed_buffer_size(&spdm_context->transcript.message_a));
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	if (cert_chain_buffer != NULL) {
		DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
		internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
		spdm_hash_all(
			spdm_context->connection_info.algorithm.base_hash_algo,
			cert_chain_buffer, cert_chain_buffer_size,
			cert_chain_buffer_hash);
		status = append_managed_buffer(&th_curr, cert_chain_buffer_hash,
					       hash_size);
		if (RETURN_ERROR(status)) {
			return FALSE;
		}
	}

	DEBUG((DEBUG_INFO, "message_k data :\n"));
	internal_dump_hex(
		get_managed_buffer(&session_info->session_transcript.message_k),
		get_managed_buffer_size(
			&session_info->session_transcript.message_k));
	status = append_managed_buffer(
		&th_curr,
		get_managed_buffer(&session_info->session_transcript.message_k),
		get_managed_buffer_size(
			&session_info->session_transcript.message_k));
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	*th_data_buffer_size = get_managed_buffer_size(&th_curr);
	copy_mem(th_data_buffer, get_managed_buffer(&th_curr),
		 *th_data_buffer_size);

	return TRUE;
}

/*
  This function calculates current TH data with message A, message K and message F.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
  @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
  @param  mut_cert_chain_buffer             Certitiface chain buffer with spdm_cert_chain_t header in mutual authentication.
  @param  mut_cert_chain_buffer_size         size in bytes of the certitiface chain buffer in mutual authentication.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean spdm_calculate_th_for_finish(IN void *context,
				     IN void *spdm_session_info,
				     IN uint8 *cert_chain_buffer,
				     OPTIONAL IN uintn cert_chain_buffer_size,
				     OPTIONAL IN uint8 *mut_cert_chain_buffer,
				     OPTIONAL IN uintn mut_cert_chain_buffer_size,
				     OPTIONAL IN OUT uintn *th_data_buffer_size,
				     OUT void *th_data_buffer)
{
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
	uint8 cert_chain_buffer_hash[MAX_HASH_SIZE];
	uint8 mut_cert_chain_buffer_hash[MAX_HASH_SIZE];
	uint32 hash_size;
	return_status status;
	large_managed_buffer_t th_curr;

	spdm_context = context;
	session_info = spdm_session_info;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	ASSERT(*th_data_buffer_size >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

	DEBUG((DEBUG_INFO, "message_a data :\n"));
	internal_dump_hex(
		get_managed_buffer(&spdm_context->transcript.message_a),
		get_managed_buffer_size(&spdm_context->transcript.message_a));
	status = append_managed_buffer(
		&th_curr,
		get_managed_buffer(&spdm_context->transcript.message_a),
		get_managed_buffer_size(&spdm_context->transcript.message_a));
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	if (cert_chain_buffer != NULL) {
		DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
		internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
		spdm_hash_all(
			spdm_context->connection_info.algorithm.base_hash_algo,
			cert_chain_buffer, cert_chain_buffer_size,
			cert_chain_buffer_hash);
		status = append_managed_buffer(&th_curr, cert_chain_buffer_hash,
					       hash_size);
		if (RETURN_ERROR(status)) {
			return FALSE;
		}
	}

	DEBUG((DEBUG_INFO, "message_k data :\n"));
	internal_dump_hex(
		get_managed_buffer(&session_info->session_transcript.message_k),
		get_managed_buffer_size(
			&session_info->session_transcript.message_k));
	status = append_managed_buffer(
		&th_curr,
		get_managed_buffer(&session_info->session_transcript.message_k),
		get_managed_buffer_size(
			&session_info->session_transcript.message_k));
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	if (mut_cert_chain_buffer != NULL) {
		DEBUG((DEBUG_INFO, "th_message_cm data :\n"));
		internal_dump_hex(mut_cert_chain_buffer,
				  mut_cert_chain_buffer_size);
		spdm_hash_all(
			spdm_context->connection_info.algorithm.base_hash_algo,
			mut_cert_chain_buffer, mut_cert_chain_buffer_size,
			mut_cert_chain_buffer_hash);
		status = append_managed_buffer(&th_curr, mut_cert_chain_buffer_hash,
					       hash_size);
		if (RETURN_ERROR(status)) {
			return FALSE;
		}
	}

	DEBUG((DEBUG_INFO, "message_f data :\n"));
	internal_dump_hex(
		get_managed_buffer(&session_info->session_transcript.message_f),
		get_managed_buffer_size(
			&session_info->session_transcript.message_f));
	status = append_managed_buffer(
		&th_curr,
		get_managed_buffer(&session_info->session_transcript.message_f),
		get_managed_buffer_size(
			&session_info->session_transcript.message_f));
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	*th_data_buffer_size = get_managed_buffer_size(&th_curr);
	copy_mem(th_data_buffer, get_managed_buffer(&th_curr),
		 *th_data_buffer_size);

	return TRUE;
}

/**
  This function generates the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_signature(IN spdm_context_t *spdm_context,
					 IN spdm_session_info_t *session_info,
					 OUT uint8 *signature)
{
	uint8 hash_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	boolean result;
	uintn signature_size;
	uint32 hash_size;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_local_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	// debug only
	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, hash_data);
	DEBUG((DEBUG_INFO, "th_curr hash - "));
	internal_dump_data(hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	result = spdm_responder_data_sign(
		spdm_context->connection_info.algorithm.base_asym_algo,
		spdm_context->connection_info.algorithm.base_hash_algo,
		th_curr_data, th_curr_data_size, signature, &signature_size);
	if (result) {
		DEBUG((DEBUG_INFO, "signature - "));
		internal_dump_data(signature, signature_size);
		DEBUG((DEBUG_INFO, "\n"));
	}
	return result;
}

/**
  This function generates the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT uint8 *hmac)
{
	uint8 hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint32 hash_size;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;
	boolean result;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_local_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	copy_mem(hmac, hmac_data, hash_size);

	return TRUE;
}

/**
  This function verifies the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_key_exchange_rsp_signature(
	IN spdm_context_t *spdm_context, IN spdm_session_info_t *session_info,
	IN void *sign_data, IN intn sign_data_size)
{
	uintn hash_size;
	uint8 hash_data[MAX_HASH_SIZE];
	boolean result;
	uint8 *cert_chain_data;
	uintn cert_chain_data_size;
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	void *context;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_peer_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	// debug only
	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, hash_data);
	DEBUG((DEBUG_INFO, "th_curr hash - "));
	internal_dump_data(hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	DEBUG((DEBUG_INFO, "signature - "));
	internal_dump_data(sign_data, sign_data_size);
	DEBUG((DEBUG_INFO, "\n"));

	//
	// Get leaf cert from cert chain
	//
	result = spdm_get_peer_cert_chain_data(
		spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
	if (!result) {
		return FALSE;
	}
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
		spdm_context->connection_info.algorithm.base_hash_algo, context,
		th_curr_data, th_curr_data_size, sign_data, sign_data_size);
	spdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
		       context);
	if (!result) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_key_exchange_signature - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature - PASS !!!\n"));

	return TRUE;
}

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
					  IN spdm_session_info_t *session_info,
					  IN void *hmac_data,
					  IN uintn hmac_data_size)
{
	uintn hash_size;
	uint8 calc_hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	ASSERT(hash_size == hmac_data_size);

	result = spdm_get_peer_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, calc_hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(calc_hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_key_exchange_hmac - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_key_exchange_hmac - PASS !!!\n"));

	return TRUE;
}

/**
  This function generates the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
boolean spdm_generate_finish_req_signature(IN spdm_context_t *spdm_context,
					   IN spdm_session_info_t *session_info,
					   OUT uint8 *signature)
{
	uint8 hash_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	boolean result;
	uintn signature_size;
	uint32 hash_size;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	signature_size = spdm_get_req_asym_signature_size(
		spdm_context->connection_info.algorithm.req_base_asym_alg);
	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_peer_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_get_local_cert_chain_buffer(spdm_context,
						(void **)&mut_cert_chain_buffer,
						&mut_cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	// debug only
	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, hash_data);
	DEBUG((DEBUG_INFO, "th_curr hash - "));
	internal_dump_data(hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	result = spdm_requester_data_sign(
		spdm_context->connection_info.algorithm.req_base_asym_alg,
		spdm_context->connection_info.algorithm.base_hash_algo,
		th_curr_data, th_curr_data_size, signature, &signature_size);
	if (result) {
		DEBUG((DEBUG_INFO, "signature - "));
		internal_dump_data(signature, signature_size);
		DEBUG((DEBUG_INFO, "\n"));
	}

	return result;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_req_hmac(IN spdm_context_t *spdm_context,
				      IN spdm_session_info_t *session_info,
				      OUT void *hmac)
{
	uintn hash_size;
	uint8 calc_hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_peer_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	if (session_info->mut_auth_requested) {
		result = spdm_get_local_cert_chain_buffer(
			spdm_context, (void **)&mut_cert_chain_buffer,
			&mut_cert_chain_buffer_size);
		if (!result) {
			return FALSE;
		}
	} else {
		mut_cert_chain_buffer = NULL;
		mut_cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_request_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, calc_hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(calc_hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	copy_mem(hmac, calc_hmac_data, hash_size);

	return TRUE;
}

/**
  This function verifies the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_finish_req_signature(IN spdm_context_t *spdm_context,
					 IN spdm_session_info_t *session_info,
					 IN void *sign_data,
					 IN intn sign_data_size)
{
	uintn hash_size;
	uint8 hash_data[MAX_HASH_SIZE];
	boolean result;
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_data;
	uintn mut_cert_chain_data_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	uint8 *mut_cert_buffer;
	uintn mut_cert_buffer_size;
	void *context;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_local_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_get_peer_cert_chain_buffer(spdm_context,
					       (void **)&mut_cert_chain_buffer,
					       &mut_cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	// debug only
	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, hash_data);
	DEBUG((DEBUG_INFO, "th_curr hash - "));
	internal_dump_data(hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	DEBUG((DEBUG_INFO, "signature - "));
	internal_dump_data(sign_data, sign_data_size);
	DEBUG((DEBUG_INFO, "\n"));

	//
	// Get leaf cert from cert chain
	//
	result = spdm_get_peer_cert_chain_data(spdm_context,
					       (void **)&mut_cert_chain_data,
					       &mut_cert_chain_data_size);
	if (!result) {
		return FALSE;
	}
	result = x509_get_cert_from_cert_chain(mut_cert_chain_data,
					       mut_cert_chain_data_size, -1,
					       &mut_cert_buffer,
					       &mut_cert_buffer_size);
	if (!result) {
		return FALSE;
	}

	result = spdm_req_asym_get_public_key_from_x509(
		spdm_context->connection_info.algorithm.req_base_asym_alg,
		mut_cert_buffer, mut_cert_buffer_size, &context);
	if (!result) {
		return FALSE;
	}

	result = spdm_req_asym_verify(
		spdm_context->connection_info.algorithm.req_base_asym_alg,
		spdm_context->connection_info.algorithm.base_hash_algo, context,
		th_curr_data, th_curr_data_size, sign_data, sign_data_size);
	spdm_req_asym_free(
		spdm_context->connection_info.algorithm.req_base_asym_alg,
		context);
	if (!result) {
		DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

	return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_req_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    IN uint8 *hmac, IN uintn hmac_size)
{
	uint8 hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	uintn hash_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	ASSERT(hmac_size == hash_size);

	result = spdm_get_local_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	if (session_info->mut_auth_requested) {
		result = spdm_get_peer_cert_chain_buffer(
			spdm_context, (void **)&mut_cert_chain_buffer,
			&mut_cert_chain_buffer_size);
		if (!result) {
			return FALSE;
		}
	} else {
		mut_cert_chain_buffer = NULL;
		mut_cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_request_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	if (const_compare_mem(hmac, hmac_data, hash_size) != 0) {
		DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - PASS !!!\n"));
	return TRUE;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_rsp_hmac(IN spdm_context_t *spdm_context,
				      IN spdm_session_info_t *session_info,
				      OUT uint8 *hmac)
{
	uint8 hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	uint32 hash_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	result = spdm_get_local_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	if (session_info->mut_auth_requested) {
		result = spdm_get_peer_cert_chain_buffer(
			spdm_context, (void **)&mut_cert_chain_buffer,
			&mut_cert_chain_buffer_size);
		if (!result) {
			return FALSE;
		}
	} else {
		mut_cert_chain_buffer = NULL;
		mut_cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	copy_mem(hmac, hmac_data, hash_size);

	return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    IN void *hmac_data, IN uintn hmac_data_size)
{
	uintn hash_size;
	uint8 calc_hmac_data[MAX_HASH_SIZE];
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	ASSERT(hash_size == hmac_data_size);

	result = spdm_get_peer_cert_chain_buffer(
		spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
	if (!result) {
		return FALSE;
	}

	if (session_info->mut_auth_requested) {
		result = spdm_get_local_cert_chain_buffer(
			spdm_context, (void **)&mut_cert_chain_buffer,
			&mut_cert_chain_buffer_size);
		if (!result) {
			return FALSE;
		}
	} else {
		mut_cert_chain_buffer = NULL;
		mut_cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, calc_hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(calc_hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
		DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - PASS !!!\n"));

	return TRUE;
}

/**
  This function generates the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT uint8 *hmac)
{
	uint8 hmac_data[MAX_HASH_SIZE];
	uint32 hash_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(spdm_context, session_info,
						NULL, 0, &th_curr_data_size,
						th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	copy_mem(hmac, hmac_data, hash_size);

	return TRUE;
}

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
					  IN spdm_session_info_t *session_info,
					  IN void *hmac_data,
					  IN uintn hmac_data_size)
{
	uintn hash_size;
	uint8 calc_hmac_data[MAX_HASH_SIZE];
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	ASSERT(hash_size == hmac_data_size);

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(spdm_context, session_info,
						NULL, 0, &th_curr_data_size,
						th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_response_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, calc_hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(calc_hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_psk_exchange_rsp_hmac - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_psk_exchange_rsp_hmac - PASS !!!\n"));

	return TRUE;
}

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_req_hmac(IN spdm_context_t *spdm_context,
				    IN spdm_session_info_t *session_info,
				    OUT void *hmac)
{
	uintn hash_size;
	uint8 calc_hmac_data[MAX_HASH_SIZE];
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(spdm_context, session_info, NULL,
					      0, NULL, 0, &th_curr_data_size,
					      th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_request_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, calc_hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "th_curr hmac - "));
	internal_dump_data(calc_hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	copy_mem(hmac, calc_hmac_data, hash_size);

	return TRUE;
}

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_finish_req_hmac(IN spdm_context_t *spdm_context,
					IN spdm_session_info_t *session_info,
					IN uint8 *hmac, IN uintn hmac_size)
{
	uint8 hmac_data[MAX_HASH_SIZE];
	uint32 hash_size;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	ASSERT(hmac_size == hash_size);

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(spdm_context, session_info, NULL,
					      0, NULL, 0, &th_curr_data_size,
					      th_curr_data);
	if (!result) {
		return FALSE;
	}

	result = spdm_hmac_all_with_request_finished_key(
		session_info->secured_message_context, th_curr_data,
		th_curr_data_size, hmac_data);
	if (!result) {
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "Calc th_curr hmac - "));
	internal_dump_data(hmac_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	if (const_compare_mem(hmac, hmac_data, hash_size) != 0) {
		DEBUG((DEBUG_INFO,
		       "!!! verify_psk_finish_req_hmac - FAIL !!!\n"));
		return FALSE;
	}
	DEBUG((DEBUG_INFO, "!!! verify_psk_finish_req_hmac - PASS !!!\n"));
	return TRUE;
}

/*
  This function calculates th1 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  th1 hash is calculated.
*/
return_status spdm_calculate_th1_hash(IN void *context,
				      IN void *spdm_session_info,
				      IN boolean is_requester,
				      OUT uint8 *th1_hash_data)
{
	spdm_context_t *spdm_context;
	uintn hash_size;
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	spdm_session_info_t *session_info;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	spdm_context = context;

	DEBUG((DEBUG_INFO, "Calc th1 hash ...\n"));

	session_info = spdm_session_info;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	if (!session_info->use_psk) {
		if (is_requester) {
			result = spdm_get_peer_cert_chain_buffer(
				spdm_context, (void **)&cert_chain_buffer,
				&cert_chain_buffer_size);
		} else {
			result = spdm_get_local_cert_chain_buffer(
				spdm_context, (void **)&cert_chain_buffer,
				&cert_chain_buffer_size);
		}
		if (!result) {
			return RETURN_UNSUPPORTED;
		}
	} else {
		cert_chain_buffer = NULL;
		cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_exchange(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, th1_hash_data);
	DEBUG((DEBUG_INFO, "th1 hash - "));
	internal_dump_data(th1_hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	return RETURN_SUCCESS;
}

/*
  This function calculates th2 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th2 hash

  @retval RETURN_SUCCESS  th2 hash is calculated.
*/
return_status spdm_calculate_th2_hash(IN void *context,
				      IN void *spdm_session_info,
				      IN boolean is_requester,
				      OUT uint8 *th2_hash_data)
{
	spdm_context_t *spdm_context;
	uintn hash_size;
	uint8 *cert_chain_buffer;
	uintn cert_chain_buffer_size;
	uint8 *mut_cert_chain_buffer;
	uintn mut_cert_chain_buffer_size;
	spdm_session_info_t *session_info;
	boolean result;
	uint8 th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn th_curr_data_size;

	spdm_context = context;

	DEBUG((DEBUG_INFO, "Calc th2 hash ...\n"));

	session_info = spdm_session_info;

	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	if (!session_info->use_psk) {
		if (is_requester) {
			result = spdm_get_peer_cert_chain_buffer(
				spdm_context, (void **)&cert_chain_buffer,
				&cert_chain_buffer_size);
		} else {
			result = spdm_get_local_cert_chain_buffer(
				spdm_context, (void **)&cert_chain_buffer,
				&cert_chain_buffer_size);
		}
		if (!result) {
			return RETURN_UNSUPPORTED;
		}
		if (session_info->mut_auth_requested) {
			if (is_requester) {
				result = spdm_get_local_cert_chain_buffer(
					spdm_context,
					(void **)&mut_cert_chain_buffer,
					&mut_cert_chain_buffer_size);
			} else {
				result = spdm_get_peer_cert_chain_buffer(
					spdm_context,
					(void **)&mut_cert_chain_buffer,
					&mut_cert_chain_buffer_size);
			}
			if (!result) {
				return RETURN_UNSUPPORTED;
			}
		} else {
			mut_cert_chain_buffer = NULL;
			mut_cert_chain_buffer_size = 0;
		}
	} else {
		cert_chain_buffer = NULL;
		cert_chain_buffer_size = 0;
		mut_cert_chain_buffer = NULL;
		mut_cert_chain_buffer_size = 0;
	}

	th_curr_data_size = sizeof(th_curr_data);
	result = spdm_calculate_th_for_finish(
		spdm_context, session_info, cert_chain_buffer,
		cert_chain_buffer_size, mut_cert_chain_buffer,
		mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
	if (!result) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
		      th_curr_data, th_curr_data_size, th2_hash_data);
	DEBUG((DEBUG_INFO, "th2 hash - "));
	internal_dump_data(th2_hash_data, hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	return RETURN_SUCCESS;
}
