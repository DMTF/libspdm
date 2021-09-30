/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_common_lib_internal.h"

/**
  Returns if an SPDM data_type requires session info.

  @param data_type  SPDM data type.

  @retval TRUE  session info is required.
  @retval FALSE session info is not required.
**/
boolean need_session_info_for_data(IN spdm_data_type_t data_type)
{
	switch (data_type) {
	case SPDM_DATA_SESSION_USE_PSK:
	case SPDM_DATA_SESSION_MUT_AUTH_REQUESTED:
	case SPDM_DATA_SESSION_END_SESSION_ATTRIBUTES:
		return TRUE;
	default:
		return FALSE;
	}
}

/**
  Set an SPDM context data.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  data_type                     Type of the SPDM context data.
  @param  parameter                    Type specific parameter of the SPDM context data.
  @param  data                         A pointer to the SPDM context data.
  @param  data_size                     size in bytes of the SPDM context data.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The data is NULL or the data_type is zero.
  @retval RETURN_UNSUPPORTED           The data_type is unsupported.
  @retval RETURN_ACCESS_DENIED         The data_type cannot be set.
  @retval RETURN_NOT_READY             data is not ready to set.
**/
return_status spdm_set_data(IN void *context, IN spdm_data_type_t data_type,
			    IN spdm_data_parameter_t *parameter, IN void *data,
			    IN uintn data_size)
{
	spdm_context_t *spdm_context;
	uint32 session_id;
	spdm_session_info_t *session_info;
	uint8 slot_id;
	uint8 mut_auth_requested;

	if (!context || !data || data_type >= SPDM_DATA_MAX) {
		return RETURN_INVALID_PARAMETER;
	}

	spdm_context = context;

	if (need_session_info_for_data(data_type)) {
		if (parameter->location != SPDM_DATA_LOCATION_SESSION) {
			return RETURN_INVALID_PARAMETER;
		}
		session_id = *(uint32 *)parameter->additional_data;
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_INVALID_PARAMETER;
		}
	} else {
		session_info = NULL;
	}

	switch (data_type) {
	case SPDM_DATA_SPDM_VERSION:
		if (data_size >
		    sizeof(spdm_version_number_t) * MAX_SPDM_VERSION_COUNT) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			if ((uint8)(data_size /sizeof(spdm_version_number_t)) != 1) {
				/* Only have one connected version */
				return RETURN_INVALID_PARAMETER;
			}
			copy_mem(
				 &(spdm_context->connection_info.version),
				 data,
				 sizeof(spdm_version_number_t));
		} else {
			spdm_context->local_context.version.spdm_version_count =
				(uint8)(data_size /
					sizeof(spdm_version_number_t));
			copy_mem(
				spdm_context->local_context.version.spdm_version,
				data,
				spdm_context->local_context.version
						.spdm_version_count *
					sizeof(spdm_version_number_t));
		}
		break;
	case SPDM_DATA_SECURED_MESSAGE_VERSION:
		if (data_size >
		    sizeof(spdm_version_number_t) * MAX_SPDM_VERSION_COUNT) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.secured_message_version
				.spdm_version_count = (uint8)(
				data_size / sizeof(spdm_version_number_t));
			copy_mem(spdm_context->connection_info
					 .secured_message_version.spdm_version,
				 data,
				 spdm_context->connection_info
						 .secured_message_version
						 .spdm_version_count *
					 sizeof(spdm_version_number_t));
		} else {
			spdm_context->local_context.secured_message_version
				.spdm_version_count = (uint8)(
				data_size / sizeof(spdm_version_number_t));
			copy_mem(spdm_context->local_context
					 .secured_message_version.spdm_version,
				 data,
				 spdm_context->local_context
						 .secured_message_version
						 .spdm_version_count *
					 sizeof(spdm_version_number_t));
		}
		break;
	case SPDM_DATA_CAPABILITY_FLAGS:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.capability.flags =
				*(uint32 *)data;
		} else {
			spdm_context->local_context.capability.flags =
				*(uint32 *)data;
		}
		break;
	case SPDM_DATA_CAPABILITY_CT_EXPONENT:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context.capability.ct_exponent =
			*(uint8 *)data;
		break;
	case SPDM_DATA_MEASUREMENT_SPEC:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm
				.measurement_spec = *(uint8 *)data;
		} else {
			spdm_context->local_context.algorithm.measurement_spec =
				*(uint8 *)data;
		}
		break;
	case SPDM_DATA_MEASUREMENT_HASH_ALGO:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm
				.measurement_hash_algo = *(uint32 *)data;
		} else {
			spdm_context->local_context.algorithm
				.measurement_hash_algo = *(uint32 *)data;
		}
		break;
	case SPDM_DATA_BASE_ASYM_ALGO:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm.base_asym_algo =
				*(uint32 *)data;
		} else {
			spdm_context->local_context.algorithm.base_asym_algo =
				*(uint32 *)data;
		}
		break;
	case SPDM_DATA_BASE_HASH_ALGO:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm.base_hash_algo =
				*(uint32 *)data;
		} else {
			spdm_context->local_context.algorithm.base_hash_algo =
				*(uint32 *)data;
		}
		break;
	case SPDM_DATA_DHE_NAME_GROUP:
		if (data_size != sizeof(uint16)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm.dhe_named_group =
				*(uint16 *)data;
		} else {
			spdm_context->local_context.algorithm.dhe_named_group =
				*(uint16 *)data;
		}
		break;
	case SPDM_DATA_AEAD_CIPHER_SUITE:
		if (data_size != sizeof(uint16)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm
				.aead_cipher_suite = *(uint16 *)data;
		} else {
			spdm_context->local_context.algorithm.aead_cipher_suite =
				*(uint16 *)data;
		}
		break;
	case SPDM_DATA_REQ_BASE_ASYM_ALG:
		if (data_size != sizeof(uint16)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm
				.req_base_asym_alg = *(uint16 *)data;
		} else {
			spdm_context->local_context.algorithm.req_base_asym_alg =
				*(uint16 *)data;
		}
		break;
	case SPDM_DATA_KEY_SCHEDULE:
		if (data_size != sizeof(uint16)) {
			return RETURN_INVALID_PARAMETER;
		}
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			spdm_context->connection_info.algorithm.key_schedule =
				*(uint16 *)data;
		} else {
			spdm_context->local_context.algorithm.key_schedule =
				*(uint16 *)data;
		}
		break;
	case SPDM_DATA_CONNECTION_STATE:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->connection_info.connection_state =
			*(uint32 *)data;
		break;
	case SPDM_DATA_RESPONSE_STATE:
		if (data_size != sizeof(uint32)) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->response_state = *(uint32 *)data;
		break;
	case SPDM_DATA_PEER_PUBLIC_ROOT_CERT:
		spdm_context->local_context.peer_root_cert_provision_size =
			data_size;
		spdm_context->local_context.peer_root_cert_provision =
			data;
		break;
	case SPDM_DATA_PEER_PUBLIC_CERT_CHAIN:
		spdm_context->local_context.peer_cert_chain_provision_size =
			data_size;
		spdm_context->local_context.peer_cert_chain_provision = data;
		break;
	case SPDM_DATA_LOCAL_SLOT_COUNT:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		slot_id = *(uint8 *)data;
		if (slot_id > MAX_SPDM_SLOT_COUNT) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context.slot_count = slot_id;
		break;
	case SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN:
		slot_id = parameter->additional_data[0];
		if (slot_id >= spdm_context->local_context.slot_count) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context
			.local_cert_chain_provision_size[slot_id] = data_size;
		spdm_context->local_context.local_cert_chain_provision[slot_id] =
			data;
		break;
	case SPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER:
		if (data_size > MAX_SPDM_CERT_CHAIN_SIZE) {
			return RETURN_OUT_OF_RESOURCES;
		}
		spdm_context->connection_info.local_used_cert_chain_buffer_size =
			data_size;
		spdm_context->connection_info.local_used_cert_chain_buffer =
			data;
		break;
	case SPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER:
		if (data_size > MAX_SPDM_CERT_CHAIN_SIZE) {
			return RETURN_OUT_OF_RESOURCES;
		}
		spdm_context->connection_info.peer_used_cert_chain_buffer_size =
			data_size;
		copy_mem(spdm_context->connection_info
				 .peer_used_cert_chain_buffer,
			 data, data_size);
		break;
	case SPDM_DATA_BASIC_MUT_AUTH_REQUESTED:
		if (data_size != sizeof(boolean)) {
			return RETURN_INVALID_PARAMETER;
		}
		mut_auth_requested = *(uint8 *)data;
		if (((mut_auth_requested != 0) && (mut_auth_requested != 1))) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context.basic_mut_auth_requested =
			mut_auth_requested;
		spdm_context->encap_context.error_state = 0;
		spdm_context->encap_context.request_id = 0;
		spdm_context->encap_context.req_slot_id =
			parameter->additional_data[0];
		break;
	case SPDM_DATA_MUT_AUTH_REQUESTED:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		mut_auth_requested = *(uint8 *)data;
		if (((mut_auth_requested != 0) &&
		     (mut_auth_requested !=
		      SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED) &&
		     (mut_auth_requested !=
		      SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) &&
		     (mut_auth_requested !=
		      SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS))) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context.mut_auth_requested =
			mut_auth_requested;
		spdm_context->encap_context.error_state = 0;
		spdm_context->encap_context.request_id = 0;
		spdm_context->encap_context.req_slot_id =
			parameter->additional_data[0];
		break;
	case SPDM_DATA_PSK_HINT:
		if (data_size > MAX_SPDM_PSK_HINT_LENGTH) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->local_context.psk_hint_size = data_size;
		spdm_context->local_context.psk_hint = data;
		break;
	case SPDM_DATA_SESSION_USE_PSK:
		if (data_size != sizeof(boolean)) {
			return RETURN_INVALID_PARAMETER;
		}
		session_info->use_psk = *(boolean *)data;
		break;
	case SPDM_DATA_SESSION_MUT_AUTH_REQUESTED:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		session_info->mut_auth_requested = *(uint8 *)data;
		break;
	case SPDM_DATA_SESSION_END_SESSION_ATTRIBUTES:
		if (data_size != sizeof(uint8)) {
			return RETURN_INVALID_PARAMETER;
		}
		session_info->end_session_attributes = *(uint8 *)data;
		break;
	case SPDM_DATA_OPAQUE_CONTEXT_DATA:
		if (data_size != sizeof(void *) || *(void **)data == NULL) {
			return RETURN_INVALID_PARAMETER;
		}
		spdm_context->opaque_context_data_ptr = *(void **)data;
		break;
	default:
		return RETURN_UNSUPPORTED;
		break;
	}

	return RETURN_SUCCESS;
}

/**
  Get an SPDM context data.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  data_type                     Type of the SPDM context data.
  @param  parameter                    Type specific parameter of the SPDM context data.
  @param  data                         A pointer to the SPDM context data.
  @param  data_size                     size in bytes of the SPDM context data.
                                       On input, it means the size in bytes of data buffer.
                                       On output, it means the size in bytes of copied data buffer if RETURN_SUCCESS,
                                       and means the size in bytes of desired data buffer if RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The data_size is NULL or the data is NULL and *data_size is not zero.
  @retval RETURN_UNSUPPORTED           The data_type is unsupported.
  @retval RETURN_NOT_FOUND             The data_type cannot be found.
  @retval RETURN_NOT_READY             The data is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status spdm_get_data(IN void *context, IN spdm_data_type_t data_type,
			    IN spdm_data_parameter_t *parameter,
			    IN OUT void *data, IN OUT uintn *data_size)
{
	spdm_context_t *spdm_context;
	uintn target_data_size;
	void *target_data;
	uint32 session_id;
	spdm_session_info_t *session_info;

	if (!context || !data || !data_size || data_type >= SPDM_DATA_MAX) {
		return RETURN_INVALID_PARAMETER;
	}

	spdm_context = context;

	if (need_session_info_for_data(data_type)) {
		if (parameter->location != SPDM_DATA_LOCATION_SESSION) {
			return RETURN_INVALID_PARAMETER;
		}
		session_id = *(uint32 *)parameter->additional_data;
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_INVALID_PARAMETER;
		}
	} else {
		session_info = NULL;
	}

	switch (data_type) {
	case SPDM_DATA_SPDM_VERSION:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(spdm_version_number_t);
		target_data =
			&(spdm_context->connection_info.version);
		break;
	case SPDM_DATA_SECURED_MESSAGE_VERSION:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size =
			spdm_context->connection_info.secured_message_version
				.spdm_version_count *
			sizeof(spdm_version_number_t);
		target_data = spdm_context->connection_info
				      .secured_message_version.spdm_version;
		break;
	case SPDM_DATA_CAPABILITY_FLAGS:
		target_data_size = sizeof(uint32);
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			target_data =
				&spdm_context->connection_info.capability.flags;
		} else {
			target_data =
				&spdm_context->local_context.capability.flags;
		}
		break;
	case SPDM_DATA_CAPABILITY_CT_EXPONENT:
		target_data_size = sizeof(uint8);
		if (parameter->location == SPDM_DATA_LOCATION_CONNECTION) {
			target_data = &spdm_context->connection_info.capability
					       .ct_exponent;
		} else {
			target_data = &spdm_context->local_context.capability
					       .ct_exponent;
		}
		break;
	case SPDM_DATA_MEASUREMENT_SPEC:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint8);
		target_data = &spdm_context->connection_info.algorithm
				       .measurement_spec;
		break;
	case SPDM_DATA_MEASUREMENT_HASH_ALGO:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint32);
		target_data = &spdm_context->connection_info.algorithm
				       .measurement_hash_algo;
		break;
	case SPDM_DATA_BASE_ASYM_ALGO:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint32);
		target_data =
			&spdm_context->connection_info.algorithm.base_asym_algo;
		break;
	case SPDM_DATA_BASE_HASH_ALGO:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint32);
		target_data =
			&spdm_context->connection_info.algorithm.base_hash_algo;
		break;
	case SPDM_DATA_DHE_NAME_GROUP:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint16);
		target_data =
			&spdm_context->connection_info.algorithm.dhe_named_group;
		break;
	case SPDM_DATA_AEAD_CIPHER_SUITE:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint16);
		target_data = &spdm_context->connection_info.algorithm
				       .aead_cipher_suite;
		break;
	case SPDM_DATA_REQ_BASE_ASYM_ALG:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint16);
		target_data = &spdm_context->connection_info.algorithm
				       .req_base_asym_alg;
		break;
	case SPDM_DATA_KEY_SCHEDULE:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint16);
		target_data =
			&spdm_context->connection_info.algorithm.key_schedule;
		break;
	case SPDM_DATA_CONNECTION_STATE:
		if (parameter->location != SPDM_DATA_LOCATION_CONNECTION) {
			return RETURN_INVALID_PARAMETER;
		}
		target_data_size = sizeof(uint32);
		target_data = &spdm_context->connection_info.connection_state;
		break;
	case SPDM_DATA_RESPONSE_STATE:
		target_data_size = sizeof(uint32);
		target_data = &spdm_context->response_state;
		break;
	case SPDM_DATA_SESSION_USE_PSK:
		target_data_size = sizeof(boolean);
		target_data = &session_info->use_psk;
		break;
	case SPDM_DATA_SESSION_MUT_AUTH_REQUESTED:
		target_data_size = sizeof(uint8);
		target_data = &session_info->mut_auth_requested;
		break;
	case SPDM_DATA_SESSION_END_SESSION_ATTRIBUTES:
		target_data_size = sizeof(uint8);
		target_data = &session_info->end_session_attributes;
		break;
	case SPDM_DATA_OPAQUE_CONTEXT_DATA:
		target_data_size = sizeof(void *);
		target_data = &spdm_context->opaque_context_data_ptr;
		break;
	default:
		return RETURN_UNSUPPORTED;
		break;
	}

	if (*data_size < target_data_size) {
		*data_size = target_data_size;
		return RETURN_BUFFER_TOO_SMALL;
	}
	*data_size = target_data_size;
	copy_mem(data, target_data, target_data_size);

	return RETURN_SUCCESS;
}

/**
  Reset message A cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_a(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	reset_managed_buffer(&spdm_context->transcript.message_a);
}

/**
  Reset message B cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_b(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_context->transcript.message_b);
#else
	if (spdm_context->transcript.digest_context_m1m2 != NULL) {
		spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2);
		spdm_context->transcript.digest_context_m1m2 = NULL;
	}
#endif
}

/**
  Reset message C cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_c(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_context->transcript.message_c);
#else
	if (spdm_context->transcript.digest_context_m1m2 != NULL) {
		spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2);
		spdm_context->transcript.digest_context_m1m2 = NULL;
	}
#endif
}

/**
  Reset message MutB cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_mut_b(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_context->transcript.message_mut_b);
#else
	if (spdm_context->transcript.digest_context_mut_m1m2 != NULL) {
		spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_mut_m1m2);
		spdm_context->transcript.digest_context_mut_m1m2 = NULL;
	}
#endif
}

/**
  Reset message MutC cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_mut_c(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_context->transcript.message_mut_c);
#else
	if (spdm_context->transcript.digest_context_mut_m1m2 != NULL) {
		spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_mut_m1m2);
		spdm_context->transcript.digest_context_mut_m1m2 = NULL;
	}
#endif
}

/**
  Reset message M cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_reset_message_m(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_context->transcript.message_m);
#else
	if (spdm_context->transcript.digest_context_l1l2 != NULL) {
		spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_l1l2);
		spdm_context->transcript.digest_context_l1l2 = NULL;
	}
#endif
}

/**
  Reset message K cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  spdm_session_info              A pointer to the SPDM session context.
**/
void spdm_reset_message_k(IN void *context, IN void *session_info)
{
	spdm_session_info_t *spdm_session_info;

	spdm_session_info = session_info;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_session_info->session_transcript.message_k);
#else
	{
		spdm_context_t *spdm_context;
		void *secured_message_context;
	
		spdm_context = context;
		secured_message_context = spdm_get_secured_message_context_via_session_info (session_info);

		reset_managed_buffer(&spdm_session_info->session_transcript.temp_message_k);

		if (spdm_session_info->session_transcript.digest_context_th != NULL) {
			spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th);
			spdm_session_info->session_transcript.digest_context_th = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_rsp_context_th != NULL) {
			spdm_hmac_free_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th);
			spdm_session_info->session_transcript.hmac_rsp_context_th = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_req_context_th != NULL) {
			spdm_hmac_free_with_request_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th);
			spdm_session_info->session_transcript.hmac_req_context_th = NULL;
		}
		if (spdm_session_info->session_transcript.digest_context_th_backup != NULL) {
			spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th_backup);
			spdm_session_info->session_transcript.digest_context_th_backup = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_rsp_context_th_backup != NULL) {
			spdm_hmac_free_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th_backup);
			spdm_session_info->session_transcript.hmac_rsp_context_th_backup = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_req_context_th_backup != NULL) {
			spdm_hmac_free_with_request_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th_backup);
			spdm_session_info->session_transcript.hmac_req_context_th_backup = NULL;
		}
		spdm_session_info->session_transcript.finished_key_ready = FALSE;
	}
#endif
}

/**
  Reset message F cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  spdm_session_info              A pointer to the SPDM session context.
**/
void spdm_reset_message_f(IN void *context, IN void *session_info)
{
	spdm_session_info_t *spdm_session_info;

	spdm_session_info = session_info;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	reset_managed_buffer(&spdm_session_info->session_transcript.message_f);
#else
	{
		spdm_context_t *spdm_context;
		void *secured_message_context;
	
		spdm_context = context;
		secured_message_context = spdm_get_secured_message_context_via_session_info (session_info);

		if (spdm_session_info->session_transcript.digest_context_th != NULL) {
			spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th);
			spdm_session_info->session_transcript.digest_context_th = spdm_session_info->session_transcript.digest_context_th_backup;
			spdm_session_info->session_transcript.digest_context_th_backup = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_rsp_context_th != NULL) {
			spdm_hmac_free_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th);
			spdm_session_info->session_transcript.hmac_rsp_context_th = spdm_session_info->session_transcript.hmac_rsp_context_th_backup;
			spdm_session_info->session_transcript.hmac_rsp_context_th_backup = NULL;
		}
		if (spdm_session_info->session_transcript.hmac_req_context_th != NULL) {
			spdm_hmac_free_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th);
			spdm_session_info->session_transcript.hmac_req_context_th = spdm_session_info->session_transcript.hmac_req_context_th_backup;
			spdm_session_info->session_transcript.hmac_req_context_th_backup = NULL;
		}
		spdm_session_info->session_transcript.message_f_initialized = FALSE;
	}
#endif
}

/**
  Reset message buffer in SPDM context according to request code.

  @param  spdm_context               	A pointer to the SPDM context.
  @param  spdm_request               	The SPDM request code.
*/
void spdm_reset_message_buffer_via_request_code(IN void *context,
			       IN uint8 request_code)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	/**
	  Any request other than SPDM_GET_MEASUREMENTS resets L1/L2
	*/
	if (request_code != SPDM_GET_MEASUREMENTS) {
		spdm_reset_message_m(spdm_context);
	}
	/**
	  If the Requester issued GET_MEASUREMENTS or KEY_EXCHANGE or FINISH or PSK_EXCHANGE 
	  or PSK_FINISH or KEY_UPDATE or HEARTBEAT or GET_ENCAPSULATED_REQUEST or DELIVER_ENCAPSULATED_RESPONSE 
	  or END_SESSSION request(s) and skipped CHALLENGE completion, M1 and M2 are reset to null.
	*/
	switch (request_code)
	{
	case SPDM_KEY_EXCHANGE:
	case SPDM_GET_MEASUREMENTS:
	case SPDM_FINISH:
	case SPDM_PSK_EXCHANGE:
	case SPDM_PSK_FINISH:
	case SPDM_KEY_UPDATE:
	case SPDM_HEARTBEAT:
	case SPDM_GET_ENCAPSULATED_REQUEST:
	case SPDM_END_SESSION:
		if (spdm_context->connection_info.connection_state <
			SPDM_CONNECTION_STATE_AUTHENTICATED) {
			spdm_reset_message_b(spdm_context);
			spdm_reset_message_c(spdm_context);
			spdm_reset_message_mut_b(spdm_context);
			spdm_reset_message_mut_c(spdm_context);
		}
		break;
	case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
		if (spdm_context->connection_info.connection_state <
			SPDM_CONNECTION_STATE_AUTHENTICATED) {
			spdm_reset_message_b(spdm_context);
			spdm_reset_message_c(spdm_context);
		}
		break;
	default:
		break;
	}
}
/**
  Append message A cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_a(IN void *context, IN void *message,
				    IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	return append_managed_buffer(&spdm_context->transcript.message_a,
				     message, message_size);
}

/**
  Append message B cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_b(IN void *context, IN void *message,
				    IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(&spdm_context->transcript.message_b,
				     message, message_size);
#else
	if (spdm_context->transcript.digest_context_m1m2 == NULL) {
		spdm_context->transcript.digest_context_m1m2 = spdm_hash_new (
			spdm_context->connection_info.algorithm.base_hash_algo);
		spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2);
		spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2,
			get_managed_buffer(&spdm_context->transcript.message_a),
			get_managed_buffer_size(&spdm_context->transcript.message_a));
	}
	return spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
		spdm_context->transcript.digest_context_m1m2, message, message_size) ?
		RETURN_SUCCESS : RETURN_DEVICE_ERROR;
#endif
}

/**
  Append message C cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_c(IN void *context, IN void *message,
				    IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(&spdm_context->transcript.message_c,
				     message, message_size);
#else
	if (spdm_context->transcript.digest_context_m1m2 == NULL) {
		spdm_context->transcript.digest_context_m1m2 = spdm_hash_new (
			spdm_context->connection_info.algorithm.base_hash_algo);
		spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2);
		spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_m1m2,
			get_managed_buffer(&spdm_context->transcript.message_a),
			get_managed_buffer_size(&spdm_context->transcript.message_a));
	}
	return spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
		spdm_context->transcript.digest_context_m1m2, message, message_size) ?
		RETURN_SUCCESS : RETURN_DEVICE_ERROR;
#endif
}

/**
  Append message MutB cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_mut_b(IN void *context, IN void *message,
					IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(&spdm_context->transcript.message_mut_b,
				     message, message_size);
#else
	if (spdm_context->transcript.digest_context_mut_m1m2 == NULL) {
		spdm_context->transcript.digest_context_mut_m1m2 = spdm_hash_new (
			spdm_context->connection_info.algorithm.base_hash_algo);
		spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_mut_m1m2);
	}
	return spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
		spdm_context->transcript.digest_context_mut_m1m2, message, message_size) ?
		RETURN_SUCCESS : RETURN_DEVICE_ERROR;
#endif
}

/**
  Append message MutC cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_mut_c(IN void *context, IN void *message,
					IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(&spdm_context->transcript.message_mut_c,
				     message, message_size);
#else
	if (spdm_context->transcript.digest_context_mut_m1m2 == NULL) {
		spdm_context->transcript.digest_context_mut_m1m2 = spdm_hash_new (
			spdm_context->connection_info.algorithm.base_hash_algo);
		spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_mut_m1m2);
	}
	return spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
		spdm_context->transcript.digest_context_mut_m1m2, message, message_size) ?
		RETURN_SUCCESS : RETURN_DEVICE_ERROR;
#endif
}

/**
  Append message M cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_m(IN void *context, IN void *message,
				    IN uintn message_size)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(&spdm_context->transcript.message_m,
				     message, message_size);
#else
	if (spdm_context->transcript.digest_context_l1l2 == NULL) {
		spdm_context->transcript.digest_context_l1l2 = spdm_hash_new (
			spdm_context->connection_info.algorithm.base_hash_algo);
		spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_context->transcript.digest_context_l1l2);
	}
	return spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
		spdm_context->transcript.digest_context_l1l2, message, message_size) ?
		RETURN_SUCCESS : RETURN_DEVICE_ERROR;
#endif
}

/**
  Append message K cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  spdm_session_info              A pointer to the SPDM session context.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_k(IN void *context, IN void *session_info,
            IN boolean is_requester, IN void *message, IN uintn message_size)
{
	spdm_session_info_t *spdm_session_info;

	spdm_session_info = session_info;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(
		&spdm_session_info->session_transcript.message_k, message,
		message_size);
#else
	{
		spdm_context_t *spdm_context;
		void *secured_message_context;
		uint8 *cert_chain_buffer;
		uintn cert_chain_buffer_size;
		boolean result;
		uint8 cert_chain_buffer_hash[MAX_HASH_SIZE];
		uint32 hash_size;
		boolean finished_key_ready;

		spdm_context = context;
		secured_message_context = spdm_get_secured_message_context_via_session_info (session_info);
		finished_key_ready = spdm_secured_message_is_finished_key_ready(secured_message_context);

		if (spdm_session_info->session_transcript.digest_context_th == NULL) {
			if (!spdm_session_info->use_psk) {
				if (is_requester) {
					result = spdm_get_peer_cert_chain_buffer(
						spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
				} else {
					result = spdm_get_local_cert_chain_buffer(
						spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
				}
				if (!result) {
					return FALSE;
				}
				hash_size = spdm_get_hash_size(
					spdm_context->connection_info.algorithm.base_hash_algo);
				spdm_hash_all(
					spdm_context->connection_info.algorithm.base_hash_algo,
					cert_chain_buffer, cert_chain_buffer_size,
					cert_chain_buffer_hash);
			}
		}

		//
		// prepare digest_context_th
		//
		if (spdm_session_info->session_transcript.digest_context_th == NULL) {
			spdm_session_info->session_transcript.digest_context_th = spdm_hash_new (
				spdm_context->connection_info.algorithm.base_hash_algo);
			spdm_hash_init (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th);
			spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th,
				get_managed_buffer(&spdm_context->transcript.message_a),
				get_managed_buffer_size(&spdm_context->transcript.message_a));
			append_managed_buffer(
				&spdm_session_info->session_transcript.temp_message_k,
				get_managed_buffer(&spdm_context->transcript.message_a),
				get_managed_buffer_size(&spdm_context->transcript.message_a));
			if (!spdm_session_info->use_psk) {
				spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
					spdm_session_info->session_transcript.digest_context_th,
					cert_chain_buffer_hash, hash_size);
				append_managed_buffer(
					&spdm_session_info->session_transcript.temp_message_k,
					cert_chain_buffer_hash, hash_size);
			}
		}
		spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_session_info->session_transcript.digest_context_th, message, message_size);
		if (!finished_key_ready) {
			//
			// append message only if finished_key is NOT ready.
			//
			append_managed_buffer(
				&spdm_session_info->session_transcript.temp_message_k, message, message_size);
		}

		//
		// Above action is to calculate HASH for message_k.
		// However, we cannot use similar way to calculate HMAC. (chicken-egg problem)
		// HMAC need finished_key, and finished_key calculation need message_k.
		// If the finished_key is NOT ready, then we cannot calculate HMAC. We have to cache to temp_message_k and stop here.
		// If the finished_key is ready, then we can start calculating HMAC. No need to cache temp_message_k.
		//
		if (!finished_key_ready) {
			return RETURN_SUCCESS;
		}

		//
		// prepare hmac_rsp_context_th
		//
		if (spdm_session_info->session_transcript.hmac_rsp_context_th == NULL) {
			spdm_session_info->session_transcript.hmac_rsp_context_th = spdm_hmac_new_with_response_finished_key (
				secured_message_context);
			spdm_hmac_init_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th);
			spdm_hmac_update_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th,
				get_managed_buffer(&spdm_session_info->session_transcript.temp_message_k),
				get_managed_buffer_size(&spdm_session_info->session_transcript.temp_message_k));
		}
		spdm_hmac_update_with_response_finished_key (secured_message_context,
			spdm_session_info->session_transcript.hmac_rsp_context_th, message, message_size);

		//
		// prepare hmac_req_context_th
		//
		if (spdm_session_info->session_transcript.hmac_req_context_th == NULL) {
			spdm_session_info->session_transcript.hmac_req_context_th = spdm_hmac_new_with_request_finished_key (
				secured_message_context);
			spdm_hmac_init_with_request_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th);
			spdm_hmac_update_with_request_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th,
				get_managed_buffer(&spdm_session_info->session_transcript.temp_message_k),
				get_managed_buffer_size(&spdm_session_info->session_transcript.temp_message_k));
		}
		spdm_hmac_update_with_request_finished_key (secured_message_context,
			spdm_session_info->session_transcript.hmac_req_context_th, message, message_size);
		return RETURN_SUCCESS;
	}
#endif
}

/**
  Append message F cache in SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  spdm_session_info              A pointer to the SPDM session context.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  message                      message buffer.
  @param  message_size                  size in bytes of message buffer.

  @return RETURN_SUCCESS          message is appended.
  @return RETURN_OUT_OF_RESOURCES message is not appended because the internal cache is full.
**/
return_status spdm_append_message_f(IN void *context, IN void *session_info, 
            IN boolean is_requester, IN void *message, IN uintn message_size)
{
	spdm_session_info_t *spdm_session_info;

	spdm_session_info = session_info;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return append_managed_buffer(
		&spdm_session_info->session_transcript.message_f, message,
		message_size);
#else
	{
		spdm_context_t *spdm_context;
		void *secured_message_context;
		uint8 *mut_cert_chain_buffer;
		uintn mut_cert_chain_buffer_size;
		boolean result;
		uint8 mut_cert_chain_buffer_hash[MAX_HASH_SIZE];
		uint32 hash_size;
		boolean finished_key_ready;

		spdm_context = context;
		secured_message_context = spdm_get_secured_message_context_via_session_info (session_info);
		finished_key_ready = spdm_secured_message_is_finished_key_ready(secured_message_context);
		ASSERT (finished_key_ready);

		if (!spdm_session_info->session_transcript.message_f_initialized) {
			//
			// digest_context_th might be NULL in unit test, where message_k is hardcoded.
			// hmac_{rsp,req}_context_th might be NULL in real case, because
			//   after finished_key_ready is generated, no one trigger spdm_append_message_k.
			// trigger message_k to initialize by using zero length message_k, no impact to hash or HMAC.
			//   only temp_message_k is appended.
			//
			if (spdm_session_info->session_transcript.digest_context_th == NULL ||
				spdm_session_info->session_transcript.hmac_rsp_context_th == NULL ||
				spdm_session_info->session_transcript.hmac_req_context_th == NULL) {
				spdm_append_message_k (context, session_info, is_requester, NULL, 0);
			}

			if (!spdm_session_info->use_psk && spdm_session_info->mut_auth_requested) {
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

				hash_size = spdm_get_hash_size(
					spdm_context->connection_info.algorithm.base_hash_algo);
				spdm_hash_all(
					spdm_context->connection_info.algorithm.base_hash_algo,
					mut_cert_chain_buffer, mut_cert_chain_buffer_size,
					mut_cert_chain_buffer_hash);
			}

			//
			// It is first time call, backup current message_k context
			// this backup will be used in reset_message_f.
			//
			ASSERT (spdm_session_info->session_transcript.digest_context_th != NULL);
			spdm_session_info->session_transcript.digest_context_th_backup = spdm_hash_new (
				spdm_context->connection_info.algorithm.base_hash_algo);
			spdm_hash_duplicate (spdm_context->connection_info.algorithm.base_hash_algo,
				spdm_session_info->session_transcript.digest_context_th,
				spdm_session_info->session_transcript.digest_context_th_backup);

			ASSERT (spdm_session_info->session_transcript.hmac_rsp_context_th != NULL);
			spdm_session_info->session_transcript.hmac_rsp_context_th_backup = spdm_hmac_new_with_response_finished_key (
				secured_message_context);
			spdm_hmac_duplicate_with_response_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_rsp_context_th,
				spdm_session_info->session_transcript.hmac_rsp_context_th_backup);

			ASSERT (spdm_session_info->session_transcript.hmac_req_context_th != NULL);
			spdm_session_info->session_transcript.hmac_req_context_th_backup = spdm_hmac_new_with_request_finished_key (
				secured_message_context);
			spdm_hmac_duplicate_with_request_finished_key (secured_message_context,
				spdm_session_info->session_transcript.hmac_req_context_th,
				spdm_session_info->session_transcript.hmac_req_context_th_backup);
		}

		//
		// prepare digest_context_th
		//
		ASSERT (spdm_session_info->session_transcript.digest_context_th != NULL);
		if (!spdm_session_info->session_transcript.message_f_initialized) {
			if (!spdm_session_info->use_psk && spdm_session_info->mut_auth_requested) {
				spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
					spdm_session_info->session_transcript.digest_context_th, mut_cert_chain_buffer_hash, hash_size);
			}
		}
		spdm_hash_update (spdm_context->connection_info.algorithm.base_hash_algo,
			spdm_session_info->session_transcript.digest_context_th, message, message_size);

		//
		// prepare hmac_rsp_context_th
		//
		ASSERT (spdm_session_info->session_transcript.hmac_rsp_context_th != NULL);
		if (!spdm_session_info->session_transcript.message_f_initialized) {
			if (!spdm_session_info->use_psk && spdm_session_info->mut_auth_requested) {
				spdm_hmac_update_with_response_finished_key (secured_message_context,
					spdm_session_info->session_transcript.hmac_rsp_context_th, mut_cert_chain_buffer_hash, hash_size);
			}
		}
		spdm_hmac_update_with_response_finished_key (secured_message_context,
			spdm_session_info->session_transcript.hmac_rsp_context_th, message, message_size);

		//
		// prepare hmac_req_context_th
		//
		ASSERT (spdm_session_info->session_transcript.hmac_req_context_th != NULL);
		if (!spdm_session_info->session_transcript.message_f_initialized) {
			if (!spdm_session_info->use_psk && spdm_session_info->mut_auth_requested) {
				spdm_hmac_update_with_request_finished_key (secured_message_context,
					spdm_session_info->session_transcript.hmac_req_context_th, mut_cert_chain_buffer_hash, hash_size);
			}
		}
		spdm_hmac_update_with_request_finished_key (secured_message_context,
			spdm_session_info->session_transcript.hmac_req_context_th, message, message_size);

		spdm_session_info->session_transcript.message_f_initialized = TRUE;
		return RETURN_SUCCESS;
	}
#endif
}

/**
  This function returns if a given version is supported based upon the GET_VERSION/VERSION.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  version                      The SPDM version.

  @retval TRUE  the version is supported.
  @retval FALSE the version is not supported.
**/
boolean spdm_is_version_supported(IN spdm_context_t *spdm_context,
				  IN uint8 version)
{
	uint8 major_version;
	uint8 minor_version;

	major_version = ((version >> 4) & 0xF);
	minor_version = (version & 0xF);

	if ((major_version ==
			spdm_context->connection_info.version.major_version) &&
		(minor_version ==
			spdm_context->connection_info.version.minor_version)) {
		return TRUE;
	}

	return FALSE;
}

/**
  This function returns if a capablities flag is supported in current SPDM connection.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  is_requester                  Is the function called from a requester.
  @param  requester_capabilities_flag    The requester capabilities flag to be checked
  @param  responder_capabilities_flag    The responder capabilities flag to be checked

  @retval TRUE  the capablities flag is supported.
  @retval FALSE the capablities flag is not supported.
**/
boolean
spdm_is_capabilities_flag_supported(IN spdm_context_t *spdm_context,
				    IN boolean is_requester,
				    IN uint32 requester_capabilities_flag,
				    IN uint32 responder_capabilities_flag)
{
	uint32 negotiated_requester_capabilities_flag;
	uint32 negotiated_responder_capabilities_flag;

	if (is_requester) {
		negotiated_requester_capabilities_flag =
			spdm_context->local_context.capability.flags;
		negotiated_responder_capabilities_flag =
			spdm_context->connection_info.capability.flags;
	} else {
		negotiated_requester_capabilities_flag =
			spdm_context->connection_info.capability.flags;
		negotiated_responder_capabilities_flag =
			spdm_context->local_context.capability.flags;
	}

	if (((requester_capabilities_flag == 0) ||
	     ((negotiated_requester_capabilities_flag &
	       requester_capabilities_flag) != 0)) &&
	    ((responder_capabilities_flag == 0) ||
	     ((negotiated_responder_capabilities_flag &
	       responder_capabilities_flag) != 0))) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
  Register SPDM device input/output functions.

  This function must be called after spdm_init_context, and before any SPDM communication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  send_message                  The fuction to send an SPDM transport layer message.
  @param  receive_message               The fuction to receive an SPDM transport layer message.
**/
void spdm_register_device_io_func(
	IN void *context, IN spdm_device_send_message_func send_message,
	IN spdm_device_receive_message_func receive_message)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	spdm_context->send_message = send_message;
	spdm_context->receive_message = receive_message;
	return;
}

/**
  Register SPDM transport layer encode/decode functions for SPDM or APP messages.

  This function must be called after spdm_init_context, and before any SPDM communication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  transport_encode_message       The fuction to encode an SPDM or APP message to a transport layer message.
  @param  transport_decode_message       The fuction to decode an SPDM or APP message from a transport layer message.
**/
void spdm_register_transport_layer_func(
	IN void *context,
	IN spdm_transport_encode_message_func transport_encode_message,
	IN spdm_transport_decode_message_func transport_decode_message)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	spdm_context->transport_encode_message = transport_encode_message;
	spdm_context->transport_decode_message = transport_decode_message;
	return;
}

/**
  Get the last error of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.

  @return Last error of an SPDM context.
*/
uint32 spdm_get_last_error(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	return spdm_context->error_state;
}

/**
  Get the last SPDM error struct of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM context.
*/
void spdm_get_last_spdm_error_struct(IN void *context,
				     OUT spdm_error_struct_t *last_spdm_error)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	copy_mem(last_spdm_error, &spdm_context->last_spdm_error,
		 sizeof(spdm_error_struct_t));
}

/**
  Set the last SPDM error struct of an SPDM context.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  last_spdm_error                Last SPDM error struct of an SPDM context.
*/
void spdm_set_last_spdm_error_struct(IN void *context,
				     IN spdm_error_struct_t *last_spdm_error)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	copy_mem(&spdm_context->last_spdm_error, last_spdm_error,
		 sizeof(spdm_error_struct_t));
}

/**
  Initialize an SPDM context.

  The size in bytes of the spdm_context can be returned by spdm_get_context_size.

  @param  spdm_context                  A pointer to the SPDM context.
*/
void spdm_init_context(IN void *context)
{
	spdm_context_t *spdm_context;
	void *secured_message_context;
	uintn SecuredMessageContextSize;
	uintn index;

	spdm_context = context;
	zero_mem(spdm_context, sizeof(spdm_context_t));
	spdm_context->version = spdm_context_struct_VERSION;
	spdm_context->transcript.message_a.max_buffer_size =
		sizeof(spdm_context->transcript.message_a.buffer);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_b.max_buffer_size =
		sizeof(spdm_context->transcript.message_b.buffer);
	spdm_context->transcript.message_c.max_buffer_size =
		sizeof(spdm_context->transcript.message_c.buffer);
	spdm_context->transcript.message_mut_b.max_buffer_size =
		sizeof(spdm_context->transcript.message_mut_b.buffer);
	spdm_context->transcript.message_mut_c.max_buffer_size =
		sizeof(spdm_context->transcript.message_mut_c.buffer);
	spdm_context->transcript.message_m.max_buffer_size =
		sizeof(spdm_context->transcript.message_m.buffer);
#endif
	spdm_context->retry_times = MAX_SPDM_REQUEST_RETRY_TIMES;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->current_token = 0;
	spdm_context->local_context.version.spdm_version_count = 2;
	spdm_context->local_context.version.spdm_version[0].major_version = 1;
	spdm_context->local_context.version.spdm_version[0].minor_version = 0;
	spdm_context->local_context.version.spdm_version[0].alpha = 0;
	spdm_context->local_context.version.spdm_version[0]
		.update_version_number = 0;
	spdm_context->local_context.version.spdm_version[1].major_version = 1;
	spdm_context->local_context.version.spdm_version[1].minor_version = 1;
	spdm_context->local_context.version.spdm_version[1].alpha = 0;
	spdm_context->local_context.version.spdm_version[1]
		.update_version_number = 0;
	spdm_context->local_context.secured_message_version.spdm_version_count =
		1;
	spdm_context->local_context.secured_message_version.spdm_version[0]
		.major_version = 1;
	spdm_context->local_context.secured_message_version.spdm_version[0]
		.minor_version = 1;
	spdm_context->local_context.secured_message_version.spdm_version[0]
		.alpha = 0;
	spdm_context->local_context.secured_message_version.spdm_version[0]
		.update_version_number = 0;
	spdm_context->encap_context.certificate_chain_buffer.max_buffer_size =
		sizeof(spdm_context->encap_context.certificate_chain_buffer.buffer);

	secured_message_context = (void *)((uintn)(spdm_context + 1));
	SecuredMessageContextSize = spdm_secured_message_get_context_size();
	for (index = 0; index < MAX_SPDM_SESSION_COUNT; index++) {
		spdm_context->session_info[index].secured_message_context =
			(void *)((uintn)secured_message_context +
				 SecuredMessageContextSize * index);
		spdm_secured_message_init_context(
			spdm_context->session_info[index]
				.secured_message_context);
	}

	random_seed(NULL, 0);
	return;
}

/**
  Reset an SPDM context.

  The size in bytes of the spdm_context can be returned by spdm_get_context_size.

  @param  spdm_context                  A pointer to the SPDM context.
*/
void spdm_reset_context(IN void *context)
{
	spdm_context_t *spdm_context;
	uintn index;

	spdm_context = context;
	//Clear all info about last connection
	zero_mem(&spdm_context->connection_info.capability, sizeof(spdm_device_capability_t));
	zero_mem(&spdm_context->connection_info.algorithm, sizeof(spdm_device_algorithm_t));
	zero_mem(&spdm_context->last_spdm_error, sizeof(spdm_error_struct_t));
	zero_mem(&spdm_context->encap_context, sizeof(spdm_encap_context_t));
	spdm_context->connection_info.local_used_cert_chain_buffer_size = 0;
	spdm_context->connection_info.local_used_cert_chain_buffer = NULL;
	spdm_context->cache_spdm_request_size = 0;
	spdm_context->retry_times = MAX_SPDM_REQUEST_RETRY_TIMES;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->current_token = 0;
	spdm_context->last_spdm_request_session_id = INVALID_SESSION_ID;
	spdm_context->last_spdm_request_session_id_valid = FALSE;
	spdm_context->last_spdm_request_size = 0;
	spdm_context->encap_context.certificate_chain_buffer.max_buffer_size =
		sizeof(spdm_context->encap_context.certificate_chain_buffer.buffer);
	for (index = 0; index < MAX_SPDM_SESSION_COUNT; index++)
	{
		spdm_session_info_init(spdm_context,
							&spdm_context->session_info[index],
							INVALID_SESSION_ID,
							FALSE);
	}
}
/**
  Return the size in bytes of the SPDM context.

  @return the size in bytes of the SPDM context.
**/
uintn spdm_get_context_size(void)
{
	return sizeof(spdm_context_t) +
	       spdm_secured_message_get_context_size() * MAX_SPDM_SESSION_COUNT;
}

/**
  Return the SPDMversion field of the version number struct.

  @param  ver				Spdm version number struct.

  @return the SPDMversion of the version number struct.
**/
uint8 spdm_get_version_from_version_number(IN spdm_version_number_t ver)
{
	return (uint8)(ver.major_version << 4 |
				   ver.minor_version);
}
