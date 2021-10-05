/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint8 digest[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
} spdm_digests_response_max_t;

#pragma pack()

#if SPDM_ENABLE_CAPABILITY_CERT_CAP

/**
  This function sends GET_DIGEST
  to get all digest of the certificate chains from device.

  If the peer certificate chain is deployed,
  this function also verifies the digest with the certificate chain.

  TotalDigestSize = sizeof(digest) * count in slot_mask

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_mask                     The slots which deploy the CertificateChain.
  @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.

  @retval RETURN_SUCCESS               The digests are got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status try_spdm_get_digest(IN void *context, OUT uint8 *slot_mask,
				  OUT void *total_digest_buffer)
{
	boolean result;
	return_status status;
	spdm_get_digest_request_t spdm_request;
	spdm_digests_response_max_t spdm_response;
	uintn spdm_response_size;
	uintn digest_size;
	uintn digest_count;
	uintn index;
	spdm_context_t *spdm_context;

	spdm_context = context;
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
		return RETURN_UNSUPPORTED;
	}
	spdm_reset_message_buffer_via_request_code(spdm_context,
										SPDM_GET_DIGESTS);
	if (spdm_context->connection_info.connection_state !=
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return RETURN_UNSUPPORTED;
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	} else {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
	}
	spdm_request.header.request_response_code = SPDM_GET_DIGESTS;
	spdm_request.header.param1 = 0;
	spdm_request.header.param2 = 0;
	status = spdm_send_spdm_request(spdm_context, NULL,
					sizeof(spdm_request), &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}
	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, NULL, &spdm_response_size, &spdm_response);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_message_header_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		status = spdm_handle_error_response_main(
			spdm_context, NULL,
			&spdm_response_size,
			&spdm_response, SPDM_GET_DIGESTS, SPDM_DIGESTS,
			sizeof(spdm_digests_response_max_t));
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code != SPDM_DIGESTS) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_digest_response_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		return RETURN_DEVICE_ERROR;
	}

	digest_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	if (slot_mask != NULL) {
		*slot_mask = spdm_response.header.param2;
	}
	digest_count = 0;
	for (index = 0; index < MAX_SPDM_SLOT_COUNT; index++) {
		if (spdm_response.header.param2 & (1 << index)) {
			digest_count++;
		}
	}
	if (digest_count == 0) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size <
	    sizeof(spdm_digest_response_t) + digest_count * digest_size) {
		return RETURN_DEVICE_ERROR;
	}
	spdm_response_size =
		sizeof(spdm_digest_response_t) + digest_count * digest_size;
	//
	// Cache data
	//
	status = spdm_append_message_b(spdm_context, &spdm_request,
				       sizeof(spdm_request));
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	status = spdm_append_message_b(spdm_context, &spdm_response,
				       spdm_response_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	for (index = 0; index < digest_count; index++) {
		DEBUG((DEBUG_INFO, "digest (0x%x) - ", index));
		internal_dump_data(&spdm_response.digest[digest_size * index],
				   digest_size);
		DEBUG((DEBUG_INFO, "\n"));
	}

	result = spdm_verify_peer_digests(
		spdm_context, spdm_response.digest, digest_count);
	if (!result) {
		spdm_context->error_state =
			SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_context->error_state = SPDM_STATUS_SUCCESS;

	if (total_digest_buffer != NULL) {
		copy_mem(total_digest_buffer, spdm_response.digest,
			 digest_size * digest_count);
	}

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	return RETURN_SUCCESS;
}

/**
  This function sends GET_DIGEST
  to get all digest of the certificate chains from device.

  If the peer certificate chain is deployed,
  this function also verifies the digest with the certificate chain.

  TotalDigestSize = sizeof(digest) * count in slot_mask

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_mask                     The slots which deploy the CertificateChain.
  @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.

  @retval RETURN_SUCCESS               The digests are got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_digest(IN void *context, OUT uint8 *slot_mask,
			      OUT void *total_digest_buffer)
{
	spdm_context_t *spdm_context;
	uintn retry;
	return_status status;

	spdm_context = context;
	retry = spdm_context->retry_times;
	do {
		status = try_spdm_get_digest(spdm_context, slot_mask,
					     total_digest_buffer);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}

#endif SPDM_ENABLE_CAPABILITY_CERT_CAP