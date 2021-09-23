/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#if SPDM_ENABLE_CAPABILITY_CERT_CAP

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint16 portion_length;
	uint16 remainder_length;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_BLOCK_LEN];
} spdm_certificate_response_max_t;

#pragma pack()

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  length                       length parameter in the get_certificate message (limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN).
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status try_spdm_get_certificate(IN void *context, IN uint8 slot_id,
				       IN uint16 length,
				       IN OUT uintn *cert_chain_size,
				       OUT void *cert_chain)
{
	boolean result;
	return_status status;
	spdm_get_certificate_request_t spdm_request;
	spdm_certificate_response_max_t spdm_response;
	uintn spdm_response_size;
	large_managed_buffer_t certificate_chain_buffer;
	spdm_context_t *spdm_context;

	spdm_context = context;
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
		return RETURN_UNSUPPORTED;
	}
	spdm_reset_message_buffer_via_request_code(spdm_context,
							SPDM_GET_CERTIFICATE);
	if ((spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_NEGOTIATED) &&
	    (spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_AFTER_DIGESTS) &&
	    (spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_AFTER_CERTIFICATE)) {
		return RETURN_UNSUPPORTED;
	}

	init_managed_buffer(&certificate_chain_buffer,
			    MAX_SPDM_MESSAGE_BUFFER_SIZE);
	length = MIN(length, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);

	if (slot_id >= MAX_SPDM_SLOT_COUNT) {
		return RETURN_INVALID_PARAMETER;
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	do {
		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11)) {
			spdm_request.header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
		} else {
			spdm_request.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
		}
		spdm_request.header.request_response_code =
			SPDM_GET_CERTIFICATE;
		spdm_request.header.param1 = slot_id;
		spdm_request.header.param2 = 0;
		spdm_request.offset = (uint16)get_managed_buffer_size(
			&certificate_chain_buffer);
		spdm_request.length = length;
		DEBUG((DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
		       spdm_request.offset, spdm_request.length));

		status = spdm_send_spdm_request(spdm_context, NULL,
						sizeof(spdm_request),
						&spdm_request);
		if (RETURN_ERROR(status)) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}

		spdm_response_size = sizeof(spdm_response);
		zero_mem(&spdm_response, sizeof(spdm_response));
		status = spdm_receive_spdm_response(spdm_context, NULL,
						    &spdm_response_size,
						    &spdm_response);
		if (RETURN_ERROR(status)) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response_size < sizeof(spdm_message_header_t)) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response.header.request_response_code == SPDM_ERROR) {
			status = spdm_handle_error_response_main(
				spdm_context, NULL,
				NULL, 0, &spdm_response_size,
				&spdm_response, SPDM_GET_CERTIFICATE,
				SPDM_CERTIFICATE,
				sizeof(spdm_certificate_response_max_t));
			if (RETURN_ERROR(status)) {
				goto done;
			}
		} else if (spdm_response.header.request_response_code !=
			   SPDM_CERTIFICATE) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response_size < sizeof(spdm_certificate_response_t)) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response_size > sizeof(spdm_response)) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response.portion_length >
		    MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response.header.param1 != slot_id) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		if (spdm_response_size < sizeof(spdm_certificate_response_t) +
						 spdm_response.portion_length) {
			status = RETURN_DEVICE_ERROR;
			goto done;
		}
		spdm_response_size = sizeof(spdm_certificate_response_t) +
				     spdm_response.portion_length;
		//
		// Cache data
		//
		status = spdm_append_message_b(spdm_context, &spdm_request,
					       sizeof(spdm_request));
		if (RETURN_ERROR(status)) {
			status = RETURN_SECURITY_VIOLATION;
			goto done;
		}
		status = spdm_append_message_b(spdm_context, &spdm_response,
					       spdm_response_size);
		if (RETURN_ERROR(status)) {
			status = RETURN_SECURITY_VIOLATION;
			goto done;
		}

		DEBUG((DEBUG_INFO, "Certificate (offset 0x%x, size 0x%x):\n",
		       spdm_request.offset, spdm_response.portion_length));
		internal_dump_hex(spdm_response.cert_chain,
				  spdm_response.portion_length);

		status = append_managed_buffer(&certificate_chain_buffer,
					       spdm_response.cert_chain,
					       spdm_response.portion_length);
		if (RETURN_ERROR(status)) {
			status = RETURN_SECURITY_VIOLATION;
			goto done;
		}
		spdm_context->connection_info.connection_state =
			SPDM_CONNECTION_STATE_AFTER_CERTIFICATE;

	} while (spdm_response.remainder_length != 0);

	result = spdm_verify_peer_cert_chain_buffer(
		spdm_context, get_managed_buffer(&certificate_chain_buffer),
		get_managed_buffer_size(&certificate_chain_buffer));
	if (!result) {
		spdm_context->error_state =
			SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
		status = RETURN_SECURITY_VIOLATION;
		goto done;
	}
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		get_managed_buffer_size(&certificate_chain_buffer);
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 get_managed_buffer(&certificate_chain_buffer),
		 get_managed_buffer_size(&certificate_chain_buffer));

	spdm_context->error_state = SPDM_STATUS_SUCCESS;

	if (cert_chain_size != NULL) {
		if (*cert_chain_size <
		    get_managed_buffer_size(&certificate_chain_buffer)) {
			*cert_chain_size = get_managed_buffer_size(
				&certificate_chain_buffer);
			return RETURN_BUFFER_TOO_SMALL;
		}
		*cert_chain_size =
			get_managed_buffer_size(&certificate_chain_buffer);
		if (cert_chain != NULL) {
			copy_mem(cert_chain,
				 get_managed_buffer(&certificate_chain_buffer),
				 get_managed_buffer_size(
					 &certificate_chain_buffer));
		}
	}

	status = RETURN_SUCCESS;
done:
	return status;
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_certificate(IN void *context, IN uint8 slot_id,
				   IN OUT uintn *cert_chain_size,
				   OUT void *cert_chain)
{
	return spdm_get_certificate_choose_length(context, slot_id,
						  MAX_SPDM_CERT_CHAIN_BLOCK_LEN,
						  cert_chain_size, cert_chain);
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  length                       length parameter in the get_certificate message (limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN).
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_certificate_choose_length(IN void *context,
						 IN uint8 slot_id,
						 IN uint16 length,
						 IN OUT uintn *cert_chain_size,
						 OUT void *cert_chain)
{
	spdm_context_t *spdm_context;
	uintn retry;
	return_status status;

	spdm_context = context;
	retry = spdm_context->retry_times;
	do {
		status = try_spdm_get_certificate(spdm_context, slot_id, length,
						  cert_chain_size, cert_chain);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}

#endif // SPDM_ENABLE_CAPABILITY_CERT_CAP