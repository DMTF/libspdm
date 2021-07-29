/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)
typedef struct {
	spdm_message_header_t header;
	uint8 reserved;
	uint8 version_number_entry_count;
	spdm_version_number_t version_number_entry[MAX_SPDM_VERSION_COUNT];
} spdm_version_response_max_t;
#pragma pack()

/**
  This function sends GET_VERSION and receives VERSION.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_get_version(IN spdm_context_t *spdm_context)
{
	return_status status;
	spdm_get_version_request_t spdm_request;
	spdm_version_response_max_t spdm_response;
	uintn spdm_response_size;
	uintn index;
	uint8 version;
	uint8 compatible_version_count;
	spdm_version_number_t
		compatible_version_number_entry[MAX_SPDM_VERSION_COUNT];

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;

	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
	spdm_request.header.request_response_code = SPDM_GET_VERSION;
	spdm_request.header.param1 = 0;
	spdm_request.header.param2 = 0;

	spdm_reset_context(spdm_context);

	status = spdm_send_spdm_request(spdm_context, NULL,
					sizeof(spdm_request), &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache data
	//
	reset_managed_buffer(&spdm_context->transcript.message_a);
	reset_managed_buffer(&spdm_context->transcript.message_b);
	reset_managed_buffer(&spdm_context->transcript.message_c);
	status = spdm_append_message_a(spdm_context, &spdm_request,
				       sizeof(spdm_request));
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
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
	if (spdm_response.header.spdm_version != SPDM_MESSAGE_VERSION_10) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		shrink_managed_buffer(&spdm_context->transcript.message_a,
				      sizeof(spdm_request));
		status = spdm_handle_simple_error_response(
			spdm_context, spdm_response.header.param1);
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code != SPDM_VERSION) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_version_response)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.version_number_entry_count > MAX_SPDM_VERSION_COUNT) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.version_number_entry_count == 0) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size <
	    sizeof(spdm_version_response) +
		    spdm_response.version_number_entry_count *
			    sizeof(spdm_version_number_t)) {
		return RETURN_DEVICE_ERROR;
	}
	spdm_response_size = sizeof(spdm_version_response) +
			     spdm_response.version_number_entry_count *
				     sizeof(spdm_version_number_t);
	//
	// Cache data
	//
	status = spdm_append_message_a(spdm_context, &spdm_response,
				       spdm_response_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}
	compatible_version_count = 0;

	zero_mem(&compatible_version_number_entry,
		 sizeof(compatible_version_number_entry));
	for (index = 0; index < spdm_response.version_number_entry_count;
	     index++) {
		version = (uint8)(
			(spdm_response.version_number_entry[index].major_version
			 << 4) |
			spdm_response.version_number_entry[index].minor_version);

		if (version == SPDM_MESSAGE_VERSION_11 ||
		    version == SPDM_MESSAGE_VERSION_10) {
			compatible_version_number_entry[compatible_version_count] =
				spdm_response.version_number_entry[index];
			compatible_version_count++;
		}
	}
	if (compatible_version_count == 0) {
		return RETURN_DEVICE_ERROR;
	}
	spdm_context->connection_info.version.spdm_version_count =
		compatible_version_count;
	copy_mem(spdm_context->connection_info.version.spdm_version,
		 compatible_version_number_entry,
		 sizeof(spdm_version_number_t) * compatible_version_count);

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	return RETURN_SUCCESS;
}

/**
  This function sends GET_VERSION and receives VERSION.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  version_count                 version_count from the VERSION response.
  @param  VersionNumberEntries         VersionNumberEntries from the VERSION response.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_get_version(IN spdm_context_t *spdm_context)
{
	uintn retry;
	return_status status;

	retry = spdm_context->retry_times;
	do {
		status = try_spdm_get_version(spdm_context);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
