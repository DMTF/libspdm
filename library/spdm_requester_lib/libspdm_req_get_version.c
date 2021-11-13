/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
	spdm_message_header_t header;
	uint8 reserved;
	uint8 version_number_entry_count;
	spdm_version_number_t version_number_entry[MAX_SPDM_VERSION_COUNT];
} spdm_version_response_max_t;
#pragma pack()


/**
  Compare SPDMversion feild of spdm_version_number_t.

  @param  spdm_context				A pointer to the SPDM context.
  @param  first_ver					First version number.
  @param  seccond_ver				Second version number.

  @retval TRUE						First version is higher than seccond version.
  @retval FALSE						First version is not higher than seccond version.
*/
boolean spdm_version_number_compare(IN spdm_version_number_t first_ver, IN spdm_version_number_t seccond_ver)
{
	uint8 first_version;
	uint8 seccond_version;

	first_version = spdm_get_version_from_version_number(first_ver);
	seccond_version = spdm_get_version_from_version_number(seccond_ver);
	return (first_version > seccond_version);
}

/**
  Sort SPDMversion in descending order.

  @param  spdm_context				A pointer to the SPDM context.
  @param  ver_set					A pointer to the version set.
  @param  ver_num					Version number.
*/
void spdm_version_number_sort(IN OUT spdm_version_number_t *ver_set, IN uintn ver_num)
{
	uintn index;
	uintn index_sort;
	uintn index_max;
	spdm_version_number_t version;

	/* Select sort */
	if (ver_num > 1) {
		for (index_sort = 0; index_sort < ver_num; index_sort++) {
			index_max = index_sort;
			for (index = index_sort + 1; index < ver_num; index++) {
				/* if ver_ser[index] higher than ver_set[index_max] */
				if (spdm_version_number_compare(ver_set[index], ver_set[index_max])) {
					index_max = index;
				}
			}
			/* swap ver_ser[index_min] and ver_set[index_sort] */
			version = ver_set[index_sort];
            ver_set[index_sort] = ver_set[index_max];
			ver_set[index_max] = version;
		}
	}
}
/**
  Negotiate SPDMversion for connection.
  ver_set is the local version set of requester, res_ver_set is the version set of responder.

  @param  spdm_context				A pointer to the SPDM context.
  @param  req_ver_set				A pointer to the requester version set.
  @param  req_ver_num				Version number of requester.
  @param  res_ver_set				A pointer to the responder version set.
  @param  res_ver_num				Version number of responder.

  @retval TRUE               		Negotiation successfully, connect version be saved to context.
  @retval FALSE					    Negotiation failed.
*/
boolean spdm_negotiate_connection_version(IN OUT void *context, IN spdm_version_number_t *req_ver_set, IN uintn req_ver_num,
									   	IN spdm_version_number_t *res_ver_set, IN uintn res_ver_num)
{
	uint8 req_version;
	uint8 res_version;
	boolean ver_available;
	uintn req_index;
	uintn res_index;
	spdm_context_t *spdm_context;

	if (req_ver_set == NULL || req_ver_num == 0) {
		return FALSE;
	}
	if (res_ver_set == NULL || res_ver_num == 0) {
		return FALSE;
	}

	spdm_context = context;
	ver_available = FALSE;
	/* Sort SPDMversion in descending order. */
	spdm_version_number_sort(req_ver_set, req_ver_num);
	spdm_version_number_sort(res_ver_set, res_ver_num);
	/**
  	  Find highest same version and make req_index point to it.
	  If not found, ver_available will be FALSE.
	**/
	for (req_index = 0; req_index < req_ver_num; req_index++) {
		req_version = spdm_get_version_from_version_number(req_ver_set[req_index]);
		res_index = 0;
		res_version = spdm_get_version_from_version_number(res_ver_set[res_index]);
		while (res_index < res_ver_num && res_version > req_version) {
			res_index++;
			res_version = spdm_get_version_from_version_number(res_ver_set[res_index]);
		}
		if (req_version == res_version) {
			ver_available = TRUE;
			DEBUG((DEBUG_INFO,"connection ver: %x \n", req_version));
			break;
		}
	}

	if (ver_available == TRUE) {
		copy_mem(&(spdm_context->connection_info.version),
			req_ver_set + req_index,
			sizeof(spdm_version_number_t));
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
  This function sends GET_VERSION and receives VERSION.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_get_version(IN spdm_context_t *spdm_context)
{
	return_status status;
	boolean result;
	spdm_get_version_request_t spdm_request;
	spdm_version_response_max_t spdm_response;
	uintn spdm_response_size;

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;

	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
	spdm_request.header.request_response_code = SPDM_GET_VERSION;
	spdm_request.header.param1 = 0;
	spdm_request.header.param2 = 0;

	libspdm_reset_context(spdm_context);

	spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
						spdm_request.header.request_response_code);

	status = spdm_send_spdm_request(spdm_context, NULL,
					sizeof(spdm_request), &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	libspdm_reset_message_a(spdm_context);
	libspdm_reset_message_b(spdm_context);
	libspdm_reset_message_c(spdm_context);

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
	status = libspdm_append_message_a(spdm_context, &spdm_request,
				       sizeof(spdm_request));
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}
	status = libspdm_append_message_a(spdm_context, &spdm_response,
				       spdm_response_size);
	if (RETURN_ERROR(status)) {
		libspdm_reset_message_a(spdm_context);
		return RETURN_SECURITY_VIOLATION;
	}

	//
	// spdm_negotiate_connection_version will change the spdm_response.
	// It must be done after append_message_a.
	//
	result = spdm_negotiate_connection_version(spdm_context, spdm_context->local_context.version.spdm_version,
									spdm_context->local_context.version.spdm_version_count,
									spdm_response.version_number_entry,
									spdm_response.version_number_entry_count);
	if (result != TRUE) {
		libspdm_reset_message_a(spdm_context);
		return RETURN_DEVICE_ERROR;
	}

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
