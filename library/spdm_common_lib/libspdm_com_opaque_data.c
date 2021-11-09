/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_common_lib_internal.h"

/**
  Return the size in bytes of opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @return the size in bytes of opaque data version selection.
**/
uintn spdm_get_opaque_data_version_selection_data_size(
	IN spdm_context_t *spdm_context)
{
	uintn size;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		return 0;
	}

	size = sizeof(secured_message_general_opaque_data_table_header_t) +
	       sizeof(secured_message_opaque_element_table_header_t) +
	       sizeof(secured_message_opaque_element_version_selection_t);
	// Add Padding
	return (size + 3) & ~3;
}

/**
  Return the size in bytes of opaque data supproted version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @return the size in bytes of opaque data supproted version.
**/
uintn spdm_get_opaque_data_supported_version_data_size(
	IN spdm_context_t *spdm_context)
{
	uintn size;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		return 0;
	}

	size = sizeof(secured_message_general_opaque_data_table_header_t) +
	       sizeof(secured_message_opaque_element_table_header_t) +
	       sizeof(secured_message_opaque_element_supported_version_t) +
	       sizeof(spdm_version_number_t);
	// Add Padding
	return (size + 3) & ~3;
}

/**
  Build opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @param  data_out_size                  size in bytes of the data_out.
                                       On input, it means the size in bytes of data_out buffer.
                                       On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  data_out                      A pointer to the desination buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_build_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
					      IN OUT uintn *data_out_size,
					      OUT void *data_out)
{
	uintn final_data_size;
	secured_message_general_opaque_data_table_header_t
		*general_opaque_data_table_header;
	secured_message_opaque_element_table_header_t
		*opaque_element_table_header;
	secured_message_opaque_element_supported_version_t
		*opaque_element_support_version;
	spdm_version_number_t *versions_list;
	void *end;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		*data_out_size = 0;
		return RETURN_SUCCESS;
	}

	final_data_size =
		spdm_get_opaque_data_supported_version_data_size(spdm_context);
	if (*data_out_size < final_data_size) {
		*data_out_size = final_data_size;
		return RETURN_BUFFER_TOO_SMALL;
	}

	general_opaque_data_table_header = data_out;
	general_opaque_data_table_header->spec_id =
		SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
	general_opaque_data_table_header->opaque_version =
		SECURED_MESSAGE_OPAQUE_VERSION;
	general_opaque_data_table_header->total_elements = 1;
	general_opaque_data_table_header->reserved = 0;

	opaque_element_table_header =
		(void *)(general_opaque_data_table_header + 1);
	opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
	opaque_element_table_header->vendor_len = 0;
	opaque_element_table_header->opaque_element_data_len =
		sizeof(secured_message_opaque_element_supported_version_t) +
		sizeof(spdm_version_number_t);

	opaque_element_support_version =
		(void *)(opaque_element_table_header + 1);
	opaque_element_support_version->sm_data_version =
		SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
	opaque_element_support_version->sm_data_id =
		SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
	opaque_element_support_version->version_count = 1;

	versions_list = (void *)(opaque_element_support_version + 1);
	versions_list->alpha = 0;
	versions_list->update_version_number = 0;
	versions_list->minor_version = 1;
	versions_list->major_version = 1;

	// Zero Padding
	end = versions_list + 1;
	zero_mem(end, (uintn)data_out + final_data_size - (uintn)end);

	return RETURN_SUCCESS;
}

/**
  Process opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.

  @param  data_in_size                   size in bytes of the data_in.
  @param  data_in                       A pointer to the buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
  @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data supported version.
**/
return_status
spdm_process_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
						IN uintn data_in_size,
						IN void *data_in)
{
	secured_message_general_opaque_data_table_header_t
		*general_opaque_data_table_header;
	secured_message_opaque_element_table_header_t
		*opaque_element_table_header;
	secured_message_opaque_element_supported_version_t
		*opaque_element_support_version;
	spdm_version_number_t *versions_list;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		return RETURN_SUCCESS;
	}

	if (data_in_size !=
	    spdm_get_opaque_data_supported_version_data_size(spdm_context)) {
		return RETURN_UNSUPPORTED;
	}
	general_opaque_data_table_header = data_in;
	if ((general_opaque_data_table_header->spec_id !=
	     SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
	    (general_opaque_data_table_header->opaque_version !=
	     SECURED_MESSAGE_OPAQUE_VERSION) ||
	    (general_opaque_data_table_header->total_elements != 1) ||
	    (general_opaque_data_table_header->reserved != 0)) {
		return RETURN_UNSUPPORTED;
	}
	opaque_element_table_header =
		(void *)(general_opaque_data_table_header + 1);
	if ((opaque_element_table_header->id != SPDM_REGISTRY_ID_DMTF) ||
	    (opaque_element_table_header->vendor_len != 0) ||
	    (opaque_element_table_header->opaque_element_data_len !=
	     sizeof(secured_message_opaque_element_supported_version_t) +
		     sizeof(spdm_version_number_t))) {
		return RETURN_UNSUPPORTED;
	}
	opaque_element_support_version =
		(void *)(opaque_element_table_header + 1);
	if ((opaque_element_support_version->sm_data_version !=
	     SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
	    (opaque_element_support_version->sm_data_id !=
	     SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION) ||
	    (opaque_element_support_version->version_count != 1)) {
		return RETURN_UNSUPPORTED;
	}
	versions_list = (void *)(opaque_element_support_version + 1);
	if ((versions_list->minor_version != 1) ||
	    (versions_list->major_version != 1)) {
		return RETURN_UNSUPPORTED;
	}

	return RETURN_SUCCESS;
}

/**
  Build opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @param  data_out_size                  size in bytes of the data_out.
                                       On input, it means the size in bytes of data_out buffer.
                                       On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  data_out                      A pointer to the desination buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_build_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
					      IN OUT uintn *data_out_size,
					      OUT void *data_out)
{
	uintn final_data_size;
	secured_message_general_opaque_data_table_header_t
		*general_opaque_data_table_header;
	secured_message_opaque_element_table_header_t
		*opaque_element_table_header;
	secured_message_opaque_element_version_selection_t
		*OpaqueElementVersionSection;
	void *end;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		*data_out_size = 0;
		return RETURN_SUCCESS;
	}

	final_data_size =
		spdm_get_opaque_data_version_selection_data_size(spdm_context);
	if (*data_out_size < final_data_size) {
		*data_out_size = final_data_size;
		return RETURN_BUFFER_TOO_SMALL;
	}

	general_opaque_data_table_header = data_out;
	general_opaque_data_table_header->spec_id =
		SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
	general_opaque_data_table_header->opaque_version =
		SECURED_MESSAGE_OPAQUE_VERSION;
	general_opaque_data_table_header->total_elements = 1;
	general_opaque_data_table_header->reserved = 0;

	opaque_element_table_header =
		(void *)(general_opaque_data_table_header + 1);
	opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
	opaque_element_table_header->vendor_len = 0;
	opaque_element_table_header->opaque_element_data_len =
		sizeof(secured_message_opaque_element_version_selection_t);

	OpaqueElementVersionSection = (void *)(opaque_element_table_header + 1);
	OpaqueElementVersionSection->sm_data_version =
		SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
	OpaqueElementVersionSection->sm_data_id =
		SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
	OpaqueElementVersionSection->selected_version.alpha = 0;
	OpaqueElementVersionSection->selected_version.update_version_number = 0;
	OpaqueElementVersionSection->selected_version.minor_version = 1;
	OpaqueElementVersionSection->selected_version.major_version = 1;

	// Zero Padding
	end = OpaqueElementVersionSection + 1;
	zero_mem(end, (uintn)data_out + final_data_size - (uintn)end);

	return RETURN_SUCCESS;
}

/**
  Process opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.

  @param  data_in_size                   size in bytes of the data_in.
  @param  data_in                       A pointer to the buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
  @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data version selection.
**/
return_status
spdm_process_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
						IN uintn data_in_size,
						IN void *data_in)
{
	secured_message_general_opaque_data_table_header_t
		*general_opaque_data_table_header;
	secured_message_opaque_element_table_header_t
		*opaque_element_table_header;
	secured_message_opaque_element_version_selection_t
		*OpaqueElementVersionSection;

	if (spdm_context->local_context.secured_message_version
		    .spdm_version_count == 0) {
		return RETURN_SUCCESS;
	}

	if (data_in_size !=
	    spdm_get_opaque_data_version_selection_data_size(spdm_context)) {
		return RETURN_UNSUPPORTED;
	}
	general_opaque_data_table_header = data_in;
	if ((general_opaque_data_table_header->spec_id !=
	     SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
	    (general_opaque_data_table_header->opaque_version !=
	     SECURED_MESSAGE_OPAQUE_VERSION) ||
	    (general_opaque_data_table_header->total_elements != 1) ||
	    (general_opaque_data_table_header->reserved != 0)) {
		return RETURN_UNSUPPORTED;
	}
	opaque_element_table_header =
		(void *)(general_opaque_data_table_header + 1);
	if ((opaque_element_table_header->id != SPDM_REGISTRY_ID_DMTF) ||
	    (opaque_element_table_header->vendor_len != 0) ||
	    (opaque_element_table_header->opaque_element_data_len !=
	     sizeof(secured_message_opaque_element_version_selection_t))) {
		return RETURN_UNSUPPORTED;
	}
	OpaqueElementVersionSection = (void *)(opaque_element_table_header + 1);
	if ((OpaqueElementVersionSection->sm_data_version !=
	     SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
	    (OpaqueElementVersionSection->sm_data_id !=
	     SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION) ||
	    (OpaqueElementVersionSection->selected_version.minor_version !=
	     1) ||
	    (OpaqueElementVersionSection->selected_version.major_version !=
	     1)) {
		return RETURN_UNSUPPORTED;
	}

	return RETURN_SUCCESS;
}