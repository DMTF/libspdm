/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"


/**
 * Return the size in bytes of opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.
 *
 * @return the size in bytes of opaque data version selection.
 **/
uintn spdm_get_opaque_data_version_selection_data_size(
    IN spdm_context_t *spdm_context)
{
    uintn size;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return 0;
    }

    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_version_selection_t);
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_version_selection_t);
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

/**
 * Return the size in bytes of opaque data supproted version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.
 *
 * @return the size in bytes of opaque data supproted version.
 **/
uintn spdm_get_opaque_data_supported_version_data_size(
    IN spdm_context_t *spdm_context)
{
    uintn size;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return 0;
    }

    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t);
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t);
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

/**
 * Build opaque data supported version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.
 *
 * @param  data_out_size                  size in bytes of the data_out.
 *                                     On input, it means the size in bytes of data_out buffer.
 *                                     On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out                      A pointer to the desination buffer to store the opaque data supported version.
 *
 * @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
return_status
spdm_build_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
                                              IN OUT uintn *data_out_size,
                                              OUT void *data_out)
{
    uintn final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
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
    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = 1;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);
        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id =
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version =
            SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = 1;
        general_opaque_data_table_header->reserved = 0;
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }

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
    opaque_element_support_version->version_count =
        spdm_context->local_context.secured_message_version.spdm_version_count;

    versions_list = (void *)(opaque_element_support_version + 1);
    copy_mem(versions_list,
             spdm_context->local_context.secured_message_version.spdm_version,
             spdm_context->local_context.secured_message_version.spdm_version_count *
             sizeof(spdm_version_number_t));

    /* Zero Padding*/
    end = versions_list + spdm_context->local_context.secured_message_version.spdm_version_count;
    zero_mem(end, (uintn)data_out + final_data_size - (uintn)end);

    return RETURN_SUCCESS;
}

/**
 * Process opaque data supported version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.
 *
 * @param  data_in_size                   size in bytes of the data_in.
 * @param  data_in                       A pointer to the buffer to store the opaque data supported version.
 *
 * @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
 * @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data supported version.
 **/
return_status
spdm_process_opaque_data_supported_version_data(IN spdm_context_t *spdm_context,
                                                IN uintn data_in_size,
                                                IN void *data_in)
{
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_supported_version_t
    *opaque_element_support_version;
    spdm_version_number_t *versions_list;
    spdm_version_number_t common_version;
    bool result;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return RETURN_SUCCESS;
    }

    if (data_in_size !=
        spdm_get_opaque_data_supported_version_data_size(spdm_context)) {
        return RETURN_UNSUPPORTED;
    }
    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (spdm_general_opaque_data_table_header->total_elements != 1) {
            return RETURN_UNSUPPORTED;
        }
        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_in;
        if ((general_opaque_data_table_header->spec_id !=
             SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
            (general_opaque_data_table_header->opaque_version !=
             SECURED_MESSAGE_OPAQUE_VERSION) ||
            (general_opaque_data_table_header->total_elements != 1)) {
            return RETURN_UNSUPPORTED;
        }
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }
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
        (opaque_element_support_version->version_count == 0)) {
        return RETURN_UNSUPPORTED;
    }
    versions_list = (void *)(opaque_element_support_version + 1);

    result = spdm_negotiate_connection_version(&common_version,
                                               spdm_context->local_context.secured_message_version.spdm_version,
                                               spdm_context->local_context.secured_message_version.spdm_version_count,
                                               versions_list,
                                               opaque_element_support_version->version_count);
    if (result == false) {
        return RETURN_UNSUPPORTED;
    }
    copy_mem(&(spdm_context->connection_info.secured_message_version),
             &(common_version),
             sizeof(spdm_version_number_t));

    return RETURN_SUCCESS;
}

/**
 * Build opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.
 *
 * @param  data_out_size                  size in bytes of the data_out.
 *                                     On input, it means the size in bytes of data_out buffer.
 *                                     On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out                      A pointer to the desination buffer to store the opaque data version selection.
 *
 * @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
return_status
spdm_build_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
                                              IN OUT uintn *data_out_size,
                                              OUT void *data_out)
{
    uintn final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_version_selection_t
    *opaque_element_version_section;
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

    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = 1;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);

        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id =
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version =
            SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = 1;
        general_opaque_data_table_header->reserved = 0;

        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }
    opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
    opaque_element_table_header->vendor_len = 0;
    opaque_element_table_header->opaque_element_data_len =
        sizeof(secured_message_opaque_element_version_selection_t);

    opaque_element_version_section = (void *)(opaque_element_table_header + 1);
    opaque_element_version_section->sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_element_version_section->sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
    opaque_element_version_section->selected_version =
        spdm_context->connection_info.secured_message_version;
    /* Zero Padding*/
    end = opaque_element_version_section + 1;
    zero_mem(end, (uintn)data_out + final_data_size - (uintn)end);

    return RETURN_SUCCESS;
}

/**
 * Process opaque data version selection.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.
 *
 * @param  data_in_size                   size in bytes of the data_in.
 * @param  data_in                       A pointer to the buffer to store the opaque data version selection.
 *
 * @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
 * @retval RETURN_UNSUPPORTED           The data_in is NOT opaque data version selection.
 **/
return_status
spdm_process_opaque_data_version_selection_data(IN spdm_context_t *spdm_context,
                                                IN uintn data_in_size,
                                                IN void *data_in)
{
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_version_selection_t
    *opaque_element_version_section;
    uint8_t secured_message_version_index;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return RETURN_SUCCESS;
    }

    if (data_in_size !=
        spdm_get_opaque_data_version_selection_data_size(spdm_context)) {
        return RETURN_UNSUPPORTED;
    }
    if (spdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (spdm_general_opaque_data_table_header->total_elements != 1) {
            return RETURN_UNSUPPORTED;
        }
        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_in;
        if ((general_opaque_data_table_header->spec_id !=
             SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
            (general_opaque_data_table_header->opaque_version !=
             SECURED_MESSAGE_OPAQUE_VERSION) ||
            (general_opaque_data_table_header->total_elements != 1)) {
            return RETURN_UNSUPPORTED;
        }
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }
    if ((opaque_element_table_header->id != SPDM_REGISTRY_ID_DMTF) ||
        (opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_version_selection_t))) {
        return RETURN_UNSUPPORTED;
    }
    opaque_element_version_section = (void *)(opaque_element_table_header + 1);
    if ((opaque_element_version_section->sm_data_version !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
        (opaque_element_version_section->sm_data_id !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION)) {
        return RETURN_UNSUPPORTED;
    }

    for (secured_message_version_index = 0;
         secured_message_version_index <
         spdm_context->local_context.secured_message_version.spdm_version_count;
         secured_message_version_index++) {

        if (spdm_get_version_from_version_number(opaque_element_version_section->selected_version)
            ==
            spdm_get_version_from_version_number(spdm_context->local_context.secured_message_version
                                                 .spdm_version[secured_message_version_index])) {
            return RETURN_SUCCESS;
        }
    }

    return RETURN_UNSUPPORTED;
}
