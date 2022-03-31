/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
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
size_t libspdm_get_opaque_data_version_selection_data_size(
    const libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
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
size_t libspdm_get_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
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
libspdm_return_t
libspdm_build_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
                                                 size_t *data_out_size,
                                                 void *data_out)
{
    size_t final_data_size;
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
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
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
    libspdm_copy_mem(versions_list,
                     *data_out_size - ((uint8_t*)versions_list - (uint8_t*)data_out),
                     spdm_context->local_context.secured_message_version.spdm_version,
                     spdm_context->local_context.secured_message_version.spdm_version_count *
                     sizeof(spdm_version_number_t));

    /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
    end = versions_list + spdm_context->local_context.secured_message_version.spdm_version_count;
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);

    return LIBSPDM_STATUS_SUCCESS;
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
libspdm_return_t
libspdm_process_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
                                                   size_t data_in_size,
                                                   void *data_in)
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
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (data_in_size !=
        libspdm_get_opaque_data_supported_version_data_size(spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (spdm_general_opaque_data_table_header->total_elements != 1) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
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
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }
    if ((opaque_element_table_header->id != SPDM_REGISTRY_ID_DMTF) ||
        (opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_supported_version_t) +
         sizeof(spdm_version_number_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    opaque_element_support_version =
        (void *)(opaque_element_table_header + 1);
    if ((opaque_element_support_version->sm_data_version !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
        (opaque_element_support_version->sm_data_id !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION) ||
        (opaque_element_support_version->version_count == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    versions_list = (void *)(opaque_element_support_version + 1);

    result = libspdm_negotiate_connection_version(&common_version,
                                                  spdm_context->local_context.secured_message_version.spdm_version,
                                                  spdm_context->local_context.secured_message_version.spdm_version_count,
                                                  versions_list,
                                                  opaque_element_support_version->version_count);
    if (!result) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    libspdm_copy_mem(&(spdm_context->connection_info.secured_message_version),
                     sizeof(spdm_context->connection_info.secured_message_version),
                     &(common_version),
                     sizeof(spdm_version_number_t));

    return LIBSPDM_STATUS_SUCCESS;
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
libspdm_return_t
libspdm_build_opaque_data_version_selection_data(const libspdm_context_t *spdm_context,
                                                 size_t *data_out_size,
                                                 void *data_out)
{
    size_t final_data_size;
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
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
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
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);

    return LIBSPDM_STATUS_SUCCESS;
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
libspdm_return_t
libspdm_process_opaque_data_version_selection_data(libspdm_context_t *spdm_context,
                                                   size_t data_in_size,
                                                   void *data_in)
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
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (data_in_size !=
        libspdm_get_opaque_data_version_selection_data_size(spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (spdm_general_opaque_data_table_header->total_elements != 1) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
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
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }
    if ((opaque_element_table_header->id != SPDM_REGISTRY_ID_DMTF) ||
        (opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_version_selection_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    opaque_element_version_section = (void *)(opaque_element_table_header + 1);
    if ((opaque_element_version_section->sm_data_version !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
        (opaque_element_version_section->sm_data_id !=
         SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    for (secured_message_version_index = 0;
         secured_message_version_index <
         spdm_context->local_context.secured_message_version.spdm_version_count;
         secured_message_version_index++) {

        if (libspdm_get_version_from_version_number(opaque_element_version_section->
                                                    selected_version)
            ==
            libspdm_get_version_from_version_number(spdm_context->local_context.
                                                    secured_message_version
                                                    .spdm_version[secured_message_version_index]))
        {
            return LIBSPDM_STATUS_SUCCESS;
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
