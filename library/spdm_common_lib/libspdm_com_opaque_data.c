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
size_t libspdm_get_opaque_data_version_selection_data_size(const libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
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
 * Return the size in bytes of opaque data supported version.
 *
 * This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.
 *
 * @return the size in bytes of opaque data supported version.
 **/
size_t libspdm_get_opaque_data_supported_version_data_size(libspdm_context_t *spdm_context)
{
    size_t size;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) *
               spdm_context->local_context.secured_message_version.spdm_version_count;
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) *
               spdm_context->local_context.secured_message_version.spdm_version_count;
    }
    /* Add Padding*/
    return (size + 3) & ~3;
}

/**
 * Return the size in bytes of opaque data supported version.
 *
 * This function should be called in libspdm_process_opaque_data_supported_version_data.
 *
 * @param  version_count                 Secure version count.
 *
 * @return the size in bytes of opaque data supported version.
 **/
size_t libspdm_get_untrusted_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context, uint8_t version_count)
{
    size_t size;

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) * version_count;
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t) +
               sizeof(secured_message_opaque_element_table_header_t) +
               sizeof(secured_message_opaque_element_supported_version_t) +
               sizeof(spdm_version_number_t) * version_count;
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
libspdm_return_t libspdm_build_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
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

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size = libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = 1;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);
        opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id = SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version = SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = 1;
        general_opaque_data_table_header->reserved = 0;
        opaque_element_table_header = (void *)(general_opaque_data_table_header + 1);
    }

    opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
    opaque_element_table_header->vendor_len = 0;
    opaque_element_table_header->opaque_element_data_len =
        sizeof(secured_message_opaque_element_supported_version_t) +
        sizeof(spdm_version_number_t) *
        spdm_context->local_context.secured_message_version.spdm_version_count;

    opaque_element_support_version = (void *)(opaque_element_table_header + 1);
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
 * Get element from multi element opaque data by element id.
 *
 * This function should be called in
 * libspdm_process_opaque_data_supported_version_data/libspdm_process_opaque_data_version_selection_data.
 *
 * @param[in]  data_in_size                size of multi element opaque data.
 * @param[in]  data_in                     A pointer to the multi element opaque data.
 * @param[in]  element_id                  element id.
 * @param[in]  sm_data_id                  sm_data_id to identifiy for the Secured Message data type.
 * @param[out] get_element_ptr             pointer to store finded element
 *
 * @retval true                            get element successfully
 * @retval false                           get element failed
 **/
bool libspdm_get_element_from_opaque_data(libspdm_context_t *spdm_context,
                                          size_t data_in_size, const void *data_in,
                                          uint8_t element_id, uint8_t sm_data_id,
                                          const void **get_element_ptr, size_t *get_element_len)
{
    const secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    const spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    const secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    const secured_message_opaque_element_header_t
    * secured_message_element_header;

    bool result;
    uint8_t element_num;
    uint8_t element_index;
    size_t data_element_size;
    size_t current_element_len;
    size_t total_element_len;

    total_element_len = 0;
    result = false;

    /*check parameter in*/
    if (element_id > SPDM_REGISTRY_ID_JEDEC) {
        return false;
    }
    if ((data_in_size == 0) || (data_in == NULL)) {
        return false;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(spdm_general_opaque_data_table_header_t)) {
            return false;
        }
        if (spdm_general_opaque_data_table_header->total_elements < 1) {
            return false;
        }
        opaque_element_table_header = (const void *)(spdm_general_opaque_data_table_header + 1);

        element_num = spdm_general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size - sizeof(spdm_general_opaque_data_table_header_t);
    } else {
        general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(secured_message_general_opaque_data_table_header_t)) {
            return false;
        }
        if ((general_opaque_data_table_header->spec_id !=
             SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
            (general_opaque_data_table_header->opaque_version !=
             SECURED_MESSAGE_OPAQUE_VERSION) ||
            (general_opaque_data_table_header->total_elements < 1)) {
            return false;
        }
        opaque_element_table_header = (const void *)(general_opaque_data_table_header + 1);

        element_num = general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size -
                            sizeof(secured_message_general_opaque_data_table_header_t);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*ensure the opaque_element_table_header is valid*/
        if (total_element_len + sizeof(secured_message_opaque_element_table_header_t) >
            data_element_size) {
            return false;
        }

        /*check element header id*/
        if ((opaque_element_table_header->id > SPDM_REGISTRY_ID_JEDEC) ||
            (opaque_element_table_header->vendor_len != 0)) {
            return false;
        }

        current_element_len = sizeof(secured_message_opaque_element_table_header_t) +
                              opaque_element_table_header->opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;

        total_element_len += current_element_len;

        if (data_element_size < total_element_len) {
            return false;
        }

        if (opaque_element_table_header->id == element_id) {
            secured_message_element_header = (const void *)(opaque_element_table_header + 1);
            if ((const uint8_t *)secured_message_element_header +
                sizeof(secured_message_opaque_element_header_t) >
                (const uint8_t *)data_in + data_in_size) {
                return false;
            }

            if ((secured_message_element_header->sm_data_id == sm_data_id) &&
                (secured_message_element_header->sm_data_version ==
                 SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION)) {
                /*get element by element id*/
                *get_element_ptr = opaque_element_table_header;
                *get_element_len = current_element_len;
                result = true;
            }
        }

        /*move to next element*/
        opaque_element_table_header = (const secured_message_opaque_element_table_header_t *)
                                      ((const uint8_t *)opaque_element_table_header +
                                       current_element_len);
    }

    /*ensure data size is right*/
    if (data_element_size != total_element_len) {
        return false;
    }

    return result;
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
                                                   const void *data_in)
{
    const secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    const secured_message_opaque_element_supported_version_t
    *opaque_element_support_version;
    const spdm_version_number_t *versions_list;
    spdm_version_number_t common_version;
    uint8_t version_count;

    bool result;
    const void *get_element_ptr;
    size_t get_element_len;

    result = false;
    get_element_ptr = NULL;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (data_in_size < libspdm_get_untrusted_opaque_data_supported_version_data_size(spdm_context,
                                                                                     1)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    result = libspdm_get_element_from_opaque_data(
        spdm_context, data_in_size,
        data_in, SPDM_REGISTRY_ID_DMTF,
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,
        &get_element_ptr, &get_element_len);
    if ((!result) || (get_element_ptr == NULL)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"get element error!\n"));
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    opaque_element_table_header = (const secured_message_opaque_element_table_header_t*)
                                  get_element_ptr;

    /*check for supported vesion data*/
    opaque_element_support_version = (const void *)(opaque_element_table_header + 1);

    if ((const uint8_t *)opaque_element_support_version +
        sizeof(secured_message_opaque_element_supported_version_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (opaque_element_support_version->version_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    version_count = opaque_element_support_version->version_count;

    if ((opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_supported_version_t) +
         sizeof(spdm_version_number_t) * version_count)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    versions_list = (const void *)(opaque_element_support_version + 1);

    if ((const uint8_t *)versions_list + sizeof(spdm_version_number_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    result = libspdm_negotiate_connection_version(
        &common_version,
        spdm_context->local_context.secured_message_version.spdm_version,
        spdm_context->local_context.secured_message_version.spdm_version_count,
        versions_list,
        version_count);
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

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size = libspdm_get_opaque_data_version_selection_data_size(spdm_context);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = 1;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);

        opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id = SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version = SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = 1;
        general_opaque_data_table_header->reserved = 0;

        opaque_element_table_header = (void *)(general_opaque_data_table_header + 1);
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
libspdm_return_t libspdm_process_opaque_data_version_selection_data(libspdm_context_t *spdm_context,
                                                                    size_t data_in_size,
                                                                    void *data_in)
{
    const secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    const secured_message_opaque_element_version_selection_t
    *opaque_element_version_section;

    bool result;
    uint8_t secured_message_version_index;
    const void *get_element_ptr;
    size_t get_element_len;

    result = false;
    get_element_ptr = NULL;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    result = libspdm_get_element_from_opaque_data(
        spdm_context, data_in_size,
        data_in, SPDM_REGISTRY_ID_DMTF,
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,
        &get_element_ptr, &get_element_len);
    if ((!result) || (get_element_ptr == NULL)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"get element error!\n"));
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    opaque_element_table_header = (const secured_message_opaque_element_table_header_t*)
                                  get_element_ptr;

    /*check for selection vesion data*/
    if ((opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_version_selection_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    opaque_element_version_section = (const void *)(opaque_element_table_header + 1);

    if ((const uint8_t *)opaque_element_version_section +
        sizeof(secured_message_opaque_element_version_selection_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    for (secured_message_version_index = 0;
         secured_message_version_index <
         spdm_context->local_context.secured_message_version.spdm_version_count;
         secured_message_version_index++) {
        if (libspdm_get_version_from_version_number(opaque_element_version_section->
                                                    selected_version)
            ==
            libspdm_get_version_from_version_number(
                spdm_context->local_context.secured_message_version.spdm_version[
                    secured_message_version_index])) {
            return LIBSPDM_STATUS_SUCCESS;
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
