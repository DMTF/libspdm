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
