/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

uint16_t libspdm_allocate_req_session_id(libspdm_context_t *spdm_context)
{
    uint16_t req_session_id;
    libspdm_session_info_t *session_info;
    size_t index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF0000) == (INVALID_SESSION_ID & 0xFFFF0000)) {
            req_session_id = (uint16_t)(0xFFFF - index);
            return req_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_req_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}

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
