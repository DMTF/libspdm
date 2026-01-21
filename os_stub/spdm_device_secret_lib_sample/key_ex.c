/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "internal/libspdm_common_lib.h"

uint8_t g_key_exchange_start_mut_auth = 0;
bool g_mandatory_mut_auth = false;

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
bool g_generate_key_exchange_opaque_data = false;
size_t libspdm_secret_lib_finish_opaque_data_size;
bool g_generate_finish_opaque_data = false;

bool libspdm_key_exchange_rsp_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_hash_type,
    uint8_t slot_id,
    uint8_t session_policy,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    if (g_generate_key_exchange_opaque_data) {
        size_t version_selection_data_size;
        version_selection_data_size = sizeof(spdm_general_opaque_data_table_header_t) +
                                      sizeof(secured_message_opaque_element_table_header_t) +
                                      sizeof(secured_message_opaque_element_version_selection_t);

        LIBSPDM_ASSERT(*opaque_data_size >= version_selection_data_size);
        *opaque_data_size = version_selection_data_size;

        if (opaque_data != NULL) {
            spdm_general_opaque_data_table_header_t *spdm_general_opaque_data_table_header;
            secured_message_opaque_element_table_header_t *opaque_element_table_header;
            secured_message_opaque_element_version_selection_t *opaque_element_version_section;

            spdm_general_opaque_data_table_header = opaque_data;
            spdm_general_opaque_data_table_header->total_elements = 1;
            libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);

            opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);
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
                SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        }

        return true;
    }
    return false;
}

bool libspdm_finish_rsp_opaque_data(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t req_slot_id,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    if (g_generate_finish_opaque_data) {
        LIBSPDM_ASSERT(libspdm_secret_lib_finish_opaque_data_size <= *opaque_data_size);

        *opaque_data_size = libspdm_secret_lib_finish_opaque_data_size;

        if (opaque_data != NULL) {
            for (size_t index = 0; index < *opaque_data_size; index++)
            {
                ((uint8_t *)opaque_data)[index] = (uint8_t)(index + 1);
            }
        }
    } else {
        *opaque_data_size = 0;
    }

    return true;
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
extern uint8_t libspdm_key_exchange_start_mut_auth(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *req_slot_id,
    uint8_t session_policy,
    size_t opaque_data_length,
    const void *opaque_data,
    bool *mandatory_mut_auth)
{
    *req_slot_id = 0;
    *mandatory_mut_auth = g_mandatory_mut_auth;

    return g_key_exchange_start_mut_auth;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
