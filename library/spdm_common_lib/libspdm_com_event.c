/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

bool libspdm_validate_dmtf_event_type(uint16_t event_type_id, uint16_t event_detail_len)
{
    switch (event_type_id) {
    case SPDM_DMTF_EVENT_TYPE_EVENT_LOST:
        return (event_detail_len == SPDM_DMTF_EVENT_TYPE_EVENT_LOST_SIZE);
    case SPDM_DMTF_EVENT_TYPE_MEASUREMENT_CHANGED:
        return (event_detail_len == SPDM_DMTF_EVENT_TYPE_MEASUREMENT_CHANGED_SIZE);
    case SPDM_DMTF_EVENT_TYPE_MEASUREMENT_PRE_UPDATE:
        return (event_detail_len == SPDM_DMTF_EVENT_TYPE_MEASUREMENT_PRE_UPDATE_SIZE);
    case SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED:
        return (event_detail_len == SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED_SIZE);
    default:
        return false;
    }
}

bool libspdm_parse_and_send_event(libspdm_context_t *context, uint32_t session_id,
                                  const void *event_data, const void **next_event_data)
{
    libspdm_return_t status;
    const uint8_t *ptr;
    uint32_t event_instance_id;
    uint8_t svh_id;
    uint8_t svh_vendor_id_len;
    const void *svh_vendor_id;
    uint16_t event_type_id;
    uint16_t event_detail_len;

    LIBSPDM_ASSERT(context->process_event != NULL);

    ptr = event_data;
    event_instance_id = libspdm_read_uint32(ptr);

    ptr += sizeof(uint32_t);
    ptr += sizeof(uint32_t);
    svh_id = *ptr;
    ptr++;
    svh_vendor_id_len = *ptr;
    ptr++;

    if (svh_vendor_id_len == 0) {
        svh_vendor_id = NULL;
    } else {
        svh_vendor_id = ptr;
    }
    ptr += svh_vendor_id_len;

    event_type_id = libspdm_read_uint16(ptr);
    ptr += sizeof(uint16_t);
    event_detail_len = libspdm_read_uint16(ptr);
    ptr += sizeof(uint16_t);

    status = context->process_event(context, session_id, event_instance_id, svh_id,
                                    svh_vendor_id_len, svh_vendor_id, event_type_id,
                                    event_detail_len, ptr);

    if (next_event_data != NULL) {
        ptr += event_detail_len;
        *next_event_data = ptr;
    }

    return (status == LIBSPDM_STATUS_SUCCESS);
}

const void *libspdm_find_event_instance_id(const void *events_list_start, uint32_t event_count,
                                           uint32_t target_event_instance_id)
{
    uint32_t index;
    const uint8_t *ptr;

    ptr = events_list_start;

    for (index = 0; index < event_count; index++) {
        uint32_t event_instance_id;

        event_instance_id = libspdm_read_uint32(ptr);

        if (event_instance_id == target_event_instance_id) {
            return ptr;
        } else {
            uint8_t vendor_id_len;
            uint16_t event_detail_len;

            ptr += sizeof(uint32_t) +  sizeof(uint32_t) + sizeof(uint8_t);
            vendor_id_len = *ptr;
            ptr += sizeof(uint8_t);
            ptr += vendor_id_len;
            ptr += sizeof(uint16_t);
            event_detail_len = libspdm_read_uint16(ptr);
            ptr += sizeof(uint16_t);
            ptr += event_detail_len;
        }
    }

    return NULL;
}

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
