/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"

#pragma pack(1)
typedef struct {
    uint8_t id;
    uint8_t vendor_id_len;
} event_group_id_0byte_t;

typedef struct {
    uint8_t id;
    uint8_t vendor_id_len;
    uint16_t vendor_id;
} event_group_id_2byte_t;

typedef struct {
    uint16_t event_type_count;
    uint16_t event_group_ver;
    uint32_t attributes;
    /* uint8_t event_type_list[] */
} event_group_t;

typedef struct {
    uint16_t event_type_id;
    uint16_t reserved;
} event_type_t;
#pragma pack()

void generate_dmtf_event_group(void *buffer, uint8_t *total_bytes, uint32_t attributes,
                               bool inc_event_lost, bool inc_meas_changed,
                               bool inc_meas_pre_update, bool inc_cert_changed)
{
    uint8_t *ptr;
    uint16_t event_type_count;

    LIBSPDM_ASSERT(!(attributes & SPDM_SUBSCRIBE_EVENT_TYPES_REQUEST_ATTRIBUTE_ALL) ||
                   (!inc_event_lost && !inc_meas_changed &&
                    !inc_meas_pre_update && !inc_cert_changed));

    event_type_count = 0;

    if (inc_event_lost) {
        event_type_count++;
    }
    if (inc_meas_changed) {
        event_type_count++;
    }
    if (inc_meas_pre_update) {
        event_type_count++;
    }
    if (inc_cert_changed) {
        event_type_count++;
    }

    ptr = buffer;
    *total_bytes = 0;

    ((event_group_id_0byte_t *)ptr)->id = SPDM_REGISTRY_ID_DMTF;
    ((event_group_id_0byte_t *)ptr)->vendor_id_len = 0;

    ptr += sizeof(event_group_id_0byte_t);
    *total_bytes += (uint8_t)sizeof(event_group_id_0byte_t);

    ((event_group_t *)ptr)->event_type_count = event_type_count;
    ((event_group_t *)ptr)->event_group_ver = 1;
    ((event_group_t *)ptr)->attributes = attributes;

    ptr += sizeof(event_group_t);
    *total_bytes += (uint8_t)sizeof(event_group_t);

    if (inc_event_lost) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_EVENT_LOST;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_meas_changed) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_MEASUREMENT_CHANGED;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_meas_pre_update) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_MEASUREMENT_PRE_UPDATE;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_cert_changed) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED;
        ((event_type_t *)ptr)->reserved = 0;
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
}
