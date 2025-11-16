/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#ifdef LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP

libspdm_return_t libspdm_generate_device_endpoint_info(
    void *spdm_context,
    uint8_t sub_code,
    uint8_t request_attributes,
    uint32_t *endpoint_info_size,
    void *endpoint_info)
{
    uint8_t *ptr;
    spdm_endpoint_info_device_class_identifier_t *device_class_identifier;
    spdm_endpoint_info_device_class_identifier_element_t *identifier;
    uint8_t *num_sub_ids;
    spdm_endpoint_info_device_class_identifier_subordinate_id_t *subordinate_id;
    uint8_t *sub_identifier;
    uint32_t ep_info_size;

    LIBSPDM_ASSERT(endpoint_info_size != NULL);
    LIBSPDM_ASSERT(endpoint_info != NULL);

    switch (sub_code) {
    case SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER:
        ep_info_size = sizeof(spdm_endpoint_info_device_class_identifier_t) +
                       sizeof(spdm_endpoint_info_device_class_identifier_element_t) +
                       sizeof(uint8_t) +
                       sizeof(spdm_endpoint_info_device_class_identifier_subordinate_id_t) +
                       3;

        if (*endpoint_info_size < ep_info_size) {
            *endpoint_info_size = ep_info_size;
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        *endpoint_info_size = ep_info_size;

        ptr = (uint8_t *)endpoint_info;
        device_class_identifier = (spdm_endpoint_info_device_class_identifier_t *) ptr;
        device_class_identifier->num_identifiers = 1;

        ptr += sizeof(spdm_endpoint_info_device_class_identifier_t);
        identifier = (spdm_endpoint_info_device_class_identifier_element_t *) ptr;
        identifier->id_elem_length =
            sizeof(spdm_svh_header_t) + sizeof(uint8_t) +
            sizeof(spdm_endpoint_info_device_class_identifier_subordinate_id_t) + 3;

        identifier->svh.id = 0x0;
        identifier->svh.vendor_id_len = 0x0;
        /* DMTF does not have a Vendor ID registry*/
        ptr += sizeof(spdm_endpoint_info_device_class_identifier_element_t);

        /* a fake sub id for structure sample*/
        num_sub_ids = (uint8_t *) ptr;
        *num_sub_ids = 1;

        ptr += sizeof(uint8_t);
        subordinate_id = (spdm_endpoint_info_device_class_identifier_subordinate_id_t *) ptr;
        subordinate_id->sub_id_len = 0x3;

        ptr += sizeof(spdm_endpoint_info_device_class_identifier_subordinate_id_t);
        sub_identifier = (uint8_t *) ptr;
        sub_identifier[0] = 0x12;
        sub_identifier[1] = 0x34;
        sub_identifier[2] = 0x56;

        break;
    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP */
