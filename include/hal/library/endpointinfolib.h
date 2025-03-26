/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef ENDPOINTINFOLIB_H
#define ENDPOINTINFOLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP

/**
 * Endpoint Info Response Get Device Class Identifier Function Pointer.
 * Required to be able to return the Device Class Identifier correctly
 *
 * @param  spdm_context         A pointer to the SPDM context.
 * @param  sub_code             The subcode of endpoint info, should be one of the
 *                              SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_* values.
 * @param  request_attributes   The request attributes of the endpoint info.
 * @param  endpoint_info_size   On input, the size, in bytes, of the buffer to hold
 *                              the device class identifier.
 *                              On output, the size, in bytes, of the device class identifier.
 * @param  endpoint_info        The buffer to hold the device class identifier content.
 *
 * @retval LIBSPDM_STATUS_SUCCESS          Success.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP  The operation is not supported.
 * @retval LIBSPDM_STATUS_BUFFER_TOO_SMALL The buffer is too small to hold the device class identifier.
 **/
extern libspdm_return_t libspdm_generate_device_endpoint_info(
    void *spdm_context,
    uint8_t sub_code,
    uint8_t request_attributes,
    uint32_t *endpoint_info_size,
    void *endpoint_info);

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP */

#endif /* ENDPOINTINFOLIB_H */
