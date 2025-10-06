/**
 *  Copyright Notice:
 *  Copyright 2024-2025 DMTF. All rights reserved.
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

uint32_t g_supported_event_groups_list_len = 8;
uint8_t g_event_group_count = 1;
bool g_event_all_subscribe = false;
bool g_event_all_unsubscribe = false;
uint32_t g_event_count = 1;
bool g_generate_event_list_error = false;
bool g_event_get_types_error = false;
bool g_event_subscribe_error = false;

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count)
{
    if (g_event_get_types_error) {
        return false;
    }

    *supported_event_groups_list_len = g_supported_event_groups_list_len;

    for (uint32_t index = 0; index < *supported_event_groups_list_len; index++)
    {
        ((char *)supported_event_groups_list)[index] = (char)index;
    }

    *event_group_count = g_event_group_count;

    return true;
}

bool libspdm_event_subscribe(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    uint8_t subscribe_type,
    uint8_t subscribe_event_group_count,
    uint32_t subscribe_list_len,
    const void *subscribe_list)
{
    if (g_event_subscribe_error) {
        return false;
    }

    switch (subscribe_type) {
    case LIBSPDM_EVENT_SUBSCRIBE_ALL:
        if ((subscribe_list_len != 0) || (subscribe_list != NULL)) {
            return false;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "Subscribing to all events for session ID 0x%x.\n", session_id));
        g_event_all_subscribe = true;
        g_event_all_unsubscribe = false;
        return true;
    case LIBSPDM_EVENT_SUBSCRIBE_NONE:
        if ((subscribe_list_len != 0) || (subscribe_list != NULL)) {
            return false;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "Unsubscribing from all events for session ID 0x%x.\n", session_id));
        g_event_all_subscribe = false;
        g_event_all_unsubscribe = true;
        return true;
    case LIBSPDM_EVENT_SUBSCRIBE_LIST:
        if ((subscribe_list_len == 0) || (subscribe_list == NULL)) {
            return false;
        }
        break;
    default:
        return false;
    }

    g_event_all_subscribe = false;
    g_event_all_unsubscribe = false;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "subscribe_event_group_count == %d, subscribe_list_len = %d\n",
                   subscribe_event_group_count, subscribe_list_len));

    for (uint32_t index = 0; index < subscribe_list_len; index++) {
        printf("%02x ", ((const char *)subscribe_list)[index]);
    }
    printf("\n");

    return true;
}

bool libspdm_generate_event_list(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    uint32_t *event_count,
    size_t *events_list_size,
    void *events_list)
{
    if (g_generate_event_list_error) {
        return false;
    }

    *event_count = g_event_count;

    for (uint32_t index = 0; index < *events_list_size; index++)
    {
        ((char *)events_list)[index] = (char)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
