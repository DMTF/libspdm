/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
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

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count)
{
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
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
