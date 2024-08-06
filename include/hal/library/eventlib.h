/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef EVENTLIB_H
#define EVENTLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
/**
 * Populate the SupportedEventGroupsList field in the SUPPORTED_EVENT_TYPES response.
 *
 * The SPDM specification mandates that, at a minimum, the event notifier must support the DMTF
 * event types and the EventLost event.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  spdm_version  Indicates the negotiated version.
 * @param  supported_event_groups_list      A pointer to the buffer that holds the list of event.
 *                                          groups.
 * @param  supported_event_groups_list_len  On input, the size, in bytes, of the buffer to hold the
 *                                          list of event groups.
 *                                          On output, the size, in bytes, of the list of event
 *                                          groups. This value must be greater than zero.
 * @param  event_group_count  The number of event groups in supported_event_groups_list. This value
 *                            must be greater than 0.
 *
 * @retval true   The event groups list was successfully populated.
 * @retval false  An error occurred when populating the event groups list.
 **/
extern bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count);

/**
 * Subscribe to the events given in SubscribeList.
 *
 * If subscribe_event_group_count is 0 then the event recipient unsubscribes from all events and
 * subscribe_list_len is 0 and subscribe_list is NULL. For a given event group, if
 * SPDM_SUBSCRIBE_EVENT_TYPES_REQUEST_ATTRIBUTE_ALL is set in the Attributes field then the event
 * recipient subscribes to all events in that group.
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  spdm_version                 Indicates the negotiated version.
 * @param  subscribe_event_group_count  Number of event groups in subscribe_list.
 * @param  subscribe_list_len           Size, in bytes, of subscribe_list.
 * @param  subscribe_list               Buffer that contains the event groups to be subscribed.
 *
 * @retval true   All events were successfully subscribed or unsubscribed to.
 * @retval false  An error occurred when processing the event group list.
 **/
extern bool libspdm_event_subscribe(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t subscribe_event_group_count,
    uint32_t subscribe_list_len,
    const void *subscribe_list);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
#endif /* EVENTLIB_H */
