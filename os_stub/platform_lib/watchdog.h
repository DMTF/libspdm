/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PLATFORM_LIB_WATCHDOG_H
#define PLATFORM_LIB_WATCHDOG_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
/**
 * The watchdog calls that libspdm has made, so that a test can check the calls against the
 * behavior the specification requires of the Responder.
 **/
typedef struct {
    size_t start_count;
    size_t stop_count;
    size_t reset_count;
    uint32_t start_session_id;
    uint32_t stop_session_id;
    uint32_t reset_session_id;
    uint16_t start_timeout;
} libspdm_watchdog_stats_t;

/**
 * Return the watchdog calls recorded since the last call to libspdm_watchdog_clear_stats().
 **/
const libspdm_watchdog_stats_t *libspdm_watchdog_get_stats(void);

/**
 * Discard the recorded watchdog calls.
 **/
void libspdm_watchdog_clear_stats(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

#endif /* PLATFORM_LIB_WATCHDOG_H */
