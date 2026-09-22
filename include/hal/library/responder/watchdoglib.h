/**
 *  Copyright Notice:
 *  Copyright 2022-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#ifndef RESPONDER_WATCHDOGLIB_H
#define RESPONDER_WATCHDOGLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
/**
 * Start the watchdog timer for a given session ID.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 * @param  timeout       Non-zero timeout value, in units of seconds.
 **/
extern bool libspdm_start_watchdog(void *spdm_context, uint32_t session_id, uint16_t timeout);

/**
 * Stop the watchdog timer for a given session ID.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 **/
extern bool libspdm_stop_watchdog(void *spdm_context, uint32_t session_id);

/**
 * Reset the watchdog timer for a given session ID.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 **/
extern bool libspdm_reset_watchdog(void *spdm_context, uint32_t session_id);
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

#endif /* RESPONDER_WATCHDOGLIB_H */
