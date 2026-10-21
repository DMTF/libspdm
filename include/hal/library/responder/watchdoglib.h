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
 * libspdm calls this function when a session with a non-zero heartbeat period is established, that
 * is, when it sends FINISH_RSP or PSK_FINISH_RSP, or PSK_EXCHANGE_RSP if the session does not use
 * PSK_FINISH. timeout is twice the heartbeat period. If the timer expires then the Integrator must
 * end the session with libspdm_terminate_session(). If false is returned then libspdm sends
 * ERROR(Unspecified).
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 * @param  timeout       Non-zero timeout value, in units of seconds.
 *
 * @retval true   The watchdog timer was started.
 * @retval false  The watchdog timer could not be started.
 **/
extern bool libspdm_start_watchdog(void *spdm_context, uint32_t session_id, uint16_t timeout);

/**
 * Stop the watchdog timer for a given session ID.
 *
 * libspdm calls this function only when it sends END_SESSION_ACK, and it ignores the return value.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 *
 * @retval true   The watchdog timer was stopped.
 * @retval false  The watchdog timer could not be stopped.
 **/
extern bool libspdm_stop_watchdog(void *spdm_context, uint32_t session_id);

/**
 * Reset the watchdog timer for a given session ID.
 *
 * libspdm calls this function each time it sends a response in the session, other than FINISH_RSP,
 * PSK_FINISH_RSP and END_SESSION_ACK, and it ignores the return value.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Indicate the SPDM session ID.
 *
 * @retval true   The watchdog timer was reset.
 * @retval false  The watchdog timer could not be reset.
 **/
extern bool libspdm_reset_watchdog(void *spdm_context, uint32_t session_id);
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

#endif /* RESPONDER_WATCHDOGLIB_H */
