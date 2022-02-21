/**
 *  Copyright Notice:
 *  Copyright 2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#ifndef __PLATFORM_LIB_H__
#define __PLATFORM_LIB_H__

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param milliseconds     The time interval for which execution is to be suspended, in milliseconds.
 *
 **/
void libspdm_sleep(uint64_t milliseconds);

/**
 * If no heartbeat arrives in seconds, the watchdog timeout event
 * should terminate the session.
 *
 * @param  session_id     Indicate the SPDM session ID.
 * @param  seconds        heartbeat period, in seconds.
 *
 **/
bool libspdm_start_watchdog(uint32_t session_id, uint16_t seconds);

/**
 * stop watchdog.
 *
 * @param  session_id     Indicate the SPDM session ID.
 *
 **/
bool libspdm_stop_watchdog(uint32_t session_id);

/**
 * Reset the watchdog in heartbeat response.
 *
 * @param  session_id     Indicate the SPDM session ID.
 *
 **/
bool libspdm_reset_watchdog(uint32_t session_id);

#endif /* __PLATFORM_LIB_H__ */
