/**
 *  Copyright Notice:
 *  Copyright 2022-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "base.h"
#include "internal/libspdm_lib_config.h"
#include "library/debuglib.h"
#include "watchdog.h"

#if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
static libspdm_watchdog_stats_t m_libspdm_watchdog_stats;

const libspdm_watchdog_stats_t *libspdm_watchdog_get_stats(void)
{
    return &m_libspdm_watchdog_stats;
}

void libspdm_watchdog_clear_stats(void)
{
    m_libspdm_watchdog_stats.start_count = 0;
    m_libspdm_watchdog_stats.stop_count = 0;
    m_libspdm_watchdog_stats.reset_count = 0;
    m_libspdm_watchdog_stats.start_session_id = 0;
    m_libspdm_watchdog_stats.stop_session_id = 0;
    m_libspdm_watchdog_stats.reset_session_id = 0;
    m_libspdm_watchdog_stats.start_timeout = 0;
}

bool libspdm_start_watchdog(void *spdm_context, uint32_t session_id, uint16_t seconds)
{
    m_libspdm_watchdog_stats.start_count++;
    m_libspdm_watchdog_stats.start_session_id = session_id;
    m_libspdm_watchdog_stats.start_timeout = seconds;

    LIBSPDM_ASSERT(seconds != 0);

    return true;
}

bool libspdm_stop_watchdog(void *spdm_context, uint32_t session_id)
{
    m_libspdm_watchdog_stats.stop_count++;
    m_libspdm_watchdog_stats.stop_session_id = session_id;

    return true;
}

bool libspdm_reset_watchdog(void *spdm_context, uint32_t session_id)
{
    m_libspdm_watchdog_stats.reset_count++;
    m_libspdm_watchdog_stats.reset_session_id = session_id;

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */
