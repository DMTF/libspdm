/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Zephyr implementations of the platform hooks the vendored mbedTLS
 * 3.6.5 used by libspdm expects. mbedtls needs:
 * - mbedtls_ms_time : monotonic ms clock. Routed to k_uptime_get().
 * Signaled with MBEDTLS_PLATFORM_MS_TIME_ALT.
 * - mbedtls_time    : wall-clock time used by X.509 validity-period
 * checks. Zephyr has no wall clock by default, so this is routed to
 * the source selected by CONFIG_LIBSPDM_WALLCLOCK (see
 * include/libspdm/zephyr/wallclock.h): either a Zephyr RTC or a
 * callback the application installs. Signaled with
 * MBEDTLS_PLATFORM_TIME_ALT.
 *
 * Both flags are set as compile definitions on the libspdm
 * zephyr_library by zephyr/CMakeLists.txt.
 */
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <mbedtls/build_info.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>

#include <libspdm/zephyr/wallclock.h>

mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)k_uptime_get();
}

static mbedtls_time_t libspdm_zephyr_mbedtls_time(mbedtls_time_t *t)
{
    mbedtls_time_t now = (mbedtls_time_t)libspdm_zephyr_wallclock_get();

    if (t != NULL) {
        *t = now;
    }
    return now;
}

static int libspdm_mbedtls_time_init(void)
{
    mbedtls_platform_set_time(libspdm_zephyr_mbedtls_time);
    return 0;
}

SYS_INIT(libspdm_mbedtls_time_init, APPLICATION, 0);
