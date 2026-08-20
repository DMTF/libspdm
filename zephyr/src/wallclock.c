/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Wall-clock source. See include/libspdm/zephyr/wallclock.h for the
 * rationale and the CONFIG_LIBSPDM_WALLCLOCK choice; the crypto
 * backend consumes it through src/mbedtls_platform_time.c.
 */

#include <stdint.h>

#include <zephyr/kernel.h>

#include <libspdm/zephyr/wallclock.h>

#if defined(CONFIG_LIBSPDM_WALLCLOCK_RTC)

#include <zephyr/devicetree.h>
#include <zephyr/drivers/rtc.h>
#include <zephyr/sys/timeutil.h>

#define WALLCLOCK_RTC_NODE DT_ALIAS(rtc)

BUILD_ASSERT(DT_NODE_HAS_STATUS(WALLCLOCK_RTC_NODE, okay),
             "CONFIG_LIBSPDM_WALLCLOCK_RTC needs an enabled \"rtc\" "
             "devicetree alias; add one in a board overlay or pick "
             "CONFIG_LIBSPDM_WALLCLOCK_CUSTOM instead.");

static const struct device *const wallclock_rtc =
    DEVICE_DT_GET(WALLCLOCK_RTC_NODE);

int64_t libspdm_zephyr_wallclock_get(void)
{
    struct rtc_time rtc_now;

    if (!device_is_ready(wallclock_rtc)) {
        return 0;
    }
    if (rtc_get_time(wallclock_rtc, &rtc_now) != 0) {
        return 0;
    }

    return (int64_t)timeutil_timegm(rtc_time_to_tm(&rtc_now));
}

#else /* CONFIG_LIBSPDM_WALLCLOCK_CUSTOM */

static libspdm_zephyr_wallclock_fn wallclock_fn;

void libspdm_zephyr_wallclock_register(libspdm_zephyr_wallclock_fn fn)
{
    wallclock_fn = fn;
}

int64_t libspdm_zephyr_wallclock_get(void)
{
    libspdm_zephyr_wallclock_fn fn = wallclock_fn;

    return (fn != NULL) ? fn() : 0;
}

#endif /* CONFIG_LIBSPDM_WALLCLOCK_RTC */
