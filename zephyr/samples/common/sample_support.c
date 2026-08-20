/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Application-side support hooks for the libspdm samples on Zephyr.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <libspdm/zephyr/wallclock.h>

#include "sample_static_blob_store.h"

#include "sample_support.h"

/*
 * Wall-clock seeding.
 *
 * The port deliberately ships no constant of its own (see
 * libspdm/zephyr/include/libspdm/zephyr/wallclock.h): a fixed time is a
 * demo answer, not a product one -- it defeats certificate expiry
 * entirely. So the constant lives here, with the sample certificates it
 * has to agree with.
 */
#if IS_ENABLED(CONFIG_LIBSPDM_WALLCLOCK_RTC)

#include <errno.h>
#include <time.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/rtc.h>

static const struct device *const sample_rtc = DEVICE_DT_GET(DT_ALIAS(rtc));

/* libspdm reads this RTC by itself; setting it is ordinary application
 * work, so the samples do it straight through Zephyr's RTC API. These
 * boards have neither backup power nor a time server, so the RTC would
 * otherwise come up unset. */
int sample_wallclock_init(int64_t unix_seconds)
{
    struct rtc_time rtc_now = { 0 };
    struct tm tm_now;
    time_t when = (time_t)unix_seconds;
    int ret;

    if (!device_is_ready(sample_rtc)) {
        printk("sample: RTC %s not ready\n", sample_rtc->name);
        return -ENODEV;
    }
    if (gmtime_r(&when, &tm_now) == NULL) {
        return -EINVAL;
    }

    rtc_now.tm_sec   = tm_now.tm_sec;
    rtc_now.tm_min   = tm_now.tm_min;
    rtc_now.tm_hour  = tm_now.tm_hour;
    rtc_now.tm_mday  = tm_now.tm_mday;
    rtc_now.tm_mon   = tm_now.tm_mon;
    rtc_now.tm_year  = tm_now.tm_year;
    rtc_now.tm_wday  = tm_now.tm_wday;
    rtc_now.tm_yday  = tm_now.tm_yday;
    rtc_now.tm_isdst = -1;
    rtc_now.tm_nsec  = 0;

    ret = rtc_set_time(sample_rtc, &rtc_now);
    if (ret != 0) {
        printk("sample: could not set RTC %s (%d)\n", sample_rtc->name, ret);
    }
    return ret;
}

#else

static int64_t fixed_wallclock_s;

static int64_t fixed_wallclock(void)
{
    return fixed_wallclock_s;
}

int sample_wallclock_init(int64_t unix_seconds)
{
    fixed_wallclock_s = unix_seconds;
    libspdm_zephyr_wallclock_register(fixed_wallclock);
    return 0;
}

#endif

/*
 * libspdm's contract for libspdm_read_input_file() is:
 *  - allocate a buffer with malloc()
 *  - copy the file contents in
 *  - return the pointer + size to the caller, which will free() it.
 */
bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size)
{
    const struct sample_static_blob *entry;
    void *buf;

    if (file_name == NULL || file_data == NULL || file_size == NULL) {
        return false;
    }

    entry = sample_static_blob_find(file_name);
    if (entry == NULL) {
        printk("libspdm: no embedded blob for \"%s\"\n", file_name);
        return false;
    }

    buf = malloc(entry->length);
    if (buf == NULL) {
        return false;
    }
    memcpy(buf, entry->data, entry->length);

    *file_data = buf;
    *file_size = entry->length;
    return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size)
{
    /* The samples keep their blobs in flash and have no writable store. */
    ARG_UNUSED(file_name);
    ARG_UNUSED(file_data);
    ARG_UNUSED(file_size);
    return false;
}

/*
 * Diagnostic helper the sample device-secret library calls from a few
 * paths (PSK derivation, slot-key dump).
 */
void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    for (size_t i = 0; i < buffer_size; i++) {
        printk("%02x", buffer[i]);
    }
}
