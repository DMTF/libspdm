/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/**
 * @file
 * Wall-clock source for libspdm on Zephyr.
 *
 * X.509 validity-period checks need a wall clock. Where that time
 * comes from is selected at build time by the CONFIG_LIBSPDM_WALLCLOCK
 * choice:
 *
 *   CONFIG_LIBSPDM_WALLCLOCK_RTC
 *      Read a Zephyr RTC device -- the one the "rtc" devicetree alias
 *      points at. Nothing has to be registered at run time. Keeping
 *      that RTC correct (seeding it at boot, resynchronising it) stays
 *      with the application and Zephyr's own RTC API; this module only
 *      reads it.
 *
 *   CONFIG_LIBSPDM_WALLCLOCK_CUSTOM
 *      The application installs the source with
 *      libspdm_zephyr_wallclock_register() -- SNTP, a TF-M secure time
 *      service, an RTC the alias does not cover, or, for a demo, a
 *      constant inside the sample certificates' validity window. Until
 *      it does, libspdm_zephyr_wallclock_get() returns 0 (the Unix
 *      epoch), which makes certificate verification fail loudly rather
 *      than silently accept an expired or not-yet-valid chain.
 *
 * A hard-coded constant is a demo answer, never a product one: it
 * defeats certificate expiry entirely. It therefore belongs with the
 * certificates it has to agree with, in the application, not here. See
 * zephyr/samples/common/sample_support.h for the samples' version.
 */

#ifndef LIBSPDM_ZEPHYR_WALLCLOCK_H
#define LIBSPDM_ZEPHYR_WALLCLOCK_H

#include <stdint.h>

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_LIBSPDM_WALLCLOCK_CUSTOM) || defined(__DOXYGEN__)

/**
 * Wall-clock callback type.
 *
 * @return Seconds elapsed since 1970-01-01T00:00:00Z.
 */
typedef int64_t (*libspdm_zephyr_wallclock_fn)(void);

/**
 * Install the wall-clock source used for X.509 validity checks.
 *
 * Only available with CONFIG_LIBSPDM_WALLCLOCK_CUSTOM.
 *
 * @param fn Callback returning Unix seconds, or NULL to uninstall the
 *           current source and go back to returning 0.
 */
void libspdm_zephyr_wallclock_register(libspdm_zephyr_wallclock_fn fn);

#endif /* CONFIG_LIBSPDM_WALLCLOCK_CUSTOM */

/**
 * Read the current wall-clock time.
 *
 * Called by the port's mbedtls time hook; applications normally have
 * no reason to call this directly.
 *
 * @return Unix seconds from the selected source, or 0 if it is
 *         unavailable or not installed yet.
 */
int64_t libspdm_zephyr_wallclock_get(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBSPDM_ZEPHYR_WALLCLOCK_H */
