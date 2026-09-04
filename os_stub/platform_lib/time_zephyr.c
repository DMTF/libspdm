/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>

#include <zephyr/kernel.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds  The time interval for which execution is to be suspended,
 *                      in microseconds.
 **/
void libspdm_sleep(uint64_t microseconds)
{
    k_sleep(K_USEC(microseconds));
}
