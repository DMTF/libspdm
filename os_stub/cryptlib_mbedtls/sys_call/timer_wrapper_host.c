/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * C Run-Time Libraries (CRT) Time Management Routines Wrapper Implementation.
 **/
#define _POSIX_C_SOURCE 200112L

#include "hal/base.h"
#include "hal/library/memlib.h"
#include <mbedtls/platform_time.h>
struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf)
{
#if defined(_MSC_VER)
    if (gmtime_s(tm_buf, tt) != 0) {
        return NULL;
    }

    return tm_buf;
#elif defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || defined(LIBSPDM_CPU_ARM))
    struct tm *lt;

    lt = gmtime(tt);

    if (lt != NULL) {
        libspdm_copy_mem(tm_buf, sizeof(struct tm), lt, sizeof(struct tm));
    }

    return ((lt == NULL) ? NULL : tm_buf);
#else
    if (gmtime_r(tt, tm_buf) == NULL) {
        return NULL;
    }

    return tm_buf;
#endif
}
