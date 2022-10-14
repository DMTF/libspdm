/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * C Run-Time Libraries (CRT) Time Management Routines Wrapper Implementation.
 **/
#define _POSIX_C_SOURCE 200112L

#include <base.h>
#include "library/memlib.h"
#include <mbedtls/platform_time.h>

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf)
{
#ifdef _MSC_VER
    if (gmtime_s(tm_buf, tt) != 0) {
        return NULL;
    }

    return tm_buf;
#else
#if 0
    if (gmtime_r(tt, tm_buf) == NULL) {
        return NULL;
    }

    return tm_buf;
#endif
    return NULL;
#endif
}
