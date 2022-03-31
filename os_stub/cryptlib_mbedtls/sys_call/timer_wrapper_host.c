/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * C Run-Time Libraries (CRT) Time Management Routines Wrapper Implementation.
 **/

#include <base.h>
#include "library/memlib.h"
#include <mbedtls/platform_time.h>

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf)
{
    struct tm *lt;

    lt = gmtime(tt);

    if (lt != NULL) {
        libspdm_copy_mem(tm_buf, sizeof(struct tm), lt, sizeof(struct tm));
    }

    return ((lt == NULL) ? NULL : tm_buf);
}
