/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * C Run-Time Libraries (CRT) Wrapper Implementation.
 **/

#include <base.h>
#include "library/debuglib.h"
#include "library/memlib.h"
#include <mbedtls/build_info.h>
#include <stddef.h>

int my_printf(const char *fmt, ...)
{
    LIBSPDM_ASSERT(false);
    return 0;
}

int my_snprintf(char *str, size_t size, const char *format, ...)
{
    LIBSPDM_ASSERT(false);
    return 0;
}

#ifdef MBEDTLS_PLATFORM_ZEROIZE_ALT
void mbedtls_platform_zeroize(void *buf, size_t len)
{
    /* Mbed TLS can pass a NULL buf when len is 0, which libspdm_zero_mem() does not accept. */
    if (len != 0) {
        libspdm_zero_mem(buf, len);
    }
}
#endif /* MBEDTLS_PLATFORM_ZEROIZE_ALT */
