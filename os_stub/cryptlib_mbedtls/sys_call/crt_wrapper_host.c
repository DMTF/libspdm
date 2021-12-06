/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation.
**/

#include <base.h>
#include <library/debuglib.h>
#include <library/memlib.h>
#include <stddef.h>

int my_printf(const char *fmt, ...)
{
    ASSERT(FALSE);
    return 0;
}

int (*mbedtls_printf)(const char *format, ...) = my_printf;

int my_snprintf(char *str, size_t size, const char *format, ...)
{
    ASSERT(FALSE);
    return 0;
}

int (*mbedtls_snprintf)(char *s, size_t n, const char *format,
            ...) = my_snprintf;

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    zero_mem(buf, len);
}
