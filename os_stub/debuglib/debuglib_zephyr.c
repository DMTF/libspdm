/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdarg.h>
#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/__assert.h>

#include "library/debuglib.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_DEBUG_ASSERT_ENABLE
void libspdm_debug_assert(const char *file_name, size_t line_number, const char *description)
{
    __ASSERT(false, "libspdm assert: %s(%zu): %s",
             file_name, line_number, description);
    /* If __ASSERT is compiled out, fall back to a hard stop. */
    for (;;) {
        k_cpu_idle();
    }
}
#endif /* LIBSPDM_DEBUG_ASSERT_ENABLE */

#if LIBSPDM_DEBUG_PRINT_ENABLE

#define LIBSPDM_MAX_DEBUG_MESSAGE_LENGTH 0x100

#ifndef LIBSPDM_DEBUG_LEVEL_CONFIG
#define LIBSPDM_DEBUG_LEVEL_CONFIG (LIBSPDM_DEBUG_INFO | LIBSPDM_DEBUG_ERROR)
#endif

void libspdm_debug_print(size_t error_level, const char *format, ...)
{
    char buffer[LIBSPDM_MAX_DEBUG_MESSAGE_LENGTH];
    va_list marker;
    int status;

    if ((error_level & LIBSPDM_DEBUG_LEVEL_CONFIG) == 0) {
        return;
    }

    va_start(marker, format);
    status = vsnprintf(buffer, sizeof(buffer), format, marker);
    va_end(marker);

    if (status < 0) {
        return;
    }
    printk("%s", buffer);
}
#endif /* LIBSPDM_DEBUG_PRINT_ENABLE */
