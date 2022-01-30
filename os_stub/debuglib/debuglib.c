/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "library/debuglib.h"


/* Define the maximum debug and assert message length that this library supports*/

#define MAX_DEBUG_MESSAGE_LENGTH 0x100

#define DEBUG_ASSERT_NATIVE 0
#define DEBUG_ASSERT_DEADLOOP 1
#define DEBUG_ASSERT_BREAKPOINT 2

#ifndef DEBUG_ASSERT_CONFIG
#define DEBUG_ASSERT_CONFIG DEBUG_ASSERT_DEADLOOP
#endif

#ifndef DEBUG_LEVEL_CONFIG
#define DEBUG_LEVEL_CONFIG (DEBUG_INFO | DEBUG_ERROR)
#endif

void debug_assert(IN const char *file_name, IN uintn line_number,
                  IN const char *description)
{
    printf("ASSERT: %s(%d): %s\n", file_name, (int32_t)(uint32_t)line_number,
           description);

#if (DEBUG_ASSERT_CONFIG == DEBUG_ASSERT_DEADLOOP)
    {
        volatile intn ___i = 1;
        while (___i)
            ;
    }
#elif (DEBUG_ASSERT_CONFIG == DEBUG_ASSERT_BREAKPOINT)
#if defined(_MSC_EXTENSIONS)
    __debugbreak();
#endif
#if defined(__GNUC__)
    __asm__ __volatile__ ("int $3");
#endif
#endif

    assert(FALSE);
}

void debug_print(IN uintn error_level, IN const char *format, ...)
{
    char buffer[MAX_DEBUG_MESSAGE_LENGTH];
    va_list marker;

    if ((error_level & DEBUG_LEVEL_CONFIG) == 0) {
        return;
    }

    va_start(marker, format);

    vsnprintf(buffer, sizeof(buffer), format, marker);

    va_end(marker);

    printf("%s", buffer);
}
