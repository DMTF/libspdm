/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef DEBUGLIB_INTERNAL_H
#define DEBUGLIB_INTERNAL_H

#include "hal/library/debuglib.h"

/**
 * Internal worker macro that calls libspdm_debug_assert().
 *
 * This macro calls libspdm_debug_assert(), passing in the filename, line number, and an
 * expression that evaluated to false.
 *
 * @param  expression  Boolean expression that evaluated to false
 **/
#define LIBSPDM_ASSERT_INTERNAL(expression) libspdm_debug_assert(__FILE__, __LINE__, #expression)

/**
 * Internal worker macro that calls libspdm_debug_print().
 *
 * This macro calls libspdm_debug_print() passing in the debug error level, a format
 * string, and a variable argument list.
 *
 * @param  expression  Expression containing an error level, a format string,
 *                     and a variable argument list based on the format string.
 **/
#define LIBSPDM_DEBUG_PRINT_INTERNAL(print_level, ...) \
    do { \
        libspdm_debug_print(print_level, ## __VA_ARGS__); \
    } while (false)
#define LIBSPDM_DEBUG_INTERNAL(expression) LIBSPDM_DEBUG_PRINT_INTERNAL expression

/**
 * Macro that calls libspdm_debug_assert() if an expression evaluates to false.
 *
 * @param  expression  Boolean expression.
 **/
#if LIBSPDM_DEBUG_ASSERT_ENABLE
#define LIBSPDM_ASSERT(expression) \
    do { \
        if (!(expression)) { \
            LIBSPDM_ASSERT_INTERNAL(expression); \
        } \
    } while (false)
#else
#define LIBSPDM_ASSERT(expression)
#endif

/**
 * Macro that calls libspdm_debug_print().
 *
 * @param  expression  Expression containing an error level, a format string,
 *                     and a variable argument list based on the format string.
 **/
#if LIBSPDM_DEBUG_PRINT_ENABLE
#define LIBSPDM_DEBUG(expression) \
    do { \
        LIBSPDM_DEBUG_INTERNAL(expression); \
    } while (false)
#else
#define LIBSPDM_DEBUG(expression)
#endif

/**
 * Macro that marks the beginning of debug source code.
 **/
#define LIBSPDM_DEBUG_CODE_BEGIN() \
    do { \
        uint8_t __debug_code_local

/**
 * The macro that marks the end of debug source code.
 **/
#define LIBSPDM_DEBUG_CODE_END() \
    __debug_code_local = 0; \
    __debug_code_local++; \
    } \
    while (false)

/**
 * The macro that declares a section of debug source code.
 **/
#if LIBSPDM_DEBUG_BLOCK_ENABLE
#define LIBSPDM_DEBUG_CODE(expression) \
    LIBSPDM_DEBUG_CODE_BEGIN(); \
    expression LIBSPDM_DEBUG_CODE_END()
#else
#define LIBSPDM_DEBUG_CODE(expression)
#endif

#endif /* DEBUGLIB_INTERNAL_H */
