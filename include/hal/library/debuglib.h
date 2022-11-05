/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef DEBUG_LIB_H
#define DEBUG_LIB_H

/** @file
 * Provides services to print debug and assert messages to a debug output device.
 *
 * The debug library supports debug print and asserts based on a combination of macros and code.
 * The debug library can be turned on and off so that the debug code does not increase the size of an image.
 **/

#include "internal/libspdm_lib_config.h"

/* Declare bits for the error_level parameter of libspdm_debug_print(). */
#define LIBSPDM_DEBUG_INFO 0x00000040
#define LIBSPDM_DEBUG_ERROR 0x80000000

#if LIBSPDM_DEBUG_PRINT_ENABLE
/**
 * Prints a debug message to the debug output device if the specified error level is enabled.
 *
 * @param  error_level  The error level of the debug message, either LIBSPDM_DEBUG_INFO or
 *                      LIBSPDM_DEBUG_ERROR.
 * @param  format       The format string for the debug message to print.
 * @param  ...          The variable argument list whose contents are accessed
 *                      based on the format string specified by format.
 **/
extern void libspdm_debug_print(size_t error_level, const char *format, ...);
#endif /* LIBSPDM_DEBUG_PRINT_ENABLE */

#if LIBSPDM_DEBUG_ASSERT_ENABLE
/**
 * Prints an assert message containing a filename, line number, and description.
 * This may be followed by a breakpoint or a dead loop.
 *
 * @param  file_name     The pointer to the name of the source file that generated the assert condition.
 * @param  line_number   The line number in the source file that generated the assert condition
 * @param  description  The pointer to the description of the assert condition.
 *
 **/
extern void libspdm_debug_assert(const char *file_name, size_t line_number,
                                 const char *description);
#endif /* LIBSPDM_DEBUG_ASSERT_ENABLE */


#endif /* DEBUG_LIB_H */
