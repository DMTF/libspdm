/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Provides services to print debug and assert messages to a debug output device.
 *
 * The Debug library supports debug print and asserts based on a combination of macros and code.
 * The debug library can be turned on and off so that the debug code does not increase the size of an image.
 *
 * Note that a reserved macro named MDEPKG_NDEBUG is introduced for the intention
 * of size reduction when compiler optimization is disabled. If MDEPKG_NDEBUG is
 * defined, then debug and assert related macros wrapped by it are the NULL implementations.
 **/

#ifndef __DEBUG_LIB_H__
#define __DEBUG_LIB_H__


/* Declare bits for PcdDebugPrintErrorLevel and the error_level parameter of libspdm_debug_print()*/

#define LIBSPDM_DEBUG_INFO 0x00000040 /* Informational debug messages*/
/* Detailed debug messages that may significantly impact boot performance*/
#define LIBSPDM_DEBUG_VERBOSE 0x00400000
#define LIBSPDM_DEBUG_ERROR 0x80000000 /* Error*/

/**
 * Prints a debug message to the debug output device if the specified error level is enabled.
 *
 * If any bit in error_level is also set in DebugPrintErrorLevelLib function
 * GetDebugPrintErrorLevel (), then print the message specified by format and the
 * associated variable argument list to the debug output device.
 *
 * If format is NULL, then ASSERT().
 *
 * @param  error_level  The error level of the debug message.
 * @param  format      The format string for the debug message to print.
 * @param  ...         The variable argument list whose contents are accessed
 *                    based on the format string specified by format.
 *
 **/
void libspdm_debug_print(size_t error_level, const char *format, ...);

/**
 * Prints an assert message containing a filename, line number, and description.
 * This may be followed by a breakpoint or a dead loop.
 *
 * Print a message of the form "ASSERT <file_name>(<line_number>): <description>\n"
 * to the debug output device.  If DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED bit of
 * PcdDebugProperyMask is set then CpuBreakpoint() is called. Otherwise, if
 * DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED bit of PcdDebugProperyMask is set then
 * CpuDeadLoop() is called.  If neither of these bits are set, then this function
 * returns immediately after the message is printed to the debug output device.
 * libspdm_debug_assert() must actively prevent recursion.  If libspdm_debug_assert() is called while
 * processing another libspdm_debug_assert(), then libspdm_debug_assert() must return immediately.
 *
 * If file_name is NULL, then a <file_name> string of "(NULL) Filename" is printed.
 * If description is NULL, then a <description> string of "(NULL) description" is printed.
 *
 * @param  file_name     The pointer to the name of the source file that generated the assert condition.
 * @param  line_number   The line number in the source file that generated the assert condition
 * @param  description  The pointer to the description of the assert condition.
 *
 **/
void libspdm_debug_assert(const char *file_name, size_t line_number,
                          const char *description);

/**
 * Internal worker macro that calls libspdm_debug_assert().
 *
 * This macro calls libspdm_debug_assert(), passing in the filename, line number, and an
 * expression that evaluated to false.
 *
 * @param  expression  Boolean expression that evaluated to false
 *
 **/
#define _LIBSPDM_ASSERT(expression) libspdm_debug_assert(__FILE__, __LINE__, #expression)

/**
 * Internal worker macro that calls libspdm_debug_print().
 *
 * This macro calls libspdm_debug_print() passing in the debug error level, a format
 * string, and a variable argument list.
 * __VA_ARGS__ is not supported by EBC compiler, Microsoft Visual Studio .NET 2003
 * and Microsoft Windows Server 2003 Driver Development Kit (Microsoft WINDDK) version 3790.1830.
 *
 * @param  expression  expression containing an error level, a format string,
 *                    and a variable argument list based on the format string.
 *
 **/

#define _LIBSPDM_DEBUG_PRINT(PrintLevel, ...)                                          \
    do {                                                                   \
        libspdm_debug_print(PrintLevel, ## __VA_ARGS__);                        \
    } while (false)
#define _LIBSPDM_DEBUG(expression) _LIBSPDM_DEBUG_PRINT expression

/**
 * Macro that calls libspdm_debug_assert() if an expression evaluates to false.
 *
 * If MDEPKG_NDEBUG is not defined and the DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED
 * bit of PcdDebugProperyMask is set, then this macro evaluates the Boolean
 * expression specified by expression.  If expression evaluates to false, then
 * libspdm_debug_assert() is called passing in the source filename, source line number,
 * and expression.
 *
 * @param  expression  Boolean expression.
 *
 **/
#if !defined(MDEPKG_NDEBUG)
#define LIBSPDM_ASSERT(expression)                                                     \
    do {                                                                   \
        if (!(expression)) {                                           \
            _LIBSPDM_ASSERT(expression);                                   \
            ANALYZER_UNREACHABLE();                                \
        }                                                              \
    } while (false)
#else
#define LIBSPDM_ASSERT(expression)
#endif

/**
 * Macro that calls libspdm_debug_print().
 *
 * If MDEPKG_NDEBUG is not defined and the DEBUG_PROPERTY_DEBUG_PRINT_ENABLED
 * bit of PcdDebugProperyMask is set, then this macro passes expression to
 * libspdm_debug_print().
 *
 * @param  expression  expression containing an error level, a format string,
 *                    and a variable argument list based on the format string.
 *
 *
 **/
#if !defined(MDEPKG_NDEBUG)
#define LIBSPDM_DEBUG(expression)                                                      \
    do {                                                                   \
        _LIBSPDM_DEBUG(expression);                                            \
    } while (false)
#else
#define LIBSPDM_DEBUG(expression)
#endif

/**
 * Macro that marks the beginning of debug source code.
 *
 * If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
 * then this macro marks the beginning of source code that is included in a module.
 * Otherwise, the source lines between LIBSPDM_LIBSPDM_DEBUG_CODE_BEGIN() and LIBSPDM_LIBSPDM_DEBUG_CODE_END()
 * are not included in a module.
 *
 **/
#define LIBSPDM_DEBUG_CODE_BEGIN()                                                     \
    do {                                                                   \
        uint8_t __debug_code_local

/**
 * The macro that marks the end of debug source code.
 *
 * If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
 * then this macro marks the end of source code that is included in a module.
 * Otherwise, the source lines between LIBSPDM_LIBSPDM_DEBUG_CODE_BEGIN() and LIBSPDM_LIBSPDM_DEBUG_CODE_END()
 * are not included in a module.
 *
 **/
#define LIBSPDM_DEBUG_CODE_END()                                                       \
    __debug_code_local = 0;                                                \
    __debug_code_local++;                                                  \
    }                                                                      \
    while (false)

/**
 * The macro that declares a section of debug source code.
 *
 * If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
 * then the source code specified by expression is included in a module.
 * Otherwise, the source specified by expression is not included in a module.
 *
 **/

#if !defined(MDEPKG_NDEBUG)
#define LIBSPDM_DEBUG_CODE(expression)                                                 \
    LIBSPDM_DEBUG_CODE_BEGIN();                                                    \
    expression LIBSPDM_DEBUG_CODE_END()
#else
#define LIBSPDM_DEBUG_CODE(expression)
#endif

#endif
