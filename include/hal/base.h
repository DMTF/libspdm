/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __BASE_H__
#define __BASE_H__


/* Include processor specific binding*/

#include <processor_bind.h>

#if defined(_MSC_EXTENSIONS)

/* Disable warning when last field of data structure is a zero sized array.*/

#pragma warning(disable : 4200)
#endif


/* The Microsoft* C compiler can removed references to unreferenced data items
 *  if the /OPT:REF linker option is used. We defined a macro as this is a
 *  a non standard extension*/

#if defined(_MSC_EXTENSIONS) && _MSC_VER < 1800

/* Remove global variable from the linked image if there are no references to
 * it after all compiler and linker optimizations have been performed.*/


#define LIBSPDM_GLOBAL_REMOVE_IF_UNREFERENCED __declspec(selectany)
#else

/* Remove the global variable from the linked image if there are no references
 *  to it after all compiler and linker optimizations have been performed.*/


#define LIBSPDM_GLOBAL_REMOVE_IF_UNREFERENCED
#endif


/* Modifiers for data Types used to self document code.*/


/**
 * Return the size of argument that has been aligned to sizeof (size_t).
 *
 * @param  n    The parameter size to be aligned.
 *
 * @return The aligned size.
 **/
#define _LIBSPDM_INT_SIZE_OF(n) ((sizeof(n) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))

#if defined(__CC_arm)

/* RVCT arm variable argument list support.*/



/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

#ifdef __APCS_ADSABI
typedef int *va_list[1];
#define LIBSPDM_VA_LIST va_list
#else
typedef struct __va_list {
    void *__ap;
} va_list;
#define LIBSPDM_VA_LIST va_list
#endif

#define LIBSPDM_VA_START(marker, parameter) __va_start(marker, parameter)

#define LIBSPDM_VA_ARG(marker, TYPE) __va_arg(marker, TYPE)

#define LIBSPDM_VA_END(marker) ((void)0)

/* For some arm RVCT compilers, __va_copy is not defined*/
#ifndef __va_copy
#define __va_copy(dest, src) ((void)((dest) = (src)))
#endif

#elif defined(_M_arm) || defined(_M_arm64)

/* MSFT arm variable argument list support.*/


typedef char *LIBSPDM_VA_LIST;

#define LIBSPDM_VA_START(marker, parameter)                                            \
    __va_start(&marker, &parameter, _LIBSPDM_INT_SIZE_OF(parameter),               \
               __alignof(parameter), &parameter)
#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _LIBSPDM_INT_SIZE_OF(TYPE) +                             \
                          ((-(size_t)marker) & (sizeof(TYPE) - 1))) -        \
               _LIBSPDM_INT_SIZE_OF(TYPE)))
#define LIBSPDM_VA_END(marker) (marker = (LIBSPDM_VA_LIST)0)

#elif defined(__GNUC__) || defined(__clang__)


/* Use GCC built-in macros for variable argument lists.*/



/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

typedef __builtin_va_list LIBSPDM_VA_LIST;

#define LIBSPDM_VA_START(marker, parameter) __builtin_va_start(marker, parameter)

#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    ((sizeof(TYPE) < sizeof(size_t)) ?                                      \
     (TYPE)(__builtin_va_arg(marker, size_t)) :                     \
     (TYPE)(__builtin_va_arg(marker, TYPE)))

#define LIBSPDM_VA_END(marker) __builtin_va_end(marker)

#else

/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

typedef char *LIBSPDM_VA_LIST;

/**
 * Retrieves a pointer to the beginning of a variable argument list, based on
 * the name of the parameter that immediately precedes the variable argument list.
 *
 * This function initializes marker to point to the beginning of the variable
 * argument list that immediately follows parameter.  The method for computing the
 * pointer to the next argument in the argument list is CPU-specific following the
 * EFIAPI ABI.
 *
 * @param   marker       The LIBSPDM_VA_LIST used to traverse the list of arguments.
 * @param   parameter    The name of the parameter that immediately precedes
 *                      the variable argument list.
 *
 * @return  A pointer to the beginning of a variable argument list.
 *
 **/
#define LIBSPDM_VA_START(marker, parameter)                                            \
    (marker = (LIBSPDM_VA_LIST)((size_t) &(parameter) + _LIBSPDM_INT_SIZE_OF(parameter)))

/**
 * Returns an argument of a specified type from a variable argument list and updates
 * the pointer to the variable argument list to point to the next argument.
 *
 * This function returns an argument of the type specified by TYPE from the beginning
 * of the variable argument list specified by marker.  marker is then updated to point
 * to the next argument in the variable argument list.  The method for computing the
 * pointer to the next argument in the argument list is CPU-specific following the EFIAPI ABI.
 *
 * @param   marker   LIBSPDM_VA_LIST used to traverse the list of arguments.
 * @param   TYPE     The type of argument to retrieve from the beginning
 *                  of the variable argument list.
 *
 * @return  An argument of the type specified by TYPE.
 *
 **/
#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _LIBSPDM_INT_SIZE_OF(TYPE)) - _LIBSPDM_INT_SIZE_OF(TYPE)))

/**
 * Terminates the use of a variable argument list.
 *
 * This function initializes marker so it can no longer be used with LIBSPDM_VA_ARG().
 * After this macro is used, the only way to access the variable argument list is
 * by using LIBSPDM_VA_START() again.
 *
 * @param   marker   LIBSPDM_VA_LIST used to traverse the list of arguments.
 *
 **/
#define LIBSPDM_VA_END(marker) (marker = (LIBSPDM_VA_LIST)0)

#endif

/**
 * The macro that returns the byte offset of a field in a data structure.
 *
 * This function returns the offset, in bytes, of field specified by Field from the
 * beginning of the  data structure specified by TYPE. If TYPE does not contain Field,
 * the module will not compile.
 *
 * @param   TYPE     The name of the data structure that contains the field specified by Field.
 * @param   field    The name of the field in the data structure.
 *
 * @return  offset, in bytes, of field.
 *
 **/
#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#define LIBSPDM_OFFSET_OF(TYPE, field) ((size_t) __builtin_offsetof(TYPE, field))
#else
#define LIBSPDM_OFFSET_OF(TYPE, field) ((size_t) &(((TYPE *)0)->field))
#endif

/**
 * Return the minimum of two operands.
 *
 * This macro returns the minimal of two operand specified by a and b.
 * Both a and b must be the same numerical types, signed or unsigned.
 *
 * @param   a        The first operand with any numerical type.
 * @param   b        The second operand. It should be the same any numerical type with a.
 *
 * @return  Minimum of two operands.
 *
 **/
#define LIBSPDM_MIN(a, b) (((a) < (b)) ? (a) : (b))

/**
 * Return the number of elements in an array.
 *
 * @param  array  An object of array type. Array is only used as an argument to
 *               the sizeof operator, therefore Array is never evaluated. The
 *               caller is responsible for ensuring that Array's type is not
 *               incomplete; that is, Array must have known constant size.
 *
 * @return The number of elements in Array. The result has type size_t.
 *
 **/
#define LIBSPDM_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#endif
