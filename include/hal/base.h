/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef BASE_H
#define BASE_H

/* Include processor specific binding*/
#include <processor_bind.h>

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

#endif /* BASE_H */
