/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef BASE_H
#define BASE_H

#ifndef LIBSPDM_STDINT_ALT
#include <stdint.h>
#else
#include LIBSPDM_STDINT_ALT
#endif

#ifndef LIBSPDM_STDBOOL_ALT
#include <stdbool.h>
#else
#include LIBSPDM_STDBOOL_ALT
#endif

#ifndef LIBSPDM_STDDEF_ALT
#include <stddef.h>
#else
#include LIBSPDM_STDDEF_ALT
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
