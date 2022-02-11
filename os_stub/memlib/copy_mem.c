/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * copy_mem() implementation.
 **/

#include "base.h"
#include "library/debuglib.h"
#include "hal/library/memlib.h"

/**
 * Copies bytes from a source buffer to a destination buffer.
 *
 * This function copies "src_len" bytes from "src_buf" to "dst_buf".
 *
 * Asserts and returns a non-zero value if any of the following are true:
 *   1) "src_buf" or "dst_buf" are NULL.
 *   2) "src_len" or "dst_len" is greater than (SIZE_MAX >> 1).
 *   3) "src_len" is greater than "dst_len".
 *   4) "src_buf" and "dst_buf" overlap.
 *
 * If any of these cases fail, a non-zero value is returned. Additionally if
 * "dst_buf" points to a non-NULL value and "dst_len" is valid, then "dst_len"
 * bytes of "dst_buf" are zeroed.
 *
 * This function follows the C11 cppreference description of memcpy_s.
 * https://en.cppreference.com/w/c/string/byte/memcpy
 * The cppreferece description does NOT allow the source or destination
 * buffers to be NULL.
 *
 * This function differs from the Microsoft and Safeclib memcpy_s implementations
 * in that the Microsoft and Safeclib implementations allow for NULL source and
 * destinations pointers when the number of bytes to copy (src_len) is zero.
 *
 * In addition the Microsoft and Safeclib memcpy_s functions return different
 * negative values on error. For best support, clients should generally check
 * against zero for success or failure.
 *
 * @param    dst_buf   Destination buffer to copy to.
 * @param    dst_len   Maximum length in bytes of the destination buffer.
 * @param    src_buf   Source buffer to copy from.
 * @param    src_len   The number of bytes to copy from the source buffer.
 *
 * @return   0 on success. non-zero on error.
 *
 **/
int copy_mem_s(OUT void *restrict dst_buf, IN uintn dst_len,
               IN const void *restrict src_buf, IN uintn src_len)
{
    volatile uint8_t* dst;
    const volatile uint8_t* src;

    dst = (volatile uint8_t*) dst_buf;
    src = (const volatile uint8_t*) src_buf;

    /* Check for case where "dst" or "dst_len" may be invalid.
     * Do not zero "dst" in this case. */
    if (dst == NULL || dst_len > (SIZE_MAX >> 1)) {
        ASSERT(0);
        return -1;
    }

    /* Gaurd against invalid source. Zero "dst" in this case. */
    if (src == NULL) {
        zero_mem(dst_buf, dst_len);
        ASSERT(0);
        return -1;
    }

    /* Guard against overlap case. Zero "dst" in these cases. */
    if ((src < dst && src + src_len > dst) || (dst < src && dst + src_len > src)) {
        zero_mem(dst_buf, dst_len);
        ASSERT(0);
        return -1;
    }

    /* Guard against invalid lengths. Zero "dst" in these cases. */
    if (src_len > dst_len ||
        src_len > (SIZE_MAX >> 1)) {

        zero_mem(dst_buf, dst_len);
        ASSERT(0);
        return -1;
    }

    while (src_len-- != 0) {
        *(dst++) = *(src++);
    }

    return 0;
}

void* copy_mem(OUT void* dst_buf, IN const void* src_buf, IN uintn len)
{
    copy_mem_s(dst_buf, len, src_buf, len);
    return dst_buf;
}
