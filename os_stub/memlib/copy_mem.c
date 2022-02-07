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
 * This function copies "len" bytes from "src_buf" to "dst_buf".
 *
 * Asserts and returns a non-zero value if any of the following are true:
 *   1) "src_buf" or "dst_buf" are NULL.
 *   2) "src_buf" and "dst_buf" overlap.
 *   3) "len" is greater than "dst_len".
 *   4) "len" or "dst_len" is greater than (MAX_ADDRESS - "dst_buf" + 1).
 *   5) "len" or "dst_len" is greater than (MAX_ADDRESS - "src_buf" + 1).
 *   6) "len" or "dst_len" is greater than (SIZE_MAX >> 1).
 *
 * In case of error, "dst_len" bytes of "dst_buf" is zeroed, if "dst_buf"
 * points to a non-NULL value and "dst_len" does not exceed
 * ((MAX_ADDRESS - "dst_buf" + 1) or (MAX_ADDRESS - "src_buf" + 1)).
 *
 * @param    dst_buf   Destination buffer to copy to.
 * @param    dst_len   Maximum length in bytes of the destination buffer.
 * @param    src_buf   Source buffer to copy from.
 * @param    len       The number of bytes to copy.
 *
 * @return   0 on success. non-zero on error.
 *
 **/
int copy_mem_s(OUT void* dst_buf, IN uintn dst_len, IN const void* src_buf, IN uintn len)
{
    volatile uint8_t* dst;
    const volatile uint8_t* src;

    dst = (volatile uint8_t*) dst_buf;
    src = (const volatile uint8_t*) src_buf;

    /* Check for case where "dst" or "dst_len" may be invalid.
     * Do not zero "dst" in this case. */
    if (dst == NULL ||
        dst_len > MAX_ADDRESS - (uintn)dst + 1 ||
        dst_len > MAX_ADDRESS - (uintn)src + 1 ||
        dst_len > (SIZE_MAX >> 1)) {
        ASSERT(0);
        return -1;
    }

    /* Gaurd against invalid source. Zero "dst" in this case. */
    if (src == NULL) {
        set_mem(dst_buf, dst_len, 0);
        ASSERT(0);
        return -1;
    }

    /* Guard against overlap case. Zero "dst" in these cases. */
    if ((src < dst && src + len > dst) || (dst < src && dst + len > src)) {
        set_mem(dst_buf, dst_len, 0);
        ASSERT(0);
        return -1;
    }

    /* Guard against invalid lengths. Zero "dst" in these cases. */
    if (len > dst_len ||
        len > MAX_ADDRESS - (uintn)dst + 1 ||
        len > MAX_ADDRESS - (uintn)src + 1 ||
        len > (SIZE_MAX >> 1)) {

        set_mem(dst_buf, dst_len, 0);
        ASSERT(0);
        return -1;
    }

    while (len-- != 0) {
        *(dst++) = *(src++);
    }

    return 0;
}

void* copy_mem(OUT void* dst_buf, IN const void* src_buf, IN uintn len)
{
    copy_mem_s(dst_buf, len, src_buf, len);
    return dst_buf;
}
