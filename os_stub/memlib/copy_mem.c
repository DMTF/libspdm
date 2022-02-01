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

/**
 * Copies bytes from a source buffer to a destination buffer.
 *
 * This function copies "len" bytes from "src_buf" to "dst_buf".
 *
 * Asserts and returns a non-zero value if any of the following are true:
 *   1) ("src_buf" or "dst_buf" are NULL) and "len" is greater 0.
 *   2) "src_buf" and "dst_buf" overlap.
 *   3) "len" is greater than "dst_len".
 *   4) "len" or "dst_len" is greater than (MAX_ADDRESS - "dst_buf" + 1).
 *   5) "len" or "dst_len" is greater than (MAX_ADDRESS - "src_buf" + 1).
 *   6) "len" or "dst_len" is greater than (SIZE_MAX >> 1).
 *
 * In case of error, the "dst_buf" is left unmodifed. This behavior is different
 * than memcopy_s, which zeros the "dst_buf" if "dst_buf" is valid.
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

    dst = (uint8_t*) dst_buf;
    src = (const uint8_t*) src_buf;

    if (src == NULL || dst == NULL) {
        ASSERT(0);
        return -1;
    }

    if ((src < dst && src + len > dst)
     || (dst < src && dst + len > src)) {
        ASSERT(0);
        return -1;
    }

    if (len > dst_len
     || len > MAX_ADDRESS - (uintn)dst + 1
     || len > MAX_ADDRESS - (uintn)src + 1
     || len > (SIZE_MAX >> 1)) {

        ASSERT(0);
        return -1;
    }

    while (len-- != 0) {
        *(dst++) = *(src++);
    }

    return 0;
}

void copy_mem(OUT void* dst_buf, IN const void* src_buf, IN uintn len)
{
    copy_mem_s(dst_buf, len, src_buf, len);
}
