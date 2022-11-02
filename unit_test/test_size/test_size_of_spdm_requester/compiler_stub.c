/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

void __stack_chk_guard (void)
{
}

void __stack_chk_fail (void)
{
}

#if !defined(_MSC_EXTENSIONS)
void *
memcpy (void *dst_buf, const void *src_buf, size_t len)
{
    libspdm_copy_mem(dst_buf, len, src_buf, len);
    return dst_buf;
}
#endif
