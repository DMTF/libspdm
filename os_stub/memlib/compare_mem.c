/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

#include "base.h"

bool libspdm_consttime_is_mem_equal(const void *destination_buffer,
                                    const void *source_buffer, size_t length)
{
    const volatile uint8_t *pointer_dst;
    const volatile uint8_t *pointer_src;
    uint8_t delta;

    pointer_dst = (const uint8_t *)destination_buffer;
    pointer_src = (const uint8_t *)source_buffer;
    delta = 0;
    while ((length-- != 0)) {
        delta |= *(pointer_dst++) ^ *(pointer_src++);
    }

    return ((delta == 0) ? true : false);
}
