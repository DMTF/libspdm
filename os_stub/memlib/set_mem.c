/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "base.h"

/**
 * Fills a target buffer with a byte value, and returns the target buffer.
 *
 * This function fills length bytes of buffer with value, and returns buffer.
 *
 * If length is greater than (MAX_ADDRESS - buffer + 1), then LIBSPDM_ASSERT().
 *
 * @param  buffer    The memory to set.
 * @param  length    The number of bytes to set.
 * @param  value     The value with which to fill length bytes of buffer.
 *
 * @return buffer.
 *
 **/
void *libspdm_set_mem(void *buffer, uintn length, uint8_t value)
{
    volatile uint8_t *pointer;

    pointer = (uint8_t *)buffer;
    while (length-- != 0) {
        *(pointer++) = value;
    }

    return buffer;
}
