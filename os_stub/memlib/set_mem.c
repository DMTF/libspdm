/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/library/memlib.h"
#include "library/debuglib.h"

void libspdm_set_mem(void *buffer, size_t length, uint8_t value)
{
    volatile uint8_t *pointer;

    LIBSPDM_ASSERT(buffer != NULL);

    pointer = (uint8_t *)buffer;
    while (length-- != 0) {
        *(pointer++) = value;
    }
}
