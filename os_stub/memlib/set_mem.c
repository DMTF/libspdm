/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

#include "hal/library/memlib.h"

void libspdm_set_mem(void *buffer, size_t length, uint8_t value)
{
    volatile uint8_t *pointer;

    pointer = (uint8_t *)buffer;
    while (length-- != 0) {
        *(pointer++) = value;
    }
}
