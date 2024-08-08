/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

#include "internal/libspdm_crypt_lib.h"

bool libspdm_get_random_number(size_t size, uint8_t *rand)
{
    if (size == 0) {
        return true;
    }
    return libspdm_random_bytes(rand, size);
}
