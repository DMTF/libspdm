/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Generates a random byte stream of the specified size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  size                         size of random bytes to generate.
 * @param  rand                         Pointer to buffer to receive random value.
 **/
bool libspdm_get_random_number(size_t size, uint8_t *rand)
{
    if (size == 0) {
        return true;
    }
    return libspdm_random_bytes(rand, size);
}
