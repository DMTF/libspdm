/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

#include <base.h>
#include <stdlib.h>
#include <assert.h>

/**
 * Generates a 64-bit random number.
 *
 * if rand is NULL, then LIBSPDM_ASSERT().
 *
 * @param[out] rand_data     buffer pointer to store the 64-bit random value.
 *
 * @retval true         Random number generated successfully.
 * @retval false        Failed to generate the random number.
 *
 **/
bool libspdm_get_random_number_64(uint64_t *rand_data)
{
    uint8_t *ptr;

    assert(rand_data != NULL);

    ptr = (uint8_t *)rand_data;
    ptr[0] = (uint8_t)rand();
    ptr[1] = (uint8_t)rand();
    ptr[2] = (uint8_t)rand();
    ptr[3] = (uint8_t)rand();
    ptr[4] = (uint8_t)rand();
    ptr[5] = (uint8_t)rand();
    ptr[6] = (uint8_t)rand();
    ptr[7] = (uint8_t)rand();

    return true;
}
