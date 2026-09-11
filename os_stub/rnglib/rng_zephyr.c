/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>

#include <assert.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

/**
 * Generates a 64-bit random number using Zephyr's CSPRNG.
 *
 * Requires CONFIG_CSPRNG_ENABLED=y (selected automatically when
 * CONFIG_ENTROPY_GENERATOR=y or a hardware entropy driver is present).
 *
 * if rand_data is NULL, then ASSERT().
 *
 * @param[out] rand_data  buffer pointer to store the 64-bit random value.
 *
 * @retval true   Random number generated successfully.
 * @retval false  Failed to generate the random number.
 **/
bool libspdm_get_random_number_64(uint64_t *rand_data)
{
    assert(rand_data != NULL);

#if defined(CONFIG_CSPRNG_ENABLED)
    if (sys_csrand_get(rand_data, sizeof(*rand_data)) != 0) {
        return false;
    }
#else
    /* Fall back to the non-cryptographic PRNG. */
    sys_rand_get(rand_data, sizeof(*rand_data));
#endif
    return true;
}
