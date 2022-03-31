/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Pseudorandom Number generator Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include "library/rnglib.h"

/**
 * Sets up the seed value for the pseudorandom number generator.
 *
 * This function sets up the seed value for the pseudorandom number generator.
 * If seed is not NULL, then the seed passed in is used.
 * If seed is NULL, then default seed is used.
 *
 * @param[in]  seed      Pointer to seed value.
 *                      If NULL, default seed is used.
 * @param[in]  seed_size  size of seed value.
 *                      If seed is NULL, this parameter is ignored.
 *
 * @retval true   Pseudorandom number generator has enough entropy for random generation.
 * @retval false  Pseudorandom number generator does not have enough entropy for random generation.
 *
 **/
bool libspdm_random_seed(const uint8_t *seed, size_t seed_size)
{
    /* TBD*/
    return true;
}

/**
 * Generates a pseudorandom byte stream of the specified size.
 *
 * If output is NULL, then return false.
 *
 * @param[out]  output  Pointer to buffer to receive random value.
 * @param[in]   size    size of random bytes to generate.
 *
 * @retval true   Pseudorandom byte stream generated successfully.
 * @retval false  Pseudorandom number generator fails to generate due to lack of entropy.
 *
 **/
bool libspdm_random_bytes(uint8_t *output, size_t size)
{
    bool ret;
    uint64_t temp_rand;

    ret = false;

    while (size > 0) {
        /* Use rnglib to get random number*/
        ret = libspdm_get_random_number_64(&temp_rand);

        if (!ret) {
            return ret;
        }
        if (size >= sizeof(temp_rand)) {
            *((uint64_t *)output) = temp_rand;
            output += sizeof(uint64_t);
            size -= sizeof(temp_rand);
        } else {
            libspdm_copy_mem(output, size, &temp_rand, size);
            size = 0;
        }
    }

    return ret;
}

int libspdm_myrand(void *rng_state, unsigned char *output, size_t len)
{
    bool result = libspdm_random_bytes(output, len);


    /* The MbedTLS function f_rng, which myrand implements, is not
     * documented well. From looking at code: zero is considered success,
     * while non-zero return value is considered failure.*/

    return result ? 0 : -1;
}
