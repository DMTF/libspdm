/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Pseudorandom Number generator Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/rand.h>
#include <openssl/evp.h>


/* Default seed for Crypto Library*/

uint8_t default_seed[] = "Crypto Library default seed";

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
bool libspdm_random_seed(const uint8_t *seed, uintn seed_size)
{
    if (seed_size > INT_MAX) {
        return false;
    }


    /* The software PRNG implementation built in OpenSSL depends on message digest algorithm.
     * Make sure SHA-1 digest algorithm is available here.*/

    if (EVP_add_digest(EVP_sha256()) == 0) {
        return false;
    }


    /* seed the pseudorandom number generator with user-supplied value.
     * NOTE: A cryptographic PRNG must be seeded with unpredictable data.*/

    if (seed != NULL) {
        RAND_seed(seed, (uint32_t)seed_size);
    } else {
        RAND_seed(default_seed, sizeof(default_seed));
    }

    if (RAND_status() == 1) {
        return true;
    }

    return false;
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
bool libspdm_random_bytes(uint8_t *output, uintn size)
{

    /* Check input parameters.*/

    if (output == NULL || size > INT_MAX) {
        return false;
    }


    /* Generate random data.*/

    if (RAND_bytes(output, (uint32_t)size) != 1) {
        return false;
    }

    return true;
}
