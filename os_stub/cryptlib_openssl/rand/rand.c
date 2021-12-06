/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Pseudorandom Number generator Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <openssl/rand.h>
#include <openssl/evp.h>

//
// Default seed for Crypto Library
//
const uint8_t default_seed[] = "Crypto Library default seed";

/**
  Sets up the seed value for the pseudorandom number generator.

  This function sets up the seed value for the pseudorandom number generator.
  If seed is not NULL, then the seed passed in is used.
  If seed is NULL, then default seed is used.

  @param[in]  seed      Pointer to seed value.
                        If NULL, default seed is used.
  @param[in]  seed_size  size of seed value.
                        If seed is NULL, this parameter is ignored.

  @retval TRUE   Pseudorandom number generator has enough entropy for random generation.
  @retval FALSE  Pseudorandom number generator does not have enough entropy for random generation.

**/
boolean random_seed(IN const uint8_t *seed OPTIONAL, IN uintn seed_size)
{
    if (seed_size > INT_MAX) {
        return FALSE;
    }

    //
    // The software PRNG implementation built in OpenSSL depends on message digest algorithm.
    // Make sure SHA-1 digest algorithm is available here.
    //
    if (EVP_add_digest(EVP_sha256()) == 0) {
        return FALSE;
    }

    //
    // seed the pseudorandom number generator with user-supplied value.
    // NOTE: A cryptographic PRNG must be seeded with unpredictable data.
    //
    if (seed != NULL) {
        RAND_seed(seed, (uint32_t)seed_size);
    } else {
        RAND_seed(default_seed, sizeof(default_seed));
    }

    if (RAND_status() == 1) {
        return TRUE;
    }

    return FALSE;
}

/**
  Generates a pseudorandom byte stream of the specified size.

  If output is NULL, then return FALSE.

  @param[out]  output  Pointer to buffer to receive random value.
  @param[in]   size    size of random bytes to generate.

  @retval TRUE   Pseudorandom byte stream generated successfully.
  @retval FALSE  Pseudorandom number generator fails to generate due to lack of entropy.

**/
boolean random_bytes(OUT uint8_t *output, IN uintn size)
{
    //
    // Check input parameters.
    //
    if (output == NULL || size > INT_MAX) {
        return FALSE;
    }

    //
    // Generate random data.
    //
    if (RAND_bytes(output, (uint32_t)size) != 1) {
        return FALSE;
    }

    return TRUE;
}
