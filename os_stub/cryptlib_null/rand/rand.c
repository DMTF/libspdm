/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Pseudorandom Number generator Wrapper Implementation.
**/

#include "internal_crypt_lib.h"

int rand();

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
boolean random_seed(IN const uint8 *seed OPTIONAL, IN uintn seed_size)
{
	// TBD
	return TRUE;
}

/**
  Generates a pseudorandom byte stream of the specified size.

  If output is NULL, then return FALSE.

  @param[out]  output  Pointer to buffer to receive random value.
  @param[in]   size    size of random bytes to generate.

  @retval TRUE   Pseudorandom byte stream generated successfully.
  @retval FALSE  Pseudorandom number generator fails to generate due to lack of entropy.

**/
boolean random_bytes(OUT uint8 *output, IN uintn size)
{
	return TRUE;
}

int myrand(void *rng_state, unsigned char *output, size_t len)
{
	random_bytes(output, len);

	return 0;
}
