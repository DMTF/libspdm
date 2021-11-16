/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <base.h>
#include <stdlib.h>

/**
  Generates a 64-bit random number.

  if rand is NULL, then ASSERT().

  @param[out] rand_data     buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
boolean get_random_number_64(OUT uint64_t *rand_data)
{
	uint8_t *ptr;

	ptr = (uint8_t *)rand_data;
	ptr[0] = (uint8_t)rand();
	ptr[1] = (uint8_t)rand();
	ptr[2] = (uint8_t)rand();
	ptr[3] = (uint8_t)rand();
	ptr[4] = (uint8_t)rand();
	ptr[5] = (uint8_t)rand();
	ptr[6] = (uint8_t)rand();
	ptr[7] = (uint8_t)rand();

	return TRUE;
}
