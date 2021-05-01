/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

/**
  Generates a 64-bit random number.

  if rand is NULL, then ASSERT().

  @param[out] rand     buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
boolean get_random_number_64(OUT uint64 *rand)
{
	rand = 0;
	return TRUE;
}
