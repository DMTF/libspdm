/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "base.h"

/**
  Fills a target buffer with a byte value, and returns the target buffer.

  This function fills length bytes of buffer with value, and returns buffer.

  If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().

  @param  buffer    The memory to set.
  @param  length    The number of bytes to set.
  @param  value     The value with which to fill length bytes of buffer.

  @return buffer.

**/
void *set_mem(OUT void *buffer, IN uintn length, IN uint8 value)
{
	volatile uint8 *pointer;

	pointer = (uint8 *)buffer;
	while (length-- != 0) {
		*(pointer++) = value;
	}

	return buffer;
}
