/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  copy_mem() implementation.
**/

#include "base.h"

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  This function copies length bytes from source_buffer to destination_buffer, and returns
  destination_buffer.  The implementation must be reentrant, and it must handle the case
  where source_buffer overlaps destination_buffer.

  If length is greater than (MAX_ADDRESS - destination_buffer + 1), then ASSERT().
  If length is greater than (MAX_ADDRESS - source_buffer + 1), then ASSERT().

  @param  destination_buffer   A pointer to the destination buffer of the memory copy.
  @param  source_buffer        A pointer to the source buffer of the memory copy.
  @param  length              The number of bytes to copy from source_buffer to destination_buffer.

  @return destination_buffer.

**/
void *copy_mem(OUT void *destination_buffer, IN const void *source_buffer,
	       IN uintn length)
{
	volatile uint8 *PointerDst;
	volatile uint8 *PointerSrc;

	PointerDst = (uint8 *)destination_buffer;
	PointerSrc = (uint8 *)source_buffer;
	while (length-- != 0) {
		*(PointerDst++) = *(PointerSrc++);
	}

	return destination_buffer;
}
