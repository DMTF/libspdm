/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Provides copy memory, fill memory, zero memory, and GUID functions.

  The Base Memory Library provides optimized implementations for common memory-based operations.
  These functions should be used in place of coding your own loops to do equivalent common functions.
  This allows optimized library implementations to help increase performance.
**/

#ifndef __BASE_MEMORY_LIB__
#define __BASE_MEMORY_LIB__

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  This function copies length bytes from source_buffer to destination_buffer, and returns
  destination_buffer.  The implementation must be reentrant, and it must handle the case
  where source_buffer overlaps destination_buffer.

  If length is greater than (MAX_ADDRESS - destination_buffer + 1), then ASSERT().
  If length is greater than (MAX_ADDRESS - source_buffer + 1), then ASSERT().

  @param  destination_buffer   The pointer to the destination buffer of the memory copy.
  @param  source_buffer        The pointer to the source buffer of the memory copy.
  @param  length              The number of bytes to copy from source_buffer to destination_buffer.

  @return destination_buffer.

**/
void *copy_mem(OUT void *destination_buffer, IN const void *source_buffer,
	       IN uintn length);

/**
  Fills a target buffer with a byte value, and returns the target buffer.

  This function fills length bytes of buffer with value, and returns buffer.

  If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().

  @param  buffer    The memory to set.
  @param  length    The number of bytes to set.
  @param  value     The value with which to fill length bytes of buffer.

  @return buffer.

**/
void *set_mem(OUT void *buffer, IN uintn length, IN uint8 value);

/**
  Fills a target buffer with zeros, and returns the target buffer.

  This function fills length bytes of buffer with zeros, and returns buffer.

  If length > 0 and buffer is NULL, then ASSERT().
  If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().

  @param  buffer      The pointer to the target buffer to fill with zeros.
  @param  length      The number of bytes in buffer to fill with zeros.

  @return buffer.

**/
void *zero_mem(OUT void *buffer, IN uintn length);

/**
  Compares the contents of two buffers.

  This function compares length bytes of source_buffer to length bytes of destination_buffer.
  If all length bytes of the two buffers are identical, then 0 is returned.  Otherwise, the
  value returned is the first mismatched byte in source_buffer subtracted from the first
  mismatched byte in destination_buffer.

  If length > 0 and destination_buffer is NULL, then ASSERT().
  If length > 0 and source_buffer is NULL, then ASSERT().
  If length is greater than (MAX_ADDRESS - destination_buffer + 1), then ASSERT().
  If length is greater than (MAX_ADDRESS - source_buffer + 1), then ASSERT().

  @param  destination_buffer The pointer to the destination buffer to compare.
  @param  source_buffer      The pointer to the source buffer to compare.
  @param  length            The number of bytes to compare.

  @return 0                 All length bytes of the two buffers are identical.
  @retval Non-zero          The first mismatched byte in source_buffer subtracted from the first
                            mismatched byte in destination_buffer.

**/
intn compare_mem(IN const void *destination_buffer,
		 IN const void *source_buffer, IN uintn length);

#endif
