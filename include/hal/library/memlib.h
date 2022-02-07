/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Provides copy memory, fill memory, zero memory, and GUID functions.
 *
 * The Base Memory Library provides optimized implementations for common memory-based operations.
 * These functions should be used in place of coding your own loops to do equivalent common functions.
 * This allows optimized library implementations to help increase performance.
 **/

#ifndef __BASE_MEMORY_LIB__
#define __BASE_MEMORY_LIB__

/**
 * Copies bytes from a source buffer to a destination buffer.
 *
 * This function copies "len" bytes from "src_buf" to "dst_buf".
 *
 * Asserts and returns a non-zero value if any of the following are true:
 *   1) "src_buf" or "dst_buf" are NULL.
 *   2) "src_buf" and "dst_buf" overlap.
 *   3) "len" is greater than "dst_len".
 *   4) "len" or "dst_len" is greater than (MAX_ADDRESS - "dst_buf" + 1).
 *   5) "len" or "dst_len" is greater than (MAX_ADDRESS - "src_buf" + 1).
 *   6) "len" or "dst_len" is greater than (SIZE_MAX >> 1).
 *
 * In case of error, "dst_len" bytes of "dst_buf" is zeroed, if "dst_buf"
 * points to a non-NULL value and "dst_len" does not exceed
 * ((MAX_ADDRESS - "dst_buf" + 1) or (MAX_ADDRESS - "src_buf" + 1) or (SIZE_MAX >> 1)).
 *
 * @param    dst_buf   Destination buffer to copy to.
 * @param    dst_len   Maximum length in bytes of the destination buffer.
 * @param    src_buf   Source buffer to copy from.
 * @param    len       The number of bytes to copy.
 *
 * @return   0 on success. non-zero on error.
 *
 **/
int copy_mem_s(OUT void* dst_buf, IN uintn dst_len, IN const void* src_buf, IN uintn len);

void* copy_mem(OUT void* dst_buf, IN const void* src_buf, IN uintn len);

/**
 * Fills a target buffer with a byte value, and returns the target buffer.
 *
 * This function fills length bytes of buffer with value, and returns buffer.
 *
 * If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().
 *
 * @param  buffer    The memory to set.
 * @param  length    The number of bytes to set.
 * @param  value     The value with which to fill length bytes of buffer.
 *
 * @return buffer.
 *
 **/
void *set_mem(OUT void *buffer, IN uintn length, IN uint8_t value);

/**
 * Fills a target buffer with zeros, and returns the target buffer.
 *
 * This function fills length bytes of buffer with zeros, and returns buffer.
 *
 * If length > 0 and buffer is NULL, then ASSERT().
 * If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().
 *
 * @param  buffer      The pointer to the target buffer to fill with zeros.
 * @param  length      The number of bytes in buffer to fill with zeros.
 *
 * @return buffer.
 *
 **/
void *zero_mem(OUT void *buffer, IN uintn length);

/**
 * Compares the contents of two buffers in const time.
 *
 * This function compares length bytes of source_buffer to length bytes of destination_buffer.
 * If all length bytes of the two buffers are identical, then 0 is returned.  Otherwise, the
 * value returned is the first mismatched byte in source_buffer subtracted from the first
 * mismatched byte in destination_buffer.
 *
 * If length > 0 and destination_buffer is NULL, then ASSERT().
 * If length > 0 and source_buffer is NULL, then ASSERT().
 * If length is greater than (MAX_ADDRESS - destination_buffer + 1), then ASSERT().
 * If length is greater than (MAX_ADDRESS - source_buffer + 1), then ASSERT().
 *
 * @param  destination_buffer A pointer to the destination buffer to compare.
 * @param  source_buffer      A pointer to the source buffer to compare.
 * @param  length            The number of bytes to compare.
 *
 * @return 0                 All length bytes of the two buffers are identical.
 * @retval Non-zero          There is mismatched between source_buffer and destination_buffer.
 *
 **/
intn const_compare_mem(IN const void *destination_buffer,
                       IN const void *source_buffer, IN uintn length);

#endif
