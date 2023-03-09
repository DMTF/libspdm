/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Provides copy memory, fill memory, zero memory, and GUID functions.
 *
 * The Base Memory Library provides optimized implementations for common memory-based operations.
 * These functions should be used in place of coding your own loops to do equivalent common functions.
 * This allows optimized library implementations to help increase performance.
 **/

#ifndef BASE_MEMORY_LIB
#define BASE_MEMORY_LIB

/**
 * Copies bytes from a source buffer to a destination buffer.
 *
 * This function copies "src_len" bytes from "src_buf" to "dst_buf".
 *
 * Asserts and returns a non-zero value if any of the following are true:
 *   1) "src_buf" or "dst_buf" are NULL.
 *   2) "src_len" or "dst_len" is greater than (SIZE_MAX >> 1).
 *   3) "src_len" is greater than "dst_len".
 *   4) "src_buf" and "dst_buf" overlap.
 *
 * If any of these cases fail, a non-zero value is returned. Additionally if
 * "dst_buf" points to a non-NULL value and "dst_len" is valid, then "dst_len"
 * bytes of "dst_buf" are zeroed.
 *
 * This function follows the C11 cppreference description of memcpy_s.
 * https://en.cppreference.com/w/c/string/byte/memcpy
 * The cppreferece description does NOT allow the source or destination
 * buffers to be NULL.
 *
 * This function differs from the Microsoft and Safeclib memcpy_s implementations
 * in that the Microsoft and Safeclib implementations allow for NULL source and
 * destinations pointers when the number of bytes to copy (src_len) is zero.
 *
 * In addition the Microsoft and Safeclib memcpy_s functions return different
 * negative values on error. For best support, clients should generally check
 * against zero for success or failure.
 *
 * @param    dst_buf   Destination buffer to copy to.
 * @param    dst_len   Maximum length in bytes of the destination buffer.
 * @param    src_buf   Source buffer to copy from.
 * @param    src_len   The number of bytes to copy from the source buffer.
 *
 * @return   0 on success. non-zero on error.
 *
 **/
int libspdm_copy_mem(void *dst_buf, size_t dst_len,
                     const void *src_buf, size_t src_len);

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
void *libspdm_set_mem(void *buffer, size_t length, uint8_t value);

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
void *libspdm_zero_mem(void *buffer, size_t length);

/**
 * Compares the contents of two buffers in constant time.
 *
 * For a given length, the time to complete the comparison is always the same regardless of the
 * contents of the two buffers.
 *
 * @param  destination_buffer  A pointer to the destination buffer to compare.
 * @param  source_buffer       A pointer to the source buffer to compare.
 * @param  length              The number of bytes to compare.
 *
 * @return true   The contents of the two buffers are the same.
 * @retval false  The contents of the two buffers are not the same.
 **/
bool libspdm_const_compare_mem(const void *destination_buffer,
                               const void *source_buffer, size_t length);

#endif /* BASE_MEMORY_LIB */
