/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_common_lib.h"

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex_str(IN uint8_t *data, IN uintn size)
{
    uintn index;
    for (index = 0; index < size; index++) {
        DEBUG((DEBUG_INFO, "%02x", (uintn)data[index]));
    }
}

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_data(IN uint8_t *data, IN uintn size)
{
    uintn index;
    for (index = 0; index < size; index++) {
        DEBUG((DEBUG_INFO, "%02x ", (uintn)data[index]));
    }
}

/**
  This function dump raw data with colume format.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex(IN uint8_t *data, IN uintn size)
{
    uintn index;
    uintn count;
    uintn left;

#define COLUME_SIZE (16 * 2)

    count = size / COLUME_SIZE;
    left = size % COLUME_SIZE;
    for (index = 0; index < count; index++) {
        DEBUG((DEBUG_INFO, "%04x: ", index * COLUME_SIZE));
        internal_dump_data(data + index * COLUME_SIZE, COLUME_SIZE);
        DEBUG((DEBUG_INFO, "\n"));
    }

    if (left != 0) {
        DEBUG((DEBUG_INFO, "%04x: ", index * COLUME_SIZE));
        internal_dump_data(data + index * COLUME_SIZE, left);
        DEBUG((DEBUG_INFO, "\n"));
    }
}

/**
  Reads a 24-bit value from memory that may be unaligned.

  @param  buffer  The pointer to a 24-bit value that may be unaligned.

  @return The 24-bit value read from buffer.
**/
uint32_t libspdm_read_uint24(IN uint8_t *buffer)
{
    return (uint32_t)(buffer[0] | buffer[1] << 8 | buffer[2] << 16);
}

/**
  Writes a 24-bit value to memory that may be unaligned.

  @param  buffer  The pointer to a 24-bit value that may be unaligned.
  @param  value   24-bit value to write to buffer.
**/
void libspdm_write_uint24(IN uint8_t *buffer, IN uint32_t value)
{
    buffer[0] = (uint8_t)(value & 0xFF);
    buffer[1] = (uint8_t)((value >> 8) & 0xFF);
    buffer[2] = (uint8_t)((value >> 16) & 0xFF);
    return;
}

/**
  Append a new data buffer to the managed buffer.

  @param  managed_buffer_t                The managed buffer to be appended.
  @param  buffer                       The address of the data buffer to be appended to the managed buffer.
  @param  buffer_size                   The size in bytes of the data buffer to be appended to the managed buffer.

  @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
**/
return_status append_managed_buffer(IN OUT void *m_buffer, IN void *buffer,
                    IN uintn buffer_size)
{
    managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    if (buffer_size == 0) {
        return RETURN_SUCCESS;
    }
    if (buffer == NULL) {
        return RETURN_INVALID_PARAMETER;
    }
    ASSERT(buffer != NULL);
    ASSERT(buffer_size != 0);
    ASSERT((managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE));
    ASSERT(managed_buffer->max_buffer_size >= managed_buffer->buffer_size);
    if (buffer_size >
        managed_buffer->max_buffer_size - managed_buffer->buffer_size) {
        /* Do not ASSERT here, because command processor will append message from external.*/
        DEBUG((DEBUG_ERROR,
               "append_managed_buffer 0x%x fail, rest 0x%x only\n",
               (uint32_t)buffer_size,
               (uint32_t)(managed_buffer->max_buffer_size -
                managed_buffer->buffer_size)));
        return RETURN_BUFFER_TOO_SMALL;
    }
    ASSERT(buffer_size <=
           managed_buffer->max_buffer_size - managed_buffer->buffer_size);

    copy_mem((uint8_t *)(managed_buffer + 1) + managed_buffer->buffer_size,
         buffer, buffer_size);
    managed_buffer->buffer_size += buffer_size;
    return RETURN_SUCCESS;
}

/**
  Reset the managed buffer.
  The buffer_size is reset to 0.
  The max_buffer_size is unchanged.
  The buffer is not freed.

  @param  managed_buffer_t                The managed buffer to be shrinked.
**/
void reset_managed_buffer(IN OUT void *m_buffer)
{
    managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    ASSERT((managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE));
    managed_buffer->buffer_size = 0;
    zero_mem(managed_buffer + 1, managed_buffer->max_buffer_size);
}

/**
  Return the size of managed buffer.

  @param  managed_buffer_t                The managed buffer.

  @return the size of managed buffer.
**/
uintn get_managed_buffer_size(IN OUT void *m_buffer)
{
    managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    ASSERT((managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE));
    return managed_buffer->buffer_size;
}

/**
  Return the address of managed buffer.

  @param  managed_buffer_t                The managed buffer.

  @return the address of managed buffer.
**/
void *get_managed_buffer(IN OUT void *m_buffer)
{
    managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    ASSERT((managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE) ||
           (managed_buffer->max_buffer_size ==
        LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE));
    return (managed_buffer + 1);
}

/**
  Init the managed buffer.

  @param  managed_buffer_t                The managed buffer.
  @param  max_buffer_size                The maximum size in bytes of the managed buffer.
**/
void init_managed_buffer(IN OUT void *m_buffer, IN uintn max_buffer_size)
{
    managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    ASSERT((max_buffer_size == LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) ||
           (max_buffer_size == LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE) ||
           (max_buffer_size == LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE));

    managed_buffer->max_buffer_size = max_buffer_size;
    reset_managed_buffer(m_buffer);
}
