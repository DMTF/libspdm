/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_common_lib_internal.h"

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void internal_dump_hex_str(IN uint8 *data, IN uintn size)
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
void internal_dump_data(IN uint8 *data, IN uintn size)
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
void internal_dump_hex(IN uint8 *data, IN uintn size)
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
uint32 spdm_read_uint24(IN uint8 *buffer)
{
	return (uint32)(buffer[0] | buffer[1] << 8 | buffer[2] << 16);
}

/**
  Writes a 24-bit value to memory that may be unaligned.

  @param  buffer  The pointer to a 24-bit value that may be unaligned.
  @param  value   24-bit value to write to buffer.

  @return The 24-bit value to write to buffer.
**/
uint32 spdm_write_uint24(IN uint8 *buffer, IN uint32 value)
{
	buffer[0] = (uint8)(value & 0xFF);
	buffer[1] = (uint8)((value >> 8) & 0xFF);
	buffer[2] = (uint8)((value >> 16) & 0xFF);
	return value;
}

/**
  Append a new data buffer to the managed buffer.
  @param  context                  		A pointer to the SPDM context, context should be NULL if do not need append th hash.
  @param  managed_buffer_t              The managed buffer to be appended.
  @param  buffer                       	The address of the data buffer to be appended to the managed buffer.
  @param  buffer_size                   The size in bytes of the data buffer to be appended to the managed buffer.

  @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
**/
return_status append_managed_buffer(IN void *context, IN OUT void *m_buffer, IN void *buffer,
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

	#ifdef USE_TRANSCRIPT_HASH
		ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
		   (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif

	#ifdef USE_TRANSCRIPT_HASH
	spdm_context_t *spdm_context;
	uint32 hash_size;
	uint8 hash_data[MAX_HASH_SIZE];

	if(context != NULL)
	{
		spdm_context = context;
		hash_size = spdm_get_hash_size(
			spdm_context->connection_info.algorithm.base_hash_algo);

		if(hash_size >
			managed_buffer->max_buffer_size - managed_buffer->buffer_size){
			DEBUG((DEBUG_ERROR,
				"buffer has not enough space to calculate th hash\n"));
			return RETURN_BUFFER_TOO_SMALL;
		}
		spdm_hash_all(
			spdm_context->connection_info.algorithm.base_hash_algo,
			buffer, buffer_size, hash_data);

		if(managed_buffer->buffer_size != 0){
			copy_mem((uint8 *)(managed_buffer + 1) + managed_buffer->buffer_size,
								hash_data, hash_size);
			spdm_hash_all(
				spdm_context->connection_info.algorithm.base_hash_algo,
				get_managed_buffer(managed_buffer),
				get_managed_buffer_size(managed_buffer),
				hash_data);
		}
		zero_mem(managed_buffer + 1, managed_buffer->buffer_size);
		copy_mem((uint8 *)(managed_buffer + 1), hash_data, hash_size);
		managed_buffer->buffer_size = hash_size;
	}
	else
	{
	#endif
		(void *)context;
		ASSERT(managed_buffer->max_buffer_size >= managed_buffer->buffer_size);
		if (buffer_size >
			managed_buffer->max_buffer_size - managed_buffer->buffer_size) {
			// Do not ASSERT here, because command processor will append message from external.
			DEBUG((DEBUG_ERROR,
				"append_managed_buffer 0x%x fail, rest 0x%x only\n",
				(uint32)buffer_size,
				(uint32)(managed_buffer->max_buffer_size -
					managed_buffer->buffer_size)));
			return RETURN_BUFFER_TOO_SMALL;
		}
		ASSERT(buffer_size <=
			managed_buffer->max_buffer_size - managed_buffer->buffer_size);

		copy_mem((uint8 *)(managed_buffer + 1) + managed_buffer->buffer_size,
			buffer, buffer_size);
		managed_buffer->buffer_size += buffer_size;
	#ifdef USE_TRANSCRIPT_HASH
	}
	#endif
	return RETURN_SUCCESS;
}

/**
  Shrink the size of the managed buffer.

  @param  managed_buffer_t                The managed buffer to be shrinked.
  @param  buffer_size                   The size in bytes of the size of the buffer to be shrinked.

  @retval RETURN_SUCCESS               The managed buffer is shrinked.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be shrinked.
**/
return_status shrink_managed_buffer(IN OUT void *m_buffer, IN uintn buffer_size)
{
	managed_buffer_t *managed_buffer;

	managed_buffer = m_buffer;

	if (buffer_size == 0) {
		return RETURN_SUCCESS;
	}
	ASSERT(buffer_size != 0);
	#ifdef USE_TRANSCRIPT_HASH
		ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
		   (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif
	if (buffer_size > managed_buffer->buffer_size) {
		return RETURN_BUFFER_TOO_SMALL;
	}
	ASSERT(buffer_size <= managed_buffer->buffer_size);

	managed_buffer->buffer_size -= buffer_size;
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

	#ifdef USE_TRANSCRIPT_HASH
		ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
		   (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif
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

	#ifdef USE_TRANSCRIPT_HASH
		ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
		   (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif
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

	#ifdef USE_TRANSCRIPT_HASH
		ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
		   (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (managed_buffer->max_buffer_size ==
		MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif
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

	#ifdef USE_TRANSCRIPT_HASH
	ASSERT((max_buffer_size == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (max_buffer_size == MAX_SPDM_MESSAGE_HASH_BUFFER_SIZE) ||
		   (max_buffer_size == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#else
	ASSERT((max_buffer_size == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
	       (max_buffer_size == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
	#endif

	managed_buffer->max_buffer_size = max_buffer_size;
	reset_managed_buffer(m_buffer);
}