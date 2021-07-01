/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SM3 digest Wrapper Implementations.
**/

#include "internal_crypt_lib.h"

/**
  Retrieves the size, in bytes, of the context buffer required for SM3 hash operations.

  @return  The size, in bytes, of the context buffer required for SM3 hash operations.

**/
uintn sm3_256_get_context_size(void)
{
	return 0;
}

/**
  Initializes user-supplied memory pointed by sm3_context as SM3 hash context for
  subsequent use.

  If sm3_context is NULL, then return FALSE.

  @param[out]  sm3_context  Pointer to SM3 context being initialized.

  @retval TRUE   SM3 context initialization succeeded.
  @retval FALSE  SM3 context initialization failed.

**/
boolean sm3_256_init(OUT void *sm3_context)
{
	return FALSE;
}

/**
  Makes a copy of an existing SM3 context.

  If sm3_context is NULL, then return FALSE.
  If new_sm3_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sm3_context     Pointer to SM3 context being copied.
  @param[out] new_sm3_context  Pointer to new SM3 context.

  @retval TRUE   SM3 context copy succeeded.
  @retval FALSE  SM3 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sm3_256_duplicate(IN const void *sm3_context, OUT void *new_sm3_context)
{
	return FALSE;
}

/**
  Digests the input data and updates SM3 context.

  This function performs SM3 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SM3 context should be already correctly initialized by sm3_init(), and should not be finalized
  by sm3_final(). Behavior with invalid context is undefined.

  If sm3_context is NULL, then return FALSE.

  @param[in, out]  sm3_context     Pointer to the SM3 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SM3 data digest succeeded.
  @retval FALSE  SM3 data digest failed.

**/
boolean sm3_256_update(IN OUT void *sm3_context, IN const void *data,
		       IN uintn data_size)
{
	return FALSE;
}

/**
  Completes computation of the SM3 digest value.

  This function completes SM3 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SM3 context cannot
  be used again.
  SM3 context should be already correctly initialized by sm3_init(), and should not be
  finalized by sm3_final(). Behavior with invalid SM3 context is undefined.

  If sm3_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sm3_context     Pointer to the SM3 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SM3 digest
                                  value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.

**/
boolean sm3_256_final(IN OUT void *sm3_context, OUT uint8 *hash_value)
{
	return FALSE;
}

/**
  Computes the SM3 message digest of a input data buffer.

  This function performs the SM3 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SM3 digest
                           value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sm3_256_hash_all(IN const void *data, IN uintn data_size,
			 OUT uint8 *hash_value)
{
	return FALSE;
}
