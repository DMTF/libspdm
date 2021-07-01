/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SHA-256 digest Wrapper Implementation.
**/

#include "internal_crypt_lib.h"

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-256 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-256 hash operations.

**/
uintn sha256_get_context_size(void)
{
	ASSERT(FALSE);
	return 0;
}

/**
  Initializes user-supplied memory pointed by sha256_context as SHA-256 hash context for
  subsequent use.

  If sha256_context is NULL, then return FALSE.

  @param[out]  sha256_context  Pointer to SHA-256 context being initialized.

  @retval TRUE   SHA-256 context initialization succeeded.
  @retval FALSE  SHA-256 context initialization failed.

**/
boolean sha256_init(OUT void *sha256_context)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Makes a copy of an existing SHA-256 context.

  If sha256_context is NULL, then return FALSE.
  If new_sha256_context is NULL, then return FALSE.

  @param[in]  sha256_context     Pointer to SHA-256 context being copied.
  @param[out] new_sha256_context  Pointer to new SHA-256 context.

  @retval TRUE   SHA-256 context copy succeeded.
  @retval FALSE  SHA-256 context copy failed.

**/
boolean sha256_duplicate(IN const void *sha256_context,
			 OUT void *new_sha256_context)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Digests the input data and updates SHA-256 context.

  This function performs SHA-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-256 context should be already correctly initialized by sha256_init(), and should not be finalized
  by sha256_final(). Behavior with invalid context is undefined.

  If sha256_context is NULL, then return FALSE.

  @param[in, out]  sha256_context  Pointer to the SHA-256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-256 data digest succeeded.
  @retval FALSE  SHA-256 data digest failed.

**/
boolean sha256_update(IN OUT void *sha256_context, IN const void *data,
		      IN uintn data_size)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Completes computation of the SHA-256 digest value.

  This function completes SHA-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-256 context cannot
  be used again.
  SHA-256 context should be already correctly initialized by sha256_init(), and should not be
  finalized by sha256_final(). Behavior with invalid SHA-256 context is undefined.

  If sha256_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha256_context  Pointer to the SHA-256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
                                  value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.

**/
boolean sha256_final(IN OUT void *sha256_context, OUT uint8 *hash_value)
{
	ASSERT(FALSE);
	return FALSE;
}

/**
  Computes the SHA-256 message digest of a input data buffer.

  This function performs the SHA-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-256 digest
                           value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha256_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value)
{
	ASSERT(FALSE);
	return FALSE;
}
