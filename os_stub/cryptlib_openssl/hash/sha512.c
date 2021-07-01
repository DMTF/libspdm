/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SHA-384 and SHA-512 digest Wrapper Implementations.
**/

#include "internal_crypt_lib.h"
#include <openssl/sha.h>

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-384 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-384 hash operations.

**/
uintn sha384_get_context_size(void)
{
	//
	// Retrieves OpenSSL SHA-384 context size
	//
	return (uintn)(sizeof(SHA512_CTX));
}

/**
  Initializes user-supplied memory pointed by sha384_context as SHA-384 hash context for
  subsequent use.

  If sha384_context is NULL, then return FALSE.

  @param[out]  sha384_context  Pointer to SHA-384 context being initialized.

  @retval TRUE   SHA-384 context initialization succeeded.
  @retval FALSE  SHA-384 context initialization failed.

**/
boolean sha384_init(OUT void *sha384_context)
{
	//
	// Check input parameters.
	//
	if (sha384_context == NULL) {
		return FALSE;
	}

	//
	// OpenSSL SHA-384 context Initialization
	//
	return (boolean)(SHA384_Init((SHA512_CTX *)sha384_context));
}

/**
  Makes a copy of an existing SHA-384 context.

  If sha384_context is NULL, then return FALSE.
  If new_sha384_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha384_context     Pointer to SHA-384 context being copied.
  @param[out] new_sha384_context  Pointer to new SHA-384 context.

  @retval TRUE   SHA-384 context copy succeeded.
  @retval FALSE  SHA-384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha384_duplicate(IN const void *sha384_context,
			 OUT void *new_sha384_context)
{
	//
	// Check input parameters.
	//
	if (sha384_context == NULL || new_sha384_context == NULL) {
		return FALSE;
	}

	copy_mem(new_sha384_context, sha384_context, sizeof(SHA512_CTX));

	return TRUE;
}

/**
  Digests the input data and updates SHA-384 context.

  This function performs SHA-384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-384 context should be already correctly initialized by sha384_init(), and should not be finalized
  by sha384_final(). Behavior with invalid context is undefined.

  If sha384_context is NULL, then return FALSE.

  @param[in, out]  sha384_context  Pointer to the SHA-384 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-384 data digest succeeded.
  @retval FALSE  SHA-384 data digest failed.

**/
boolean sha384_update(IN OUT void *sha384_context, IN const void *data,
		      IN uintn data_size)
{
	//
	// Check input parameters.
	//
	if (sha384_context == NULL) {
		return FALSE;
	}

	//
	// Check invalid parameters, in case that only DataLength was checked in OpenSSL
	//
	if (data == NULL && data_size != 0) {
		return FALSE;
	}

	//
	// OpenSSL SHA-384 hash Update
	//
	return (boolean)(
		SHA384_Update((SHA512_CTX *)sha384_context, data, data_size));
}

/**
  Completes computation of the SHA-384 digest value.

  This function completes SHA-384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-384 context cannot
  be used again.
  SHA-384 context should be already correctly initialized by sha384_init(), and should not be
  finalized by sha384_final(). Behavior with invalid SHA-384 context is undefined.

  If sha384_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha384_context  Pointer to the SHA-384 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
                                  value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.

**/
boolean sha384_final(IN OUT void *sha384_context, OUT uint8 *hash_value)
{
	//
	// Check input parameters.
	//
	if (sha384_context == NULL || hash_value == NULL) {
		return FALSE;
	}

	//
	// OpenSSL SHA-384 hash Finalization
	//
	return (boolean)(
		SHA384_Final(hash_value, (SHA512_CTX *)sha384_context));
}

/**
  Computes the SHA-384 message digest of a input data buffer.

  This function performs the SHA-384 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-384 digest
                           value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha384_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value)
{
	//
	// Check input parameters.
	//
	if (hash_value == NULL) {
		return FALSE;
	}
	if (data == NULL && data_size != 0) {
		return FALSE;
	}

	//
	// OpenSSL SHA-384 hash Computation.
	//
	if (SHA384(data, data_size, hash_value) == NULL) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-512 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-512 hash operations.

**/
uintn sha512_get_context_size(void)
{
	//
	// Retrieves OpenSSL SHA-512 context size
	//
	return (uintn)(sizeof(SHA512_CTX));
}

/**
  Initializes user-supplied memory pointed by sha512_context as SHA-512 hash context for
  subsequent use.

  If sha512_context is NULL, then return FALSE.

  @param[out]  sha512_context  Pointer to SHA-512 context being initialized.

  @retval TRUE   SHA-512 context initialization succeeded.
  @retval FALSE  SHA-512 context initialization failed.

**/
boolean sha512_init(OUT void *sha512_context)
{
	//
	// Check input parameters.
	//
	if (sha512_context == NULL) {
		return FALSE;
	}

	//
	// OpenSSL SHA-512 context Initialization
	//
	return (boolean)(SHA512_Init((SHA512_CTX *)sha512_context));
}

/**
  Makes a copy of an existing SHA-512 context.

  If sha512_context is NULL, then return FALSE.
  If new_sha512_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha512_context     Pointer to SHA-512 context being copied.
  @param[out] new_sha512_context  Pointer to new SHA-512 context.

  @retval TRUE   SHA-512 context copy succeeded.
  @retval FALSE  SHA-512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha512_duplicate(IN const void *sha512_context,
			 OUT void *new_sha512_context)
{
	//
	// Check input parameters.
	//
	if (sha512_context == NULL || new_sha512_context == NULL) {
		return FALSE;
	}

	copy_mem(new_sha512_context, sha512_context, sizeof(SHA512_CTX));

	return TRUE;
}

/**
  Digests the input data and updates SHA-512 context.

  This function performs SHA-512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-512 context should be already correctly initialized by sha512_init(), and should not be finalized
  by sha512_final(). Behavior with invalid context is undefined.

  If sha512_context is NULL, then return FALSE.

  @param[in, out]  sha512_context  Pointer to the SHA-512 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-512 data digest succeeded.
  @retval FALSE  SHA-512 data digest failed.

**/
boolean sha512_update(IN OUT void *sha512_context, IN const void *data,
		      IN uintn data_size)
{
	//
	// Check input parameters.
	//
	if (sha512_context == NULL) {
		return FALSE;
	}

	//
	// Check invalid parameters, in case that only DataLength was checked in OpenSSL
	//
	if (data == NULL && data_size != 0) {
		return FALSE;
	}

	//
	// OpenSSL SHA-512 hash Update
	//
	return (boolean)(
		SHA512_Update((SHA512_CTX *)sha512_context, data, data_size));
}

/**
  Completes computation of the SHA-512 digest value.

  This function completes SHA-512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-512 context cannot
  be used again.
  SHA-512 context should be already correctly initialized by sha512_init(), and should not be
  finalized by sha512_final(). Behavior with invalid SHA-512 context is undefined.

  If sha512_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha512_context  Pointer to the SHA-512 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-512 digest
                                  value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.

**/
boolean sha512_final(IN OUT void *sha512_context, OUT uint8 *hash_value)
{
	//
	// Check input parameters.
	//
	if (sha512_context == NULL || hash_value == NULL) {
		return FALSE;
	}

	//
	// OpenSSL SHA-512 hash Finalization
	//
	return (boolean)(
		SHA384_Final(hash_value, (SHA512_CTX *)sha512_context));
}

/**
  Computes the SHA-512 message digest of a input data buffer.

  This function performs the SHA-512 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-512 digest
                           value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha512_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value)
{
	//
	// Check input parameters.
	//
	if (hash_value == NULL) {
		return FALSE;
	}
	if (data == NULL && data_size != 0) {
		return FALSE;
	}

	//
	// OpenSSL SHA-512 hash Computation.
	//
	if (SHA512(data, data_size, hash_value) == NULL) {
		return FALSE;
	} else {
		return TRUE;
	}
}
