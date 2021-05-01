/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SHA3-256/384/512 and Shake-256 digest Wrapper
  Implementation over OpenSSL.
**/

#include "internal_crypt_lib.h"
#include <crypto/evp.h>
#include <openssl/evp.h>
#include <crypto/evp/evp_local.h>

///
/// HashAll need a buffer to store hash context
/// This size is enough to hold all sha3 hash context
///
#define INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE 1024

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-256 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-256 hash operations.

**/
uintn sha3_256_get_context_size(void)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;

	evp_md = EVP_sha3_256();
	md_st = (struct evp_md_st *)evp_md;

	return (uintn)(md_st->ctx_size + sizeof(struct evp_md_ctx_st));
}

/**
  Initializes user-supplied memory pointed by sha3_256Context as SHA3-256 hash context for
  subsequent use.

  If sha3_256Context is NULL, then return FALSE.

  @param[out]  sha3_256Context  Pointer to SHA3-256 context being initialized.

  @retval TRUE   SHA3-256 context initialization succeeded.
  @retval FALSE  SHA3-256 context initialization failed.

**/
boolean sha3_256_init(OUT void *sha3_256Context)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	evp_md = EVP_sha3_256();

	md_ctx = (struct evp_md_ctx_st *)sha3_256Context;
	md_ctx->md_data =
		(uint8 *)sha3_256Context + sizeof(struct evp_md_ctx_st);
	md_ctx->digest = evp_md;
	md_ctx->engine = NULL;
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->init(md_ctx);
}

/**
  Makes a copy of an existing SHA3-256 context.

  If sha3_256Context is NULL, then return FALSE.
  If new_sha3_256_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_256Context     Pointer to SHA3-256 context being copied.
  @param[out] new_sha3_256_context  Pointer to new SHA3-256 context.

  @retval TRUE   SHA3-256 context copy succeeded.
  @retval FALSE  SHA3-256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_256_duplicate(IN const void *sha3_256Context,
			   OUT void *new_sha3_256_context)
{
	uintn ctx_size;
	if (sha3_256Context == NULL || new_sha3_256_context == NULL) {
		return FALSE;
	}

	ctx_size = sha3_256_get_context_size();
	copy_mem(new_sha3_256_context, sha3_256Context, ctx_size);
	return TRUE;
}

/**
  Digests the input data and updates SHA3-256 context.

  This function performs SHA3-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-256 context should be already correctly initialized by sha3_256_init(), and should not be finalized
  by sha3_256_final(). Behavior with invalid context is undefined.

  If sha3_256Context is NULL, then return FALSE.

  @param[in, out]  sha3_256Context  Pointer to the SHA3-256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-256 data digest succeeded.
  @retval FALSE  SHA3-256 data digest failed.

**/
boolean sha3_256_update(IN OUT void *sha3_256Context, IN const void *data,
			IN uintn data_size)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_256Context;

	evp_md = EVP_sha3_256();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->update(md_ctx, data, (size_t)data_size);
}

/**
  Completes computation of the SHA3-256 digest value.

  This function completes SHA3-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-256 context cannot
  be used again.
  SHA3-256 context should be already correctly initialized by sha3_256_init(), and should not be
  finalized by sha3_256_final(). Behavior with invalid SHA3-256 context is undefined.

  If sha3_256Context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_256Context  Pointer to the SHA3-256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-256 digest
                                  value (256 / 8 bytes).

  @retval TRUE   SHA3-256 digest computation succeeded.
  @retval FALSE  SHA3-256 digest computation failed.

**/
boolean sha3_256_final(IN OUT void *sha3_256Context, OUT uint8 *hash_value)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_256Context;

	evp_md = EVP_sha3_256();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->final(md_ctx, hash_value);
}

/**
  Computes the SHA3-256 message digest of a input data buffer.

  This function performs the SHA3-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-256 digest
                           value (256 / 8 bytes).

  @retval TRUE   SHA3-256 digest computation succeeded.
  @retval FALSE  SHA3-256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_256_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value)
{
	boolean status;
	uint8 hash_context[INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE];

	zero_mem(hash_context, INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE);
	status = sha3_256_init(hash_context);
	if (status) {
		status = sha3_256_update(hash_context, data, data_size);
	}
	if (status) {
		status = sha3_256_final(hash_context, hash_value);
	}

	return status;
}

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-384 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-384 hash operations.

**/
uintn sha3_384_get_context_size(void)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;

	evp_md = EVP_sha3_384();
	md_st = (struct evp_md_st *)evp_md;

	return (uintn)(md_st->ctx_size + sizeof(struct evp_md_ctx_st));
}

/**
  Initializes user-supplied memory pointed by sha3_384_context as SHA3-384 hash context for
  subsequent use.

  If sha3_384_context is NULL, then return FALSE.

  @param[out]  sha3_384_context  Pointer to SHA3-384 context being initialized.

  @retval TRUE   SHA3-384 context initialization succeeded.
  @retval FALSE  SHA3-384 context initialization failed.

**/
boolean sha3_384_init(OUT void *sha3_384_context)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	evp_md = EVP_sha3_384();

	md_ctx = (struct evp_md_ctx_st *)sha3_384_context;
	md_ctx->md_data =
		(uint8 *)sha3_384_context + sizeof(struct evp_md_ctx_st);
	md_ctx->digest = evp_md;
	md_ctx->engine = NULL;
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->init(md_ctx);
}

/**
  Makes a copy of an existing SHA3-384 context.

  If sha3_384_context is NULL, then return FALSE.
  If new_sha3_384_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_384_context     Pointer to SHA3-384 context being copied.
  @param[out] new_sha3_384_context  Pointer to new SHA3-384 context.

  @retval TRUE   SHA3-384 context copy succeeded.
  @retval FALSE  SHA3-384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_384_duplicate(IN const void *sha3_384_context,
			   OUT void *new_sha3_384_context)
{
	uintn ctx_size;
	if (sha3_384_context == NULL || new_sha3_384_context == NULL) {
		return FALSE;
	}

	ctx_size = sha3_384_get_context_size();
	copy_mem(new_sha3_384_context, sha3_384_context, ctx_size);
	return TRUE;
}

/**
  Digests the input data and updates SHA3-384 context.

  This function performs SHA3-384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-384 context should be already correctly initialized by sha3_384_init(), and should not be finalized
  by sha3_384_final(). Behavior with invalid context is undefined.

  If sha3_384_context is NULL, then return FALSE.

  @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-384 data digest succeeded.
  @retval FALSE  SHA3-384 data digest failed.

**/
boolean sha3_384_update(IN OUT void *sha3_384_context, IN const void *data,
			IN uintn data_size)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_384_context;

	evp_md = EVP_sha3_384();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->update(md_ctx, data, (size_t)data_size);
}

/**
  Completes computation of the SHA3-384 digest value.

  This function completes SHA3-384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-384 context cannot
  be used again.
  SHA3-384 context should be already correctly initialized by sha3_384_init(), and should not be
  finalized by sha3_384_final(). Behavior with invalid SHA3-384 context is undefined.

  If sha3_384_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-384 digest
                                  value (384 / 8 bytes).

  @retval TRUE   SHA3-384 digest computation succeeded.
  @retval FALSE  SHA3-384 digest computation failed.

**/
boolean sha3_384_final(IN OUT void *sha3_384_context, OUT uint8 *hash_value)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_384_context;

	evp_md = EVP_sha3_384();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->final(md_ctx, hash_value);
}

/**
  Computes the SHA3-384 message digest of a input data buffer.

  This function performs the SHA3-384 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-384 digest
                           value (384 / 8 bytes).

  @retval TRUE   SHA3-384 digest computation succeeded.
  @retval FALSE  SHA3-384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_384_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value)
{
	boolean status;
	uint8 hash_context[INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE];

	zero_mem(hash_context, INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE);
	status = sha3_384_init(hash_context);
	if (status) {
		status = sha3_384_update(hash_context, data, data_size);
	}
	if (status) {
		status = sha3_384_final(hash_context, hash_value);
	}

	return status;
}

/**
  Retrieves the size, in bytes, of the context buffer required for SHA3-512 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA3-512 hash operations.

**/
uintn sha3_512_get_context_size(void)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;

	evp_md = EVP_sha3_512();
	md_st = (struct evp_md_st *)evp_md;

	return (uintn)(md_st->ctx_size + sizeof(struct evp_md_ctx_st));
}

/**
  Initializes user-supplied memory pointed by sha3_512_context as SHA3-512 hash context for
  subsequent use.

  If sha3_512_context is NULL, then return FALSE.

  @param[out]  sha3_512_context  Pointer to SHA3-512 context being initialized.

  @retval TRUE   SHA3-512 context initialization succeeded.
  @retval FALSE  SHA3-512 context initialization failed.

**/
boolean sha3_512_init(OUT void *sha3_512_context)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	evp_md = EVP_sha3_512();

	md_ctx = (struct evp_md_ctx_st *)sha3_512_context;
	md_ctx->md_data =
		(uint8 *)sha3_512_context + sizeof(struct evp_md_ctx_st);
	md_ctx->digest = evp_md;
	md_ctx->engine = NULL;
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->init(md_ctx);
}

/**
  Makes a copy of an existing SHA3-512 context.

  If sha3_512_context is NULL, then return FALSE.
  If new_sha3_512_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_512_context     Pointer to SHA3-512 context being copied.
  @param[out] new_sha3_512_context  Pointer to new SHA3-512 context.

  @retval TRUE   SHA3-512 context copy succeeded.
  @retval FALSE  SHA3-512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_512_duplicate(IN const void *sha3_512_context,
			   OUT void *new_sha3_512_context)
{
	uintn ctx_size;
	if (sha3_512_context == NULL || new_sha3_512_context == NULL) {
		return FALSE;
	}

	ctx_size = sha3_512_get_context_size();
	copy_mem(new_sha3_512_context, sha3_512_context, ctx_size);
	return TRUE;
}

/**
  Digests the input data and updates SHA3-512 context.

  This function performs SHA3-512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-512 context should be already correctly initialized by sha3_512_init(), and should not be finalized
  by sha3_512_final(). Behavior with invalid context is undefined.

  If sha3_512_context is NULL, then return FALSE.

  @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-512 data digest succeeded.
  @retval FALSE  SHA3-512 data digest failed.

**/
boolean sha3_512_update(IN OUT void *sha3_512_context, IN const void *data,
			IN uintn data_size)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_512_context;

	evp_md = EVP_sha3_512();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->update(md_ctx, data, (size_t)data_size);
}

/**
  Completes computation of the SHA3-512 digest value.

  This function completes SHA3-512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-512 context cannot
  be used again.
  SHA3-512 context should be already correctly initialized by sha3_512_init(), and should not be
  finalized by sha3_512_final(). Behavior with invalid SHA3-512 context is undefined.

  If sha3_512_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-512 digest
                                  value (512 / 8 bytes).

  @retval TRUE   SHA3-512 digest computation succeeded.
  @retval FALSE  SHA3-512 digest computation failed.

**/
boolean sha3_512_final(IN OUT void *sha3_512_context, OUT uint8 *hash_value)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)sha3_512_context;

	evp_md = EVP_sha3_512();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->final(md_ctx, hash_value);
}

/**
  Computes the SHA3-512 message digest of a input data buffer.

  This function performs the SHA3-512 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-512 digest
                           value (512 / 8 bytes).

  @retval TRUE   SHA3-512 digest computation succeeded.
  @retval FALSE  SHA3-512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_512_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value)
{
	boolean status;
	uint8 hash_context[INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE];

	zero_mem(hash_context, INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE);
	status = sha3_512_init(hash_context);
	if (status) {
		status = sha3_512_update(hash_context, data, data_size);
	}
	if (status) {
		status = sha3_512_final(hash_context, hash_value);
	}

	return status;
}

/**
  Retrieves the size, in bytes, of the context buffer required for SHAKE256 hash operations.

  @return  The size, in bytes, of the context buffer required for SHAKE256 hash operations.

**/
uintn shake256_get_context_size(void)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;

	evp_md = EVP_shake256();
	md_st = (struct evp_md_st *)evp_md;

	return (uintn)(md_st->ctx_size + sizeof(struct evp_md_ctx_st));
}

/**
  Initializes user-supplied memory pointed by shake256_context as SHAKE256 hash context for
  subsequent use.

  If shake256_context is NULL, then return FALSE.

  @param[out]  shake256_context  Pointer to SHAKE256 context being initialized.

  @retval TRUE   SHAKE256 context initialization succeeded.
  @retval FALSE  SHAKE256 context initialization failed.

**/
boolean shake256_init(OUT void *shake256_context)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	evp_md = EVP_shake256();

	md_ctx = (struct evp_md_ctx_st *)shake256_context;
	md_ctx->md_data =
		(uint8 *)shake256_context + sizeof(struct evp_md_ctx_st);
	md_ctx->digest = evp_md;
	md_ctx->engine = NULL;
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->init(md_ctx);
}

/**
  Makes a copy of an existing SHAKE256 context.

  If shake256_context is NULL, then return FALSE.
  If new_shake256_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  shake256_context     Pointer to SHAKE256 context being copied.
  @param[out] new_shake256_context  Pointer to new SHAKE256 context.

  @retval TRUE   SHAKE256 context copy succeeded.
  @retval FALSE  SHAKE256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean shake256_duplicate(IN const void *shake256_context,
			   OUT void *new_shake256_context)
{
	uintn ctx_size;
	if (shake256_context == NULL || new_shake256_context == NULL) {
		return FALSE;
	}

	ctx_size = shake256_get_context_size();
	copy_mem(new_shake256_context, shake256_context, ctx_size);
	return TRUE;
}

/**
  Digests the input data and updates SHAKE256 context.

  This function performs SHAKE256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHAKE256 context should be already correctly initialized by shake256_init(), and should not be finalized
  by shake256_final(). Behavior with invalid context is undefined.

  If shake256_context is NULL, then return FALSE.

  @param[in, out]  shake256_context  Pointer to the SHAKE256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHAKE256 data digest succeeded.
  @retval FALSE  SHAKE256 data digest failed.

**/
boolean shake256_update(IN OUT void *shake256_context, IN const void *data,
			IN uintn data_size)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)shake256_context;

	evp_md = EVP_shake256();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->update(md_ctx, data, (size_t)data_size);
}

/**
  Completes computation of the SHAKE256 digest value.

  This function completes SHAKE256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHAKE256 context cannot
  be used again.
  SHAKE256 context should be already correctly initialized by shake256_init(), and should not be
  finalized by shake256_final(). Behavior with invalid SHAKE256 context is undefined.

  If shake256_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  shake256_context  Pointer to the SHAKE256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHAKE256 digest
                                  value (256 / 8 bytes).

  @retval TRUE   SHAKE256 digest computation succeeded.
  @retval FALSE  SHAKE256 digest computation failed.

**/
boolean shake256_final(IN OUT void *shake256_context, OUT uint8 *hash_value)
{
	const EVP_MD *evp_md;
	struct evp_md_st *md_st;
	struct evp_md_ctx_st *md_ctx;

	md_ctx = (struct evp_md_ctx_st *)shake256_context;

	evp_md = EVP_shake256();
	md_st = (struct evp_md_st *)evp_md;

	return (boolean)md_st->final(md_ctx, hash_value);
}

/**
  Computes the SHAKE256 message digest of a input data buffer.

  This function performs the SHAKE256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHAKE256 digest
                           value (256 / 8 bytes).

  @retval TRUE   SHAKE256 digest computation succeeded.
  @retval FALSE  SHAKE256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean shake256_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value)
{
	boolean status;
	uint8 hash_context[INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE];

	zero_mem(hash_context, INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE);
	status = shake256_init(hash_context);
	if (status) {
		status = shake256_update(hash_context, data, data_size);
	}
	if (status) {
		status = shake256_final(hash_context, hash_value);
	}

	return status;
}
