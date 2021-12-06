/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  HMAC-SHA256/384/512 Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <mbedtls/md.h>

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-MD use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_md_new() returns NULL.

**/
void *hmac_md_new(void)
{
    void *hmac_md_ctx;

    hmac_md_ctx = allocate_zero_pool(sizeof(mbedtls_md_context_t));
    if (hmac_md_ctx == NULL) {
        return NULL;
    }

    return hmac_md_ctx;
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_md_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_md_free(IN void *hmac_md_ctx)
{
    mbedtls_md_free(hmac_md_ctx);
    free_pool (hmac_md_ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_md_update().

  If hmac_md_ctx is NULL, then return FALSE.

  @param[in]   md_type             message digest Type.
  @param[out]  hmac_md_ctx      Pointer to HMAC-MD context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.

**/
boolean hmac_md_set_key(IN mbedtls_md_type_t md_type, OUT void *hmac_md_ctx,
            IN const uint8_t *key, IN uintn key_size)
{
    const mbedtls_md_info_t *md_info;
    int32_t ret;

    if (hmac_md_ctx == NULL || key_size > INT_MAX) {
        return FALSE;
    }

    zero_mem(hmac_md_ctx, sizeof(mbedtls_md_context_t));
    mbedtls_md_init(hmac_md_ctx);

    md_info = mbedtls_md_info_from_type(md_type);
    ASSERT(md_info != NULL);

    ret = mbedtls_md_setup(hmac_md_ctx, md_info, 1);
    if (ret != 0) {
        return FALSE;
    }

    ret = mbedtls_md_hmac_starts(hmac_md_ctx, key, key_size);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
  Return block size in md_type.
  This function is use to enable hmac_duplicate.

  @param[in]   md_type          mbedtls Type.

  @retval blocksize in md_type
**/
int hmac_md_get_blocksize( mbedtls_md_type_t md_type )
{
    switch( md_type )
    {
        case MBEDTLS_MD_SHA256:
            return 64;
        case MBEDTLS_MD_SHA384:
            return 128;
        case MBEDTLS_MD_SHA512:
            return 128;
        default:
            ASSERT(FALSE);
            return 0;
    }
}

/**
  Makes a copy of an existing HMAC-MD context.

  If hmac_md_ctx is NULL, then return FALSE.
  If new_hmac_md_ctx is NULL, then return FALSE.

  @param[in]  md_type          message digest Type.
  @param[in]  hmac_md_ctx      Pointer to HMAC-MD context being copied.
  @param[out] new_hmac_md_ctx  Pointer to new HMAC-MD context.

  @retval TRUE   HMAC-MD context copy succeeded.
  @retval FALSE  HMAC-MD context copy failed.

**/
boolean hmac_md_duplicate(IN mbedtls_md_type_t md_type, IN const void *hmac_md_ctx, OUT void *new_hmac_md_ctx)
{
    int32_t ret;
    const mbedtls_md_info_t *md_info;

    if (hmac_md_ctx == NULL || new_hmac_md_ctx == NULL) {
        return FALSE;
    }

    zero_mem(new_hmac_md_ctx, sizeof(mbedtls_md_context_t));
    mbedtls_md_init(new_hmac_md_ctx);

    md_info = mbedtls_md_info_from_type(md_type);
    ASSERT(md_info != NULL);

    ret = mbedtls_md_setup(new_hmac_md_ctx, md_info, 1);
    if (ret != 0) {
        return FALSE;
    }
    ret = mbedtls_md_clone(new_hmac_md_ctx, hmac_md_ctx);
    if (ret != 0) {
        return FALSE;
    }
    //Temporary solution to the problem of context clone.
    //There are not any standard function in mbedtls to clone a complete hmac context.
    copy_mem(
        ((mbedtls_md_context_t *)new_hmac_md_ctx)->hmac_ctx,
        ((mbedtls_md_context_t *)hmac_md_ctx)->hmac_ctx,
        hmac_md_get_blocksize(md_type) * 2);
    return TRUE;
}

/**
  Digests the input data and updates HMAC-MD context.

  This function performs HMAC-MD digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-MD context should be initialized by hmac_md_new(), and should not be finalized
  by hmac_md_final(). Behavior with invalid context is undefined.

  If hmac_md_ctx is NULL, then return FALSE.

  @param[in, out]  hmac_md_ctx     Pointer to the HMAC-MD context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-MD data digest succeeded.
  @retval FALSE  HMAC-MD data digest failed.

**/
boolean hmac_md_update(IN OUT void *hmac_md_ctx, IN const void *data,
               IN uintn data_size)
{
    int32_t ret;

    if (hmac_md_ctx == NULL) {
        return FALSE;
    }

    if (data == NULL && data_size != 0) {
        return FALSE;
    }
    if (data_size > INT_MAX) {
        return FALSE;
    }

    ret = mbedtls_md_hmac_update(hmac_md_ctx, data, data_size);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
  Completes computation of the HMAC-MD digest value.

  This function completes HMAC-MD hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-MD context cannot
  be used again.
  HMAC-MD context should be initialized by hmac_md_new(), and should not be finalized
  by hmac_md_final(). Behavior with invalid HMAC-MD context is undefined.

  If hmac_md_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.

  @param[in, out]  hmac_md_ctx      Pointer to the HMAC-MD context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-MD digest
                                      value.

  @retval TRUE   HMAC-MD digest computation succeeded.
  @retval FALSE  HMAC-MD digest computation failed.

**/
boolean hmac_md_final(IN OUT void *hmac_md_ctx, OUT uint8_t *hmac_value)
{
    int32_t ret;

    if (hmac_md_ctx == NULL || hmac_value == NULL) {
        return FALSE;
    }

    ret = mbedtls_md_hmac_finish(hmac_md_ctx, hmac_value);
    mbedtls_md_free(hmac_md_ctx);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
  Computes the HMAC-MD digest of a input data buffer.

  This function performs the HMAC-MD digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   md_type      message digest Type.
  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-MD digest
                           value.

  @retval TRUE   HMAC-MD digest computation succeeded.
  @retval FALSE  HMAC-MD digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_md_all(IN mbedtls_md_type_t md_type, IN const void *data,
            IN uintn data_size, IN const uint8_t *key, IN uintn key_size,
            OUT uint8_t *hmac_value)
{
    const mbedtls_md_info_t *md_info;
    int32_t ret;

    md_info = mbedtls_md_info_from_type(md_type);
    ASSERT(md_info != NULL);

    ret = mbedtls_md_hmac(md_info, key, key_size, data, data_size,
                  hmac_value);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA256 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha256_new() returns NULL.

**/
void *hmac_sha256_new(void)
{
    return hmac_md_new();
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha256_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha256_free(IN void *hmac_sha256_ctx)
{
    hmac_md_free(hmac_sha256_ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha256_update().

  If hmac_sha256_ctx is NULL, then return FALSE.

  @param[out]  hmac_sha256_ctx  Pointer to HMAC-SHA256 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.

**/
boolean hmac_sha256_set_key(OUT void *hmac_sha256_ctx, IN const uint8_t *key,
                IN uintn key_size)
{
    return hmac_md_set_key(MBEDTLS_MD_SHA256, hmac_sha256_ctx, key,
                   key_size);
}

/**
  Makes a copy of an existing HMAC-SHA256 context.

  If hmac_sha256_ctx is NULL, then return FALSE.
  If new_hmac_sha256_ctx is NULL, then return FALSE.

  @param[in]  hmac_sha256_ctx     Pointer to HMAC-SHA256 context being copied.
  @param[out] new_hmac_sha256_ctx  Pointer to new HMAC-SHA256 context.

  @retval TRUE   HMAC-SHA256 context copy succeeded.
  @retval FALSE  HMAC-SHA256 context copy failed.

**/
boolean hmac_sha256_duplicate(IN const void *hmac_sha256_ctx,
                  OUT void *new_hmac_sha256_ctx)
{
    return hmac_md_duplicate(MBEDTLS_MD_SHA256, hmac_sha256_ctx, new_hmac_sha256_ctx);
}

/**
  Digests the input data and updates HMAC-SHA256 context.

  This function performs HMAC-SHA256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA256 context should be initialized by hmac_sha256_new(), and should not be finalized
  by hmac_sha256_final(). Behavior with invalid context is undefined.

  If hmac_sha256_ctx is NULL, then return FALSE.

  @param[in, out]  hmac_sha256_ctx Pointer to the HMAC-SHA256 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA256 data digest succeeded.
  @retval FALSE  HMAC-SHA256 data digest failed.

**/
boolean hmac_sha256_update(IN OUT void *hmac_sha256_ctx, IN const void *data,
               IN uintn data_size)
{
    return hmac_md_update(hmac_sha256_ctx, data, data_size);
}

/**
  Completes computation of the HMAC-SHA256 digest value.

  This function completes HMAC-SHA256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA256 context cannot
  be used again.
  HMAC-SHA256 context should be initialized by hmac_sha256_new(), and should not be finalized
  by hmac_sha256_final(). Behavior with invalid HMAC-SHA256 context is undefined.

  If hmac_sha256_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.

  @param[in, out]  hmac_sha256_ctx  Pointer to the HMAC-SHA256 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA256 digest
                                      value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.

**/
boolean hmac_sha256_final(IN OUT void *hmac_sha256_ctx, OUT uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha256_ctx, hmac_value);
}

/**
  Computes the HMAC-SHA256 digest of a input data buffer.

  This function performs the HMAC-SHA256 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA256 digest
                           value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_all(IN const void *data, IN uintn data_size,
            IN const uint8_t *key, IN uintn key_size,
            OUT uint8_t *hmac_value)
{
    return hmac_md_all(MBEDTLS_MD_SHA256, data, data_size, key, key_size,
               hmac_value);
}

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA384 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha384_new() returns NULL.

**/
void *hmac_sha384_new(void)
{
    return hmac_md_new();
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha384_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha384_free(IN void *hmac_sha384_ctx)
{
    hmac_md_free(hmac_sha384_ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha384_update().

  If hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  hmac_sha384_ctx  Pointer to HMAC-SHA384 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_set_key(OUT void *hmac_sha384_ctx, IN const uint8_t *key,
                IN uintn key_size)
{
    return hmac_md_set_key(MBEDTLS_MD_SHA384, hmac_sha384_ctx, key,
                   key_size);
}

/**
  Makes a copy of an existing HMAC-SHA384 context.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If new_hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  hmac_sha384_ctx     Pointer to HMAC-SHA384 context being copied.
  @param[out] new_hmac_sha384_ctx  Pointer to new HMAC-SHA384 context.

  @retval TRUE   HMAC-SHA384 context copy succeeded.
  @retval FALSE  HMAC-SHA384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_duplicate(IN const void *hmac_sha384_ctx,
                  OUT void *new_hmac_sha384_ctx)
{
    return hmac_md_duplicate(MBEDTLS_MD_SHA384, hmac_sha384_ctx, new_hmac_sha384_ctx);
}

/**
  Digests the input data and updates HMAC-SHA384 context.

  This function performs HMAC-SHA384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA384 context should be initialized by hmac_sha384_new(), and should not be finalized
  by hmac_sha384_final(). Behavior with invalid context is undefined.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha384_ctx Pointer to the HMAC-SHA384 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA384 data digest succeeded.
  @retval FALSE  HMAC-SHA384 data digest failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_update(IN OUT void *hmac_sha384_ctx, IN const void *data,
               IN uintn data_size)
{
    return hmac_md_update(hmac_sha384_ctx, data, data_size);
}

/**
  Completes computation of the HMAC-SHA384 digest value.

  This function completes HMAC-SHA384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA384 context cannot
  be used again.
  HMAC-SHA384 context should be initialized by hmac_sha384_new(), and should not be finalized
  by hmac_sha384_final(). Behavior with invalid HMAC-SHA384 context is undefined.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha384_ctx  Pointer to the HMAC-SHA384 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA384 digest
                                      value (48 bytes).

  @retval TRUE   HMAC-SHA384 digest computation succeeded.
  @retval FALSE  HMAC-SHA384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_final(IN OUT void *hmac_sha384_ctx, OUT uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha384_ctx, hmac_value);
}

/**
  Computes the HMAC-SHA384 digest of a input data buffer.

  This function performs the HMAC-SHA384 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA384 digest
                           value (48 bytes).

  @retval TRUE   HMAC-SHA384 digest computation succeeded.
  @retval FALSE  HMAC-SHA384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_all(IN const void *data, IN uintn data_size,
            IN const uint8_t *key, IN uintn key_size,
            OUT uint8_t *hmac_value)
{
    return hmac_md_all(MBEDTLS_MD_SHA384, data, data_size, key, key_size,
               hmac_value);
}

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA512 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha512_new() returns NULL.

**/
void *hmac_sha512_new(void)
{
    return hmac_md_new();
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha512_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha512_free(IN void *hmac_sha512_ctx)
{
    hmac_md_free(hmac_sha512_ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha512_update().

  If hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  hmac_sha512_ctx  Pointer to HMAC-SHA512 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_set_key(OUT void *hmac_sha512_ctx, IN const uint8_t *key,
                IN uintn key_size)
{
    return hmac_md_set_key(MBEDTLS_MD_SHA512, hmac_sha512_ctx, key,
                   key_size);
}

/**
  Makes a copy of an existing HMAC-SHA512 context.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If new_hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  hmac_sha512_ctx     Pointer to HMAC-SHA512 context being copied.
  @param[out] new_hmac_sha512_ctx  Pointer to new HMAC-SHA512 context.

  @retval TRUE   HMAC-SHA512 context copy succeeded.
  @retval FALSE  HMAC-SHA512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_duplicate(IN const void *hmac_sha512_ctx,
                  OUT void *new_hmac_sha512_ctx)
{
    return hmac_md_duplicate(MBEDTLS_MD_SHA512, hmac_sha512_ctx, new_hmac_sha512_ctx);
}

/**
  Digests the input data and updates HMAC-SHA512 context.

  This function performs HMAC-SHA512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA512 context should be initialized by hmac_sha512_new(), and should not be finalized
  by hmac_sha512_final(). Behavior with invalid context is undefined.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha512_ctx Pointer to the HMAC-SHA512 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA512 data digest succeeded.
  @retval FALSE  HMAC-SHA512 data digest failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_update(IN OUT void *hmac_sha512_ctx, IN const void *data,
               IN uintn data_size)
{
    return hmac_md_update(hmac_sha512_ctx, data, data_size);
}

/**
  Completes computation of the HMAC-SHA512 digest value.

  This function completes HMAC-SHA512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA512 context cannot
  be used again.
  HMAC-SHA512 context should be initialized by hmac_sha512_new(), and should not be finalized
  by hmac_sha512_final(). Behavior with invalid HMAC-SHA512 context is undefined.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha512_ctx  Pointer to the HMAC-SHA512 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA512 digest
                                      value (64 bytes).

  @retval TRUE   HMAC-SHA512 digest computation succeeded.
  @retval FALSE  HMAC-SHA512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_final(IN OUT void *hmac_sha512_ctx, OUT uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha512_ctx, hmac_value);
}

/**
  Computes the HMAC-SHA512 digest of a input data buffer.

  This function performs the HMAC-SHA512 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA512 digest
                           value (64 bytes).

  @retval TRUE   HMAC-SHA512 digest computation succeeded.
  @retval FALSE  HMAC-SHA512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_all(IN const void *data, IN uintn data_size,
            IN const uint8_t *key, IN uintn key_size,
            OUT uint8_t *hmac_value)
{
    return hmac_md_all(MBEDTLS_MD_SHA512, data, data_size, key, key_size,
               hmac_value);
}
