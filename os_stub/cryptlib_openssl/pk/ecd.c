/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Edwards-Curve Wrapper Implementation.

  RFC 8032 - Edwards-Curve Digital signature algorithm (EdDSA)
  FIPS 186-4 - Digital signature Standard (DSS)
**/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/**
  Allocates and Initializes one Edwards-Curve context for subsequent use
  with the NID.

  The key is generated before the function returns.

  @param nid cipher NID

  @return  Pointer to the Edwards-Curve context that has been initialized.
           If the allocations fails, ecd_new_by_nid() returns NULL.

**/
void *ecd_new_by_nid(IN uintn nid)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey;
	int32 result;
	int32 openssl_pkey_type;

	switch (nid) {
	case CRYPTO_NID_EDDSA_ED25519:
		openssl_pkey_type = EVP_PKEY_ED25519;
		break;
	case CRYPTO_NID_EDDSA_ED448:
		openssl_pkey_type = EVP_PKEY_ED448;
		break;
	default:
		return NULL;
	}

	pkey_ctx = EVP_PKEY_CTX_new_id(openssl_pkey_type, NULL);
	if (pkey_ctx == NULL) {
		return NULL;
	}
	result = EVP_PKEY_keygen_init(pkey_ctx);
	if (result <= 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}
	pkey = NULL;
	result = EVP_PKEY_keygen(pkey_ctx, &pkey);
	if (result <= 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(pkey_ctx);

	return (void *)pkey;
}

/**
  Release the specified Ed context.

  @param[in]  ecd_context  Pointer to the Ed context to be released.

**/
void ecd_free(IN void *ecd_context)
{
	EVP_PKEY_free((EVP_PKEY *)ecd_context);
}

/**
  Sets the public key component into the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   Ed public key component was set successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_set_pub_key(IN OUT void *ecd_context, IN uint8 *public_key,
			IN uintn public_key_size)
{
	// TBD
	return FALSE;
}

/**
  Gets the public key component from the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   Ed key component was retrieved successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_get_pub_key(IN OUT void *ecd_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size)
{
	EVP_PKEY *pkey;
	int32 result;
	uint32 final_pub_key_size;

	if (ecd_context == NULL || public_key == NULL ||
	    public_key_size == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)ecd_context;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_ED25519:
		final_pub_key_size = 32;
		break;
	case EVP_PKEY_ED448:
		final_pub_key_size = 57;
		break;
	default:
		return FALSE;
	}
	if (*public_key_size < final_pub_key_size) {
		*public_key_size = final_pub_key_size;
		return FALSE;
	}
	*public_key_size = final_pub_key_size;
	zero_mem(public_key, *public_key_size);
	result = EVP_PKEY_get_raw_public_key(pkey, public_key, public_key_size);
	if (result == 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Validates key components of Ed context.
  NOTE: This function performs integrity checks on all the Ed key material, so
        the Ed key structure must contain all the private key data.

  If ecd_context is NULL, then return FALSE.

  @param[in]  ecd_context  Pointer to Ed context to check.

  @retval  TRUE   Ed key components are valid.
  @retval  FALSE  Ed key components are not valid.

**/
boolean ecd_check_key(IN void *ecd_context)
{
	// TBD
	return FALSE;
}

/**
  Generates Ed key and returns Ed public key.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  If ecd_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ecd_context      Pointer to the Ed context.
  @param[out]      public         Pointer to the buffer to receive generated public key.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   Ed public key generation succeeded.
  @retval FALSE  Ed public key generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ecd_generate_key(IN OUT void *ecd_context, OUT uint8 *public_key,
			 IN OUT uintn *public_key_size)
{
	// TBD
	return TRUE;
}

/**
  Carries out the Ed-DSA signature.

  This function carries out the Ed-DSA signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be NULL.
  If sig_size is large enough but signature is NULL, then return FALSE.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]       ecd_context    Pointer to Ed context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive Ed-DSA signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in Ed-DSA.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean eddsa_sign(IN void *ecd_context, IN uintn hash_nid,
		   IN const uint8 *message, IN uintn size, OUT uint8 *signature,
		   IN OUT uintn *sig_size)
{
	EVP_PKEY *pkey;
	EVP_MD_CTX *ctx;
	uintn half_size;
	int32 result;

	if (ecd_context == NULL || message == NULL) {
		return FALSE;
	}

	if (signature == NULL || sig_size == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)ecd_context;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_ED25519:
		half_size = 32;
		break;
	case EVP_PKEY_ED448:
		half_size = 57;
		break;
	default:
		return FALSE;
	}
	if (*sig_size < (uintn)(half_size * 2)) {
		*sig_size = half_size * 2;
		return FALSE;
	}
	*sig_size = half_size * 2;
	zero_mem(signature, *sig_size);

	switch (hash_nid) {
	case CRYPTO_NID_NULL:
		break;

	default:
		return FALSE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return FALSE;
	}
	result = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}
	result = EVP_DigestSign(ctx, signature, sig_size, message, size);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}

	EVP_MD_CTX_free(ctx);
	return TRUE;
}

/**
  Verifies the Ed-DSA signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be NULL.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]  ecd_context    Pointer to Ed context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to Ed-DSA signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in Ed-DSA.
  @retval  FALSE  Invalid signature or invalid Ed context.

**/
boolean eddsa_verify(IN void *ecd_context, IN uintn hash_nid,
		     IN const uint8 *message, IN uintn size,
		     IN const uint8 *signature, IN uintn sig_size)
{
	EVP_PKEY *pkey;
	EVP_MD_CTX *ctx;
	uintn half_size;
	int32 result;

	if (ecd_context == NULL || message == NULL || signature == NULL) {
		return FALSE;
	}

	if (sig_size > INT_MAX || sig_size == 0) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)ecd_context;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_ED25519:
		half_size = 32;
		break;
	case EVP_PKEY_ED448:
		half_size = 57;
		break;
	default:
		return FALSE;
	}
	if (sig_size != (uintn)(half_size * 2)) {
		return FALSE;
	}

	switch (hash_nid) {
	case CRYPTO_NID_NULL:
		break;

	default:
		return FALSE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return FALSE;
	}
	result = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}
	result = EVP_DigestVerify(ctx, signature, sig_size, message, size);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}

	EVP_MD_CTX_free(ctx);
	return TRUE;
}
