/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Montgomery-Curve Wrapper Implementation.

  RFC 7748 - Elliptic Curves for Security (Curve25519/Curve448)
  NIST SP 800-186 - Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters
**/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/**
  Allocates and Initializes one Montgomery-Curve Context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Montgomery-Curve Context that has been initialized.
           If the allocations fails, ecx_new_by_nid() returns NULL.

**/
void *ecx_new_by_nid(IN uintn nid)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey;
	int32_t result;
	int32_t openssl_pkey_type;

	switch (nid) {
	case CRYPTO_NID_CURVE_X25519:
		openssl_pkey_type = NID_X25519;
		break;
	case CRYPTO_NID_CURVE_X448:
		openssl_pkey_type = NID_X448;
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
  Release the specified Ecx context.

  @param[in]  ecx_context  Pointer to the Ecx context to be released.

**/
void ecx_free(IN void *ecx_context)
{
	EVP_PKEY_free((EVP_PKEY *)ecx_context);
}

/**
  Generates Ecx key and returns Ecx public key.

  This function generates random secret, and computes the public key, which is
  returned via parameter public, public_size.
  Ecx context is updated accordingly.
  If the public buffer is too small to hold the public key, FALSE is returned and
  public_size is set to the required buffer size to obtain the public key.

  For X25519, the public_size is 32.
  For X448, the public_size is 56.

  If ecx_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ecx_context      Pointer to the Ecx context.
  @param[out]      public         Pointer to the buffer to receive generated public key.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   Ecx public key generation succeeded.
  @retval FALSE  Ecx public key generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ecx_generate_key(IN OUT void *ecx_context, OUT uint8_t *public,
			 IN OUT uintn *public_size)
{
	EVP_PKEY *pkey;
	int32_t result;
	uint32_t final_pub_key_size;

	if (ecx_context == NULL || public == NULL || public_size == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)ecx_context;
	switch (EVP_PKEY_id(pkey)) {
	case NID_X25519:
		final_pub_key_size = 32;
		break;
	case NID_X448:
		final_pub_key_size = 56;
		break;
	default:
		return FALSE;
	}
	if (*public_size < final_pub_key_size) {
		*public_size = final_pub_key_size;
		return FALSE;
	}
	*public_size = final_pub_key_size;
	zero_mem(public, *public_size);
	result = EVP_PKEY_get_raw_public_key(pkey, public, public_size);
	if (result == 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.

  If ecx_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  For X25519, the public_size is 32.
  For X448, the public_size is 56.

  @param[in, out]  ecx_context          Pointer to the Ecx context.
  @param[in]       peer_public         Pointer to the peer's public key.
  @param[in]       peer_public_size     Size of peer's public key in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   Ecx exchanged key generation succeeded.
  @retval FALSE  Ecx exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean ecx_compute_key(IN OUT void *ecx_context, IN const uint8_t *peer_public,
			IN uintn peer_public_size, OUT uint8_t *key,
			IN OUT uintn *key_size)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey;
	EVP_PKEY *peer_key;
	int32_t result;
	uint32_t final_key_size;
	int32_t openssl_pkey_type;

	if (ecx_context == NULL || peer_public == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)ecx_context;
	switch (EVP_PKEY_id(pkey)) {
	case NID_X25519:
		openssl_pkey_type = NID_X25519;
		final_key_size = 32;
		break;
	case NID_X448:
		openssl_pkey_type = NID_X448;
		final_key_size = 56;
		break;
	default:
		return FALSE;
	}
	if (*key_size < final_key_size) {
		*key_size = final_key_size;
		return FALSE;
	}
	*key_size = final_key_size;
	zero_mem(key, *key_size);

	// Derive key
	pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pkey_ctx == NULL) {
		return FALSE;
	}
	result = EVP_PKEY_derive_init(pkey_ctx);
	if (result <= 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}

	peer_key = EVP_PKEY_new_raw_public_key(openssl_pkey_type, NULL,
					       peer_public, peer_public_size);
	if (peer_key == NULL) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	result = EVP_PKEY_derive_set_peer(pkey_ctx, peer_key);
	if (result <= 0) {
		EVP_PKEY_free(peer_key);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	EVP_PKEY_free(peer_key);

	result = EVP_PKEY_derive(pkey_ctx, key, key_size);
	if (result <= 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}

	EVP_PKEY_CTX_free(pkey_ctx);
	return TRUE;
}
