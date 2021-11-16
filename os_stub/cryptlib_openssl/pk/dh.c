/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Diffie-Hellman Wrapper Implementation over.

  RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
**/

#include "internal_crypt_lib.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>

/**
  Allocates and Initializes one Diffie-Hellman context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Diffie-Hellman context that has been initialized.
           If the allocations fails, dh_new() returns NULL.

**/
void *dh_new_by_nid(IN uintn nid)
{
	switch (nid) {
	case CRYPTO_NID_FFDHE2048:
		return DH_new_by_nid(NID_ffdhe2048);
	case CRYPTO_NID_FFDHE3072:
		return DH_new_by_nid(NID_ffdhe3072);
	case CRYPTO_NID_FFDHE4096:
		return DH_new_by_nid(NID_ffdhe4096);
	default:
		return NULL;
	}
}

/**
  Release the specified DH context.

  If dh_context is NULL, then return FALSE.

  @param[in]  dh_context  Pointer to the DH context to be released.

**/
void dh_free(IN void *dh_context)
{
	//
	// Free OpenSSL DH context
	//
	DH_free((DH *)dh_context);
}

/**
  Generates DH parameter.

  Given generator g, and length of prime number p in bits, this function generates p,
  and sets DH context according to value of g and p.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by random_seed().

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[out]      prime        Pointer to the buffer to receive the generated prime number.

  @retval TRUE   DH parameter generation succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  PRNG fails to generate random prime number with prime_length.

**/
boolean dh_generate_parameter(IN OUT void *dh_context, IN uintn generator,
			      IN uintn prime_length, OUT uint8_t *prime)
{
	boolean ret_val;
	BIGNUM *bn_p;

	//
	// Check input parameters.
	//
	if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
		return FALSE;
	}

	if (generator != DH_GENERATOR_2 && generator != DH_GENERATOR_5) {
		return FALSE;
	}

	ret_val = (boolean)DH_generate_parameters_ex(
		dh_context, (uint32_t)prime_length, (uint32_t)generator, NULL);
	if (!ret_val) {
		return FALSE;
	}

	DH_get0_pqg(dh_context, (const BIGNUM **)&bn_p, NULL, NULL);
	BN_bn2bin(bn_p, prime);

	return TRUE;
}

/**
  Sets generator and prime parameters for DH.

  Given generator g, and prime number p, this function and sets DH
  context accordingly.

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[in]       prime        Pointer to the prime number.

  @retval TRUE   DH parameter setting succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  value of generator is not suitable for the prime.
  @retval FALSE  value of prime is not a prime number.
  @retval FALSE  value of prime is not a safe prime number.

**/
boolean dh_set_parameter(IN OUT void *dh_context, IN uintn generator,
			 IN uintn prime_length, IN const uint8_t *prime)
{
	DH *dh;
	BIGNUM *bn_p;
	BIGNUM *bn_g;

	//
	// Check input parameters.
	//
	if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
		return FALSE;
	}

	if (generator != DH_GENERATOR_2 && generator != DH_GENERATOR_5) {
		return FALSE;
	}

	//
	// Set the generator and prime parameters for DH object.
	//
	dh = (DH *)dh_context;
	bn_p = BN_bin2bn((const unsigned char *)prime, (int)(prime_length / 8),
			 NULL);
	bn_g = BN_bin2bn((const unsigned char *)&generator, 1, NULL);
	if ((bn_p == NULL) || (bn_g == NULL) ||
	    !DH_set0_pqg(dh, bn_p, NULL, bn_g)) {
		goto error;
	}

	return TRUE;

error:
	BN_free(bn_p);
	BN_free(bn_g);

	return FALSE;
}

/**
  Generates DH public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  If dh_context is NULL, then return FALSE.
  If public_key_size is NULL, then return FALSE.
  If public_key_size is large enough but public_key is NULL, then return FALSE.

  For FFDHE2048, the public_size is 256.
  For FFDHE3072, the public_size is 384.
  For FFDHE4096, the public_size is 512.

  @param[in, out]  dh_context      Pointer to the DH context.
  @param[out]      public_key      Pointer to the buffer to receive generated public key.
  @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
                                  On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DH public key generation succeeded.
  @retval FALSE  DH public key generation failed.
  @retval FALSE  public_key_size is not large enough.

**/
boolean dh_generate_key(IN OUT void *dh_context, OUT uint8_t *public_key,
			IN OUT uintn *public_key_size)
{
	boolean ret_val;
	DH *dh;
	BIGNUM *dh_pub_key;
	intn size;
	uintn final_pub_key_size;

	//
	// Check input parameters.
	//
	if (dh_context == NULL || public_key_size == NULL) {
		return FALSE;
	}

	if (public_key == NULL && *public_key_size != 0) {
		return FALSE;
	}

	dh = (DH *)dh_context;
	switch (DH_size(dh)) {
	case 256:
		final_pub_key_size = 256;
		break;
	case 384:
		final_pub_key_size = 384;
		break;
	case 512:
		final_pub_key_size = 512;
		break;
	default:
		return FALSE;
	}

	if (*public_key_size < final_pub_key_size) {
		*public_key_size = final_pub_key_size;
		return FALSE;
	}
	*public_key_size = final_pub_key_size;

	ret_val = (boolean)DH_generate_key(dh_context);
	if (ret_val) {
		DH_get0_key(dh, (const BIGNUM **)&dh_pub_key, NULL);
		size = BN_num_bytes(dh_pub_key);
		if (size <= 0) {
			return FALSE;
		}
		ASSERT((uintn)size <= final_pub_key_size);

		if (public_key != NULL) {
			zero_mem(public_key, *public_key_size);
			BN_bn2bin(dh_pub_key,
				  &public_key[0 + final_pub_key_size - size]);
		}
	}

	return ret_val;
}

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  If dh_context is NULL, then return FALSE.
  If peer_public_key is NULL, then return FALSE.
  If key_size is NULL, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  For FFDHE2048, the peer_public_size and key_size is 256.
  For FFDHE3072, the peer_public_size and key_size is 384.
  For FFDHE4096, the peer_public_size and key_size is 512.

  @param[in, out]  dh_context          Pointer to the DH context.
  @param[in]       peer_public_key      Pointer to the peer's public key.
  @param[in]       peer_public_key_size  size of peer's public key in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DH exchanged key generation succeeded.
  @retval FALSE  DH exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean dh_compute_key(IN OUT void *dh_context, IN const uint8_t *peer_public_key,
		       IN uintn peer_public_key_size, OUT uint8_t *key,
		       IN OUT uintn *key_size)
{
	BIGNUM *bn;
	intn size;
	DH *dh;
	uintn final_key_size;

	//
	// Check input parameters.
	//
	if (dh_context == NULL || peer_public_key == NULL || key_size == NULL ||
	    key == NULL) {
		return FALSE;
	}

	if (peer_public_key_size > INT_MAX) {
		return FALSE;
	}

	bn = BN_bin2bn(peer_public_key, (uint32_t)peer_public_key_size, NULL);
	if (bn == NULL) {
		return FALSE;
	}

	dh = (DH *)dh_context;
	switch (DH_size(dh)) {
	case 256:
		final_key_size = 256;
		break;
	case 384:
		final_key_size = 384;
		break;
	case 512:
		final_key_size = 512;
		break;
	default:
		BN_free(bn);
		return FALSE;
	}
	if (*key_size < final_key_size) {
		*key_size = final_key_size;
		BN_free(bn);
		return FALSE;
	}

	size = DH_compute_key_padded(key, bn, dh_context);
	BN_free(bn);
	if (size < 0) {
		return FALSE;
	}
	if ((uintn)size != final_key_size) {
		return FALSE;
	}

	*key_size = size;
	return TRUE;
}
