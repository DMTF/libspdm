/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Diffie-Hellman Wrapper Implementation over OpenSSL.

  RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
**/

#include "internal_crypt_lib.h"
#include <mbedtls/dhm.h>
#include <mbedtls/bignum.h>

static const unsigned char m_ffehde2048_p[] =
	MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
static const unsigned char m_ffehde3072_p[] =
	MBEDTLS_DHM_RFC7919_FFDHE3072_P_BIN;
static const unsigned char m_ffehde4096_p[] =
	MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
static const unsigned char m_ffehde2048_g[] =
	MBEDTLS_DHM_RFC7919_FFDHE2048_G_BIN;
static const unsigned char m_ffehde3072_g[] =
	MBEDTLS_DHM_RFC7919_FFDHE3072_G_BIN;
static const unsigned char m_ffehde4096_g[] =
	MBEDTLS_DHM_RFC7919_FFDHE4096_G_BIN;

/**
  Allocates and Initializes one Diffie-Hellman context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Diffie-Hellman context that has been initialized.
           If the allocations fails, dh_new() returns NULL.

**/
void *dh_new_by_nid(IN uintn nid)
{
	mbedtls_dhm_context *ctx;
	int32 ret;

	ctx = allocate_zero_pool(sizeof(mbedtls_dhm_context));
	if (ctx == NULL) {
		return NULL;
	}

	mbedtls_dhm_init(ctx);

	switch (nid) {
	case CRYPTO_NID_FFDHE2048:
		ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde2048_p,
					      sizeof(m_ffehde2048_p));
		if (ret != 0) {
			goto error;
		}
		ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde2048_g,
					      sizeof(m_ffehde2048_g));
		if (ret != 0) {
			goto error;
		}
		break;
	case CRYPTO_NID_FFDHE3072:
		ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde3072_p,
					      sizeof(m_ffehde3072_p));
		if (ret != 0) {
			goto error;
		}
		ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde3072_g,
					      sizeof(m_ffehde3072_g));
		if (ret != 0) {
			goto error;
		}
		break;
	case CRYPTO_NID_FFDHE4096:
		ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde4096_p,
					      sizeof(m_ffehde4096_p));
		if (ret != 0) {
			goto error;
		}
		ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde4096_g,
					      sizeof(m_ffehde4096_g));
		if (ret != 0) {
			goto error;
		}
		break;
	default:
		goto error;
	}
	ctx->len = mbedtls_mpi_size(&ctx->P);
	return ctx;
error:
	free_pool(ctx);
	return NULL;
}

/**
  Release the specified DH context.

  If dh_context is NULL, then return FALSE.

  @param[in]  dh_context  Pointer to the DH context to be released.

**/
void dh_free(IN void *dh_context)
{
	mbedtls_dhm_free(dh_context);
	free_pool(dh_context);
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
			      IN uintn prime_length, OUT uint8 *prime)
{
	return FALSE;
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
			 IN uintn prime_length, IN const uint8 *prime)
{
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
boolean dh_generate_key(IN OUT void *dh_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size)
{
	int32 ret;
	mbedtls_dhm_context *ctx;
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

	ctx = dh_context;
	switch (mbedtls_mpi_size(&ctx->P)) {
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
	zero_mem(public_key, *public_key_size);

	ret = mbedtls_dhm_make_public(dh_context, (uint32)*public_key_size,
				      public_key, (uint32)*public_key_size,
				      myrand, NULL);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
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

  For FFDHE2048, the peer_public_size is 256.
  For FFDHE3072, the peer_public_size is 384.
  For FFDHE4096, the peer_public_size is 512.

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
boolean dh_compute_key(IN OUT void *dh_context, IN const uint8 *peer_public_key,
		       IN uintn peer_public_key_size, OUT uint8 *key,
		       IN OUT uintn *key_size)
{
	int32 ret;

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

	ret = mbedtls_dhm_read_public(dh_context, peer_public_key,
				      peer_public_key_size);
	if (ret != 0) {
		return FALSE;
	}

	ret = mbedtls_dhm_calc_secret(dh_context, key, *key_size, key_size,
				      myrand, NULL);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}
