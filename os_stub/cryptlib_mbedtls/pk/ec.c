/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Elliptic Curve Wrapper Implementation.

  RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
  FIPS 186-4 - Digital signature Standard (DSS)
**/

#include "internal_crypt_lib.h"
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>

/**
  Allocates and Initializes one Elliptic Curve context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Elliptic Curve context that has been initialized.
           If the allocations fails, ec_new_by_nid() returns NULL.

**/
void *ec_new_by_nid(IN uintn nid)
{
	mbedtls_ecdh_context *ctx;
	mbedtls_ecp_group_id grp_id;
	int32 ret;

	ctx = allocate_zero_pool(sizeof(mbedtls_ecdh_context));
	if (ctx == NULL) {
		return NULL;
	}
	switch (nid) {
	case CRYPTO_NID_SECP256R1:
		grp_id = MBEDTLS_ECP_DP_SECP256R1;
		break;
	case CRYPTO_NID_SECP384R1:
		grp_id = MBEDTLS_ECP_DP_SECP384R1;
		break;
	case CRYPTO_NID_SECP521R1:
		grp_id = MBEDTLS_ECP_DP_SECP521R1;
		break;
	default:
		goto error;
	}

	ret = mbedtls_ecdh_setup(ctx, grp_id);
	if (ret != 0) {
		goto error;
	}
	return ctx;
error:
	free_pool(ctx);
	return NULL;
}

/**
  Release the specified EC context.

  @param[in]  ec_context  Pointer to the EC context to be released.

**/
void ec_free(IN void *ec_context)
{
	mbedtls_ecdh_free(ec_context);
	free_pool(ec_context);
}

/**
  Sets the public key component into the established EC context.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  @param[in, out]  ec_context      Pointer to EC context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   EC public key component was set successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ec_set_pub_key(IN OUT void *ec_context, IN uint8 *public_key,
		       IN uintn public_key_size)
{
	mbedtls_ecdh_context *ctx;
	int32 ret;
	uintn half_size;

	if (ec_context == NULL || public_key == NULL) {
		return FALSE;
	}

	ctx = ec_context;
	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
		break;
	default:
		return FALSE;
	}
	if (public_key_size != half_size * 2) {
		return FALSE;
	}

	ret = mbedtls_mpi_read_binary(&ctx->Q.X, public_key, half_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_read_binary(&ctx->Q.Y, public_key + half_size,
				      half_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_lset(&ctx->Q.Z, 1);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Gets the public key component from the established EC context.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  @param[in, out]  ec_context      Pointer to EC context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   EC key component was retrieved successfully.
  @retval  FALSE  Invalid EC key component.

**/
boolean ec_get_pub_key(IN OUT void *ec_context, OUT uint8 *public_key,
		       IN OUT uintn *public_key_size)
{
	mbedtls_ecdh_context *ctx;
	int32 ret;
	uintn half_size;
	uintn x_size;
	uintn y_size;

	if (ec_context == NULL || public_key_size == NULL) {
		return FALSE;
	}

	if (public_key == NULL && *public_key_size != 0) {
		return FALSE;
	}

	ctx = ec_context;
	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
		break;
	default:
		return FALSE;
	}
	if (*public_key_size < half_size * 2) {
		*public_key_size = half_size * 2;
		return FALSE;
	}
	*public_key_size = half_size * 2;
	zero_mem(public_key, *public_key_size);

	x_size = mbedtls_mpi_size(&ctx->Q.X);
	y_size = mbedtls_mpi_size(&ctx->Q.Y);
	ASSERT(x_size <= half_size && y_size <= half_size);

	ret = mbedtls_mpi_write_binary(
		&ctx->Q.X, &public_key[0 + half_size - x_size], x_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_write_binary(
		&ctx->Q.Y, &public_key[half_size + half_size - y_size], y_size);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Validates key components of EC context.
  NOTE: This function performs integrity checks on all the EC key material, so
        the EC key structure must contain all the private key data.

  If ec_context is NULL, then return FALSE.

  @param[in]  ec_context  Pointer to EC context to check.

  @retval  TRUE   EC key components are valid.
  @retval  FALSE  EC key components are not valid.

**/
boolean ec_check_key(IN void *ec_context)
{
	// TBD
	return TRUE;
}

/**
  Generates EC key and returns EC public key (X, Y).

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter public, public_size.
  X is the first half of public with size being public_size / 2,
  Y is the second half of public with size being public_size / 2.
  EC context is updated accordingly.
  If the public buffer is too small to hold the public X, Y, FALSE is returned and
  public_size is set to the required buffer size to obtain the public X, Y.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  If ec_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ec_context      Pointer to the EC context.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   EC public X,Y generation succeeded.
  @retval FALSE  EC public X,Y generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ec_generate_key(IN OUT void *ec_context, OUT uint8 *public,
			IN OUT uintn *public_size)
{
	mbedtls_ecdh_context *ctx;
	int32 ret;
	uintn half_size;
	uintn x_size;
	uintn y_size;

	if (ec_context == NULL || public_size == NULL) {
		return FALSE;
	}

	if (public == NULL && *public_size != 0) {
		return FALSE;
	}

	ctx = ec_context;
	ret = mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, myrand,
				      NULL);
	if (ret != 0) {
		return FALSE;
	}

	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
		break;
	default:
		return FALSE;
	}
	if (*public_size < half_size * 2) {
		*public_size = half_size * 2;
		return FALSE;
	}
	*public_size = half_size * 2;
	zero_mem(public, *public_size);

	x_size = mbedtls_mpi_size(&ctx->Q.X);
	y_size = mbedtls_mpi_size(&ctx->Q.Y);
	ASSERT(x_size <= half_size && y_size <= half_size);

	ret = mbedtls_mpi_write_binary(&ctx->Q.X,
				       &public[0 + half_size - x_size], x_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_write_binary(
		&ctx->Q.Y, &public[half_size + half_size - y_size], y_size);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Computes exchanged common key.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of peer_public with size being peer_public_size / 2,
  Y is the second half of peer_public with size being peer_public_size / 2.

  If ec_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  For P-256, the peer_public_size is 64. first 32-byte is X, second 32-byte is Y. The key_size is 32.
  For P-384, the peer_public_size is 96. first 48-byte is X, second 48-byte is Y. The key_size is 48.
  For P-521, the peer_public_size is 132. first 66-byte is X, second 66-byte is Y. The key_size is 66.

  @param[in, out]  ec_context          Pointer to the EC context.
  @param[in]       peer_public         Pointer to the peer's public X,Y.
  @param[in]       peer_public_size     size of peer's public X,Y in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   EC exchanged key generation succeeded.
  @retval FALSE  EC exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean ec_compute_key(IN OUT void *ec_context, IN const uint8 *peer_public,
		       IN uintn peer_public_size, OUT uint8 *key,
		       IN OUT uintn *key_size)
{
	mbedtls_ecdh_context *ctx;
	uintn half_size;
	int32 ret;

	if (ec_context == NULL || peer_public == NULL || key_size == NULL ||
	    key == NULL) {
		return FALSE;
	}

	if (peer_public_size > INT_MAX) {
		return FALSE;
	}

	ctx = ec_context;
	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
		break;
	default:
		return FALSE;
	}
	if (peer_public_size != half_size * 2) {
		return FALSE;
	}

	ret = mbedtls_mpi_read_binary(&ctx->Qp.X, peer_public, half_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_read_binary(&ctx->Qp.Y, peer_public + half_size,
				      half_size);
	if (ret != 0) {
		return FALSE;
	}
	ret = mbedtls_mpi_lset(&ctx->Qp.Z, 1);
	if (ret != 0) {
		return FALSE;
	}

	ret = mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
					  myrand, NULL);
	if (ret != 0) {
		return FALSE;
	}

	if (mbedtls_mpi_size(&ctx->z) > *key_size) {
		return FALSE;
	}

	*key_size = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);
	ret = mbedtls_mpi_write_binary(&ctx->z, key, *key_size);
	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Carries out the EC-DSA signature.

  This function carries out the EC-DSA signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If ec_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.

  For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
  For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.

  @param[in]       ec_context    Pointer to EC context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message_hash  Pointer to octet message hash to be signed.
  @param[in]       hash_size     size of the message hash in bytes.
  @param[out]      signature    Pointer to buffer to receive EC-DSA signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in EC-DSA.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean ecdsa_sign(IN void *ec_context, IN uintn hash_nid,
		   IN const uint8 *message_hash, IN uintn hash_size,
		   OUT uint8 *signature, IN OUT uintn *sig_size)
{
	int32 ret;
	mbedtls_ecdh_context *ctx;
	mbedtls_mpi bn_r;
	mbedtls_mpi bn_s;
	uintn r_size;
	uintn s_size;
	uintn half_size;

	if (ec_context == NULL || message_hash == NULL) {
		return FALSE;
	}

	if (signature == NULL) {
		return FALSE;
	}

	ctx = ec_context;
	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
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
	case CRYPTO_NID_SHA256:
		if (hash_size != SHA256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA384:
		if (hash_size != SHA384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA512:
		if (hash_size != SHA512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	mbedtls_mpi_init(&bn_r);
	mbedtls_mpi_init(&bn_s);

	ret = mbedtls_ecdsa_sign(&ctx->grp, &bn_r, &bn_s, &ctx->d, message_hash,
				 hash_size, myrand, NULL);
	if (ret != 0) {
		return FALSE;
	}

	r_size = mbedtls_mpi_size(&bn_r);
	s_size = mbedtls_mpi_size(&bn_s);
	ASSERT(r_size <= half_size && s_size <= half_size);

	ret = mbedtls_mpi_write_binary(
		&bn_r, &signature[0 + half_size - r_size], r_size);
	if (ret != 0) {
		mbedtls_mpi_free(&bn_r);
		mbedtls_mpi_free(&bn_s);
		return FALSE;
	}
	ret = mbedtls_mpi_write_binary(
		&bn_s, &signature[half_size + half_size - s_size], s_size);
	if (ret != 0) {
		mbedtls_mpi_free(&bn_r);
		mbedtls_mpi_free(&bn_s);
		return FALSE;
	}

	mbedtls_mpi_free(&bn_r);
	mbedtls_mpi_free(&bn_s);

	return TRUE;
}

/**
  Verifies the EC-DSA signature.

  If ec_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
  For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.

  @param[in]  ec_context    Pointer to EC context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to EC-DSA signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in EC-DSA.
  @retval  FALSE  Invalid signature or invalid EC context.

**/
boolean ecdsa_verify(IN void *ec_context, IN uintn hash_nid,
		     IN const uint8 *message_hash, IN uintn hash_size,
		     IN const uint8 *signature, IN uintn sig_size)
{
	int32 ret;
	mbedtls_ecdh_context *ctx;
	mbedtls_mpi bn_r;
	mbedtls_mpi bn_s;
	uintn half_size;

	if (ec_context == NULL || message_hash == NULL || signature == NULL) {
		return FALSE;
	}

	if (sig_size > INT_MAX || sig_size == 0) {
		return FALSE;
	}

	ctx = ec_context;
	switch (ctx->grp.id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		half_size = 32;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		half_size = 48;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		half_size = 66;
		break;
	default:
		return FALSE;
	}
	if (sig_size != (uintn)(half_size * 2)) {
		return FALSE;
	}

	switch (hash_nid) {
	case CRYPTO_NID_SHA256:
		if (hash_size != SHA256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA384:
		if (hash_size != SHA384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA512:
		if (hash_size != SHA512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	mbedtls_mpi_init(&bn_r);
	mbedtls_mpi_init(&bn_s);

	ret = mbedtls_mpi_read_binary(&bn_r, signature, half_size);
	if (ret != 0) {
		mbedtls_mpi_free(&bn_r);
		mbedtls_mpi_free(&bn_s);
		return FALSE;
	}
	ret = mbedtls_mpi_read_binary(&bn_s, signature + half_size, half_size);
	if (ret != 0) {
		mbedtls_mpi_free(&bn_r);
		mbedtls_mpi_free(&bn_s);
		return FALSE;
	}

	ret = mbedtls_ecdsa_verify(&ctx->grp, message_hash, hash_size, &ctx->Q,
				   &bn_r, &bn_s);
	mbedtls_mpi_free(&bn_r);
	mbedtls_mpi_free(&bn_s);

	if (ret != 0) {
		return FALSE;
	}

	return TRUE;
}
