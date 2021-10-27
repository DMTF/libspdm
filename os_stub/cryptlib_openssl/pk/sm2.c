/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Shang-Mi2 Asymmetric Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

/**
  Allocates and Initializes one Shang-Mi2 context for subsequent use.

  The key is generated before the function returns.

  @param nid cipher NID

  @return  Pointer to the Shang-Mi2 context that has been initialized.
           If the allocations fails, sm2_new_by_nid() returns NULL.

**/
void *sm2_new_by_nid(IN uintn nid)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY_CTX *key_ctx;
	EVP_PKEY *pkey;
	int32 result;
	EVP_PKEY *params;

	pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pkey_ctx == NULL) {
		return NULL;
	}
	result = EVP_PKEY_paramgen_init(pkey_ctx);
	if (result != 1) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}
	result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2);
	if (result == 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}

	params = NULL;
	result = EVP_PKEY_paramgen(pkey_ctx, &params);
	if (result == 0) {
		EVP_PKEY_CTX_free(pkey_ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(pkey_ctx);

	key_ctx = EVP_PKEY_CTX_new(params, NULL);
	if (key_ctx == NULL) {
		EVP_PKEY_free(params);
		return NULL;
	}
	EVP_PKEY_free(params);

	result = EVP_PKEY_keygen_init(key_ctx);
	if (result == 0) {
		EVP_PKEY_CTX_free(key_ctx);
		return NULL;
	}
	pkey = NULL;
	result = EVP_PKEY_keygen(key_ctx, &pkey);
	if (result == 0 || pkey == NULL) {
		EVP_PKEY_CTX_free(key_ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(key_ctx);

	result = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	if (result == 0) {
		EVP_PKEY_free(pkey);
		return NULL;
	}

	return (void *)pkey;
}

/**
  Release the specified sm2 context.

  @param[in]  sm2_context  Pointer to the sm2 context to be released.

**/
void sm2_free(IN void *sm2_context)
{
	EVP_PKEY_free((EVP_PKEY *)sm2_context);
}

/**
  Sets the public key component into the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  ec_context      Pointer to sm2 context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   sm2 public key component was set successfully.
  @retval  FALSE  Invalid sm2 public key component.

**/
boolean sm2_set_pub_key(IN OUT void *sm2_context, IN uint8 *public_key,
			IN uintn public_key_size)
{
	EVP_PKEY *pkey;
	EC_KEY *ec_key;
	const EC_GROUP *ec_group;
	boolean ret_val;
	BIGNUM *bn_x;
	BIGNUM *bn_y;
	EC_POINT *ec_point;
	int32 openssl_nid;
	uintn half_size;

	if (sm2_context == NULL || public_key == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)sm2_context;
	if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
		return FALSE;
	}
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_EC);
	ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

	openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
	switch (openssl_nid) {
	case NID_sm2:
		half_size = 32;
		break;
	default:
		return FALSE;
	}
	if (public_key_size != half_size * 2) {
		return FALSE;
	}

	ec_group = EC_KEY_get0_group(ec_key);
	ec_point = NULL;

	bn_x = BN_bin2bn(public_key, (uint32)half_size, NULL);
	bn_y = BN_bin2bn(public_key + half_size, (uint32)half_size, NULL);
	if (bn_x == NULL || bn_y == NULL) {
		ret_val = FALSE;
		goto done;
	}
	ec_point = EC_POINT_new(ec_group);
	if (ec_point == NULL) {
		ret_val = FALSE;
		goto done;
	}

	ret_val = (boolean)EC_POINT_set_affine_coordinates(ec_group, ec_point,
							   bn_x, bn_y, NULL);
	if (!ret_val) {
		goto done;
	}

	ret_val = (boolean)EC_KEY_set_public_key(ec_key, ec_point);
	if (!ret_val) {
		goto done;
	}

	ret_val = TRUE;

done:
	if (bn_x != NULL) {
		BN_free(bn_x);
	}
	if (bn_y != NULL) {
		BN_free(bn_y);
	}
	if (ec_point != NULL) {
		EC_POINT_free(ec_point);
	}
	return ret_val;
}

/**
  Gets the public key component from the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  sm2_context     Pointer to sm2 context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   sm2 key component was retrieved successfully.
  @retval  FALSE  Invalid sm2 key component.

**/
boolean sm2_get_pub_key(IN OUT void *sm2_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size)
{
	EVP_PKEY *pkey;
	EC_KEY *ec_key;
	const EC_GROUP *ec_group;
	boolean ret_val;
	const EC_POINT *ec_point;
	BIGNUM *bn_x;
	BIGNUM *bn_y;
	int32 openssl_nid;
	uintn half_size;
	intn x_size;
	intn y_size;

	if (sm2_context == NULL || public_key_size == NULL) {
		return FALSE;
	}

	if (public_key == NULL && *public_key_size != 0) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)sm2_context;
	if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
		return FALSE;
	}
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_EC);
	ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

	openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
	switch (openssl_nid) {
	case NID_sm2:
		half_size = 32;
		break;
	default:
		return FALSE;
	}
	if (*public_key_size < half_size * 2) {
		*public_key_size = half_size * 2;
		return FALSE;
	}
	*public_key_size = half_size * 2;

	ec_group = EC_KEY_get0_group(ec_key);
	ec_point = EC_KEY_get0_public_key(ec_key);
	if (ec_point == NULL) {
		return FALSE;
	}

	bn_x = BN_new();
	bn_y = BN_new();
	if (bn_x == NULL || bn_y == NULL) {
		ret_val = FALSE;
		goto done;
	}

	ret_val = (boolean)EC_POINT_get_affine_coordinates(ec_group, ec_point,
							   bn_x, bn_y, NULL);
	if (!ret_val) {
		goto done;
	}

	x_size = BN_num_bytes(bn_x);
	y_size = BN_num_bytes(bn_y);
	if (x_size <= 0 || y_size <= 0) {
		ret_val = FALSE;
		goto done;
	}
	ASSERT((uintn)x_size <= half_size && (uintn)y_size <= half_size);

	if (public_key != NULL) {
		zero_mem(public_key, *public_key_size);
		BN_bn2bin(bn_x, &public_key[0 + half_size - x_size]);
		BN_bn2bin(bn_y, &public_key[half_size + half_size - y_size]);
	}
	ret_val = TRUE;

done:
	if (bn_x != NULL) {
		BN_free(bn_x);
	}
	if (bn_y != NULL) {
		BN_free(bn_y);
	}
	return ret_val;
}

/**
  Validates key components of sm2 context.
  NOTE: This function performs integrity checks on all the sm2 key material, so
        the sm2 key structure must contain all the private key data.

  If sm2_context is NULL, then return FALSE.

  @param[in]  sm2_context  Pointer to sm2 context to check.

  @retval  TRUE   sm2 key components are valid.
  @retval  FALSE  sm2 key components are not valid.

**/
boolean sm2_check_key(IN void *sm2_context)
{
	EVP_PKEY *pkey;
	EC_KEY *ec_key;
	boolean ret_val;

	if (sm2_context == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)sm2_context;
	if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
		return FALSE;
	}
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_EC);
	ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

	ret_val = (boolean)EC_KEY_check_key(ec_key);
	if (!ret_val) {
		return FALSE;
	}

	return TRUE;
}

/**
  Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter public, public_size.
  X is the first half of public with size being public_size / 2,
  Y is the second half of public with size being public_size / 2.
  sm2 context is updated accordingly.
  If the public buffer is too small to hold the public X, Y, FALSE is returned and
  public_size is set to the required buffer size to obtain the public X, Y.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  If sm2_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  sm2_context     Pointer to the sm2 context.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   sm2 public X,Y generation succeeded.
  @retval FALSE  sm2 public X,Y generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean sm2_generate_key(IN OUT void *sm2_context, OUT uint8 *public,
			 IN OUT uintn *public_size)
{
	// current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.
	return FALSE;
}

/**
  Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of peer_public with size being peer_public_size / 2,
  Y is the second half of peer_public with size being peer_public_size / 2.

  If sm2_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.

  The id_a_size and id_b_size must be smaller than 2^16-1.
  The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
  The key_size must be smaller than 2^32-1, limited by KDF function.

  @param[in, out]  sm2_context         Pointer to the sm2 context.
  @param[in]       hash_nid            hash NID
  @param[in]       id_a                the ID-A of the key exchange context.
  @param[in]       id_a_size           size of ID-A key exchange context.
  @param[in]       id_b                the ID-B of the key exchange context.
  @param[in]       id_b_size           size of ID-B key exchange context.
  @param[in]       peer_public         Pointer to the peer's public X,Y.
  @param[in]       peer_public_size     size of peer's public X,Y in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in]       key_size            On input, the size of key buffer in bytes.

  @retval TRUE   sm2 exchanged key generation succeeded.
  @retval FALSE  sm2 exchanged key generation failed.

**/
boolean sm2_compute_key(IN OUT void *sm2_context, IN uintn hash_nid,
			IN const uint8 *id_a, IN uintn id_a_size,
			IN const uint8 *id_b, IN uintn id_b_size,
			IN const uint8 *peer_public,
			IN uintn peer_public_size, OUT uint8 *key,
			IN uintn key_size)
{
	// current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.
	return FALSE;
}

static void ecc_signature_der_to_bin(IN uint8 *der_signature,
				     IN uintn der_sig_size,
				     OUT uint8 *signature, IN uintn sig_size)
{
	uint8 der_r_size;
	uint8 der_s_size;
	uint8 *bn_r;
	uint8 *bn_s;
	uint8 r_size;
	uint8 s_size;
	uint8 half_size;

	half_size = (uint8)(sig_size / 2);

	ASSERT(der_signature[0] == 0x30);
	ASSERT((uintn)(der_signature[1] + 2) == der_sig_size);
	ASSERT(der_signature[2] == 0x02);
	der_r_size = der_signature[3];
	ASSERT(der_signature[4 + der_r_size] == 0x02);
	der_s_size = der_signature[5 + der_r_size];
	ASSERT(der_sig_size == (uintn)(der_r_size + der_s_size + 6));

	if (der_signature[4] != 0) {
		r_size = der_r_size;
		bn_r = &der_signature[4];
	} else {
		r_size = der_r_size - 1;
		bn_r = &der_signature[5];
	}
	if (der_signature[6 + der_r_size] != 0) {
		s_size = der_s_size;
		bn_s = &der_signature[6 + der_r_size];
	} else {
		s_size = der_s_size - 1;
		bn_s = &der_signature[7 + der_r_size];
	}
	ASSERT(r_size <= half_size && s_size <= half_size);
	zero_mem(signature, sig_size);
	copy_mem(&signature[0 + half_size - r_size], bn_r, r_size);
	copy_mem(&signature[half_size + half_size - s_size], bn_s, s_size);
}

static void ecc_signature_bin_to_der(IN uint8 *signature, IN uintn sig_size,
				     OUT uint8 *der_signature,
				     IN OUT uintn *der_sig_size_in_out)
{
	uintn der_sig_size;
	uint8 der_r_size;
	uint8 der_s_size;
	uint8 *bn_r;
	uint8 *bn_s;
	uint8 r_size;
	uint8 s_size;
	uint8 half_size;
	uint8 index;

	half_size = (uint8)(sig_size / 2);

	for (index = 0; index < half_size; index++) {
		if (signature[index] != 0) {
			break;
		}
	}
	r_size = (uint8)(half_size - index);
	bn_r = &signature[index];
	for (index = 0; index < half_size; index++) {
		if (signature[half_size + index] != 0) {
			break;
		}
	}
	s_size = (uint8)(half_size - index);
	bn_s = &signature[half_size + index];
	if (r_size == 0 || s_size == 0) {
		*der_sig_size_in_out = 0;
		return;
	}
	if (bn_r[0] < 0x80) {
		der_r_size = r_size;
	} else {
		der_r_size = r_size + 1;
	}
	if (bn_s[0] < 0x80) {
		der_s_size = s_size;
	} else {
		der_s_size = s_size + 1;
	}
	der_sig_size = der_r_size + der_s_size + 6;
	ASSERT(der_sig_size <= *der_sig_size_in_out);
	*der_sig_size_in_out = der_sig_size;
	zero_mem(der_signature, der_sig_size);
	der_signature[0] = 0x30;
	der_signature[1] = (uint8)(der_sig_size - 2);
	der_signature[2] = 0x02;
	der_signature[3] = der_r_size;
	if (bn_r[0] < 0x80) {
		copy_mem(&der_signature[4], bn_r, r_size);
	} else {
		copy_mem(&der_signature[5], bn_r, r_size);
	}
	der_signature[4 + der_r_size] = 0x02;
	der_signature[5 + der_r_size] = der_s_size;
	if (bn_s[0] < 0x80) {
		copy_mem(&der_signature[6 + der_r_size], bn_s, s_size);
	} else {
		copy_mem(&der_signature[7 + der_r_size], bn_s, s_size);
	}
}

/**
  Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.

  This function carries out the SM2 signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be SM3_256.
  If sig_size is large enough but signature is NULL, then return FALSE.

  The id_a_size must be smaller than 2^16-1.
  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]       sm2_context   Pointer to sm2 context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       id_a          the ID-A of the signing context.
  @param[in]       id_a_size     size of ID-A signing context.
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive SM2 signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in SM2.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean sm2_dsa_sign(IN void *sm2_context, IN uintn hash_nid,
		       IN const char *id_a, IN uintn id_a_size,
		       IN const uint8 *message, IN uintn size,
		       OUT uint8 *signature, IN OUT uintn *sig_size)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey;
	EVP_MD_CTX *ctx;
	uintn half_size;
	int32 result;
	uint8 der_signature[32 * 2 + 8];
	uintn der_sig_size;

	if (sm2_context == NULL || message == NULL) {
		return FALSE;
	}

	if (signature == NULL || sig_size == NULL) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)sm2_context;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_SM2:
		half_size = 32;
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
	case CRYPTO_NID_SM3_256:
		break;

	default:
		return FALSE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return FALSE;
	}
	pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pkey_ctx == NULL) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}
	result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
				      id_a_size);
	if (result <= 0) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

	result = EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	der_sig_size = sizeof(der_signature);
	result = EVP_DigestSign(ctx, der_signature, &der_sig_size, message,
				size);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_CTX_free(pkey_ctx);

	ecc_signature_der_to_bin(der_signature, der_sig_size, signature,
				 *sig_size);

	return TRUE;
}

/**
  Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be SM3_256.

  The id_a_size must be smaller than 2^16-1.
  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]  sm2_context   Pointer to SM2 context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  id_a          the ID-A of the signing context.
  @param[in]  id_a_size     size of ID-A signing context.
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to SM2 signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in SM2.
  @retval  FALSE  Invalid signature or invalid sm2 context.

**/
boolean sm2_dsa_verify(IN void *sm2_context, IN uintn hash_nid,
			 IN const uint8 *id_a, IN uintn id_a_size,
			 IN const uint8 *message, IN uintn size,
			 IN const uint8 *signature, IN uintn sig_size)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey;
	EVP_MD_CTX *ctx;
	uintn half_size;
	int32 result;
	uint8 der_signature[32 * 2 + 8];
	uintn der_sig_size;

	if (sm2_context == NULL || message == NULL || signature == NULL) {
		return FALSE;
	}

	if (sig_size > INT_MAX || sig_size == 0) {
		return FALSE;
	}

	pkey = (EVP_PKEY *)sm2_context;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_SM2:
		half_size = 32;
		break;
	default:
		return FALSE;
	}
	if (sig_size != (uintn)(half_size * 2)) {
		return FALSE;
	}

	switch (hash_nid) {
	case CRYPTO_NID_SM3_256:
		break;

	default:
		return FALSE;
	}

	der_sig_size = sizeof(der_signature);
	ecc_signature_bin_to_der((uint8 *)signature, sig_size, der_signature,
				 &der_sig_size);

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return FALSE;
	}
	pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pkey_ctx == NULL) {
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}
	result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
				      id_a_size);
	if (result <= 0) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

	result = EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}
	result = EVP_DigestVerify(ctx, der_signature, (uint32)der_sig_size,
				  message, size);
	if (result != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pkey_ctx);
		return FALSE;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_CTX_free(pkey_ctx);
	return TRUE;
}
