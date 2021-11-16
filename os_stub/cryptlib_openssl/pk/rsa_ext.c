/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  RSA Asymmetric Cipher Wrapper Implementation.

  This file implements following APIs which provide more capabilities for RSA:
  1) rsa_get_key
  2) rsa_generate_key
  3) rsa_check_key
  4) rsa_pkcs1_sign

  RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
**/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

/**
  Gets the tag-designated RSA key component from the established RSA context.

  This function retrieves the tag-designated RSA key component from the
  established RSA context as a non-negative integer (octet string format
  represented in RSA PKCS#1).
  If specified key component has not been set or has been cleared, then returned
  bn_size is set to 0.
  If the big_number buffer is too small to hold the contents of the key, FALSE
  is returned and bn_size is set to the required buffer size to obtain the key.

  If rsa_context is NULL, then return FALSE.
  If bn_size is NULL, then return FALSE.
  If bn_size is large enough but big_number is NULL, then return FALSE.

  @param[in, out]  rsa_context  Pointer to RSA context being set.
  @param[in]       key_tag      tag of RSA key component being set.
  @param[out]      big_number   Pointer to octet integer buffer.
  @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
                               On output, the size of data returned in big number buffer in bytes.

  @retval  TRUE   RSA key component was retrieved successfully.
  @retval  FALSE  Invalid RSA key component tag.
  @retval  FALSE  bn_size is too small.

**/
boolean rsa_get_key(IN OUT void *rsa_context, IN rsa_key_tag_t key_tag,
		    OUT uint8_t *big_number, IN OUT uintn *bn_size)
{
	RSA *rsa_key;
	BIGNUM *bn_key;
	uintn size;

	//
	// Check input parameters.
	//
	if (rsa_context == NULL || bn_size == NULL) {
		return FALSE;
	}

	rsa_key = (RSA *)rsa_context;
	size = *bn_size;
	*bn_size = 0;
	bn_key = NULL;

	switch (key_tag) {
	//
	// RSA public Modulus (N)
	//
	case RSA_KEY_N:
		RSA_get0_key(rsa_key, (const BIGNUM **)&bn_key, NULL, NULL);
		break;

	//
	// RSA public Exponent (e)
	//
	case RSA_KEY_E:
		RSA_get0_key(rsa_key, NULL, (const BIGNUM **)&bn_key, NULL);
		break;

	//
	// RSA Private Exponent (d)
	//
	case RSA_KEY_D:
		RSA_get0_key(rsa_key, NULL, NULL, (const BIGNUM **)&bn_key);
		break;

	//
	// RSA Secret prime Factor of Modulus (p)
	//
	case RSA_KEY_P:
		RSA_get0_factors(rsa_key, (const BIGNUM **)&bn_key, NULL);
		break;

	//
	// RSA Secret prime Factor of Modules (q)
	//
	case RSA_KEY_Q:
		RSA_get0_factors(rsa_key, NULL, (const BIGNUM **)&bn_key);
		break;

	//
	// p's CRT Exponent (== d mod (p - 1))
	//
	case RSA_KEY_DP:
		RSA_get0_crt_params(rsa_key, (const BIGNUM **)&bn_key, NULL,
				    NULL);
		break;

	//
	// q's CRT Exponent (== d mod (q - 1))
	//
	case RSA_KEY_DQ:
		RSA_get0_crt_params(rsa_key, NULL, (const BIGNUM **)&bn_key,
				    NULL);
		break;

	//
	// The CRT Coefficient (== 1/q mod p)
	//
	case RSA_KEY_Q_INV:
		RSA_get0_crt_params(rsa_key, NULL, NULL,
				    (const BIGNUM **)&bn_key);
		break;

	default:
		return FALSE;
	}

	if (bn_key == NULL) {
		return FALSE;
	}

	*bn_size = size;
	size = BN_num_bytes(bn_key);

	if (*bn_size < size) {
		*bn_size = size;
		return FALSE;
	}

	if (big_number == NULL) {
		*bn_size = size;
		return TRUE;
	}
	*bn_size = BN_bn2bin(bn_key, big_number);

	return TRUE;
}

/**
  Generates RSA key components.

  This function generates RSA key components. It takes RSA public exponent E and
  length in bits of RSA modulus N as input, and generates all key components.
  If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by random_seed().

  If rsa_context is NULL, then return FALSE.

  @param[in, out]  rsa_context           Pointer to RSA context being set.
  @param[in]       modulus_length        length of RSA modulus N in bits.
  @param[in]       public_exponent       Pointer to RSA public exponent.
  @param[in]       public_exponent_size   size of RSA public exponent buffer in bytes.

  @retval  TRUE   RSA key component was generated successfully.
  @retval  FALSE  Invalid RSA key component tag.

**/
boolean rsa_generate_key(IN OUT void *rsa_context, IN uintn modulus_length,
			 IN const uint8_t *public_exponent,
			 IN uintn public_exponent_size)
{
	BIGNUM *bn_e;
	boolean ret_val;

	//
	// Check input parameters.
	//
	if (rsa_context == NULL || modulus_length > INT_MAX ||
	    public_exponent_size > INT_MAX) {
		return FALSE;
	}

	bn_e = BN_new();
	if (bn_e == NULL) {
		return FALSE;
	}

	ret_val = FALSE;

	if (public_exponent == NULL) {
		if (BN_set_word(bn_e, 0x10001) == 0) {
			goto done;
		}
	} else {
		if (BN_bin2bn(public_exponent, (uint32_t)public_exponent_size,
			      bn_e) == NULL) {
			goto done;
		}
	}

	if (RSA_generate_key_ex((RSA *)rsa_context, (uint32_t)modulus_length,
				bn_e, NULL) == 1) {
		ret_val = TRUE;
	}

done:
	BN_free(bn_e);
	return ret_val;
}

/**
  Validates key components of RSA context.
  NOTE: This function performs integrity checks on all the RSA key material, so
        the RSA key structure must contain all the private key data.

  This function validates key components of RSA context in following aspects:
  - Whether p is a prime
  - Whether q is a prime
  - Whether n = p * q
  - Whether d*e = 1  mod lcm(p-1,q-1)

  If rsa_context is NULL, then return FALSE.

  @param[in]  rsa_context  Pointer to RSA context to check.

  @retval  TRUE   RSA key components are valid.
  @retval  FALSE  RSA key components are not valid.

**/
boolean rsa_check_key(IN void *rsa_context)
{
	uintn reason;

	//
	// Check input parameters.
	//
	if (rsa_context == NULL) {
		return FALSE;
	}

	if (RSA_check_key((RSA *)rsa_context) != 1) {
		reason = ERR_GET_REASON(ERR_peek_last_error());
		if (reason == RSA_R_P_NOT_PRIME ||
		    reason == RSA_R_Q_NOT_PRIME ||
		    reason == RSA_R_N_DOES_NOT_EQUAL_P_Q ||
		    reason == RSA_R_D_E_NOT_CONGRUENT_TO_1) {
			return FALSE;
		}
	}

	return TRUE;
}

/**
  Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      rsa_context   Pointer to RSA context for signature generation.
  @param[in]      hash_nid      hash NID
  @param[in]      message_hash  Pointer to octet message hash to be signed.
  @param[in]      hash_size     size of the message hash in bytes.
  @param[out]     signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
  @param[in, out] sig_size      On input, the size of signature buffer in bytes.
                               On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in PKCS1-v1_5.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_pkcs1_sign_with_nid(IN void *rsa_context, IN uintn hash_nid,
				IN const uint8_t *message_hash,
				IN uintn hash_size, OUT uint8_t *signature,
				IN OUT uintn *sig_size)
{
	RSA *rsa;
	uintn size;
	int32_t digest_type;

	//
	// Check input parameters.
	//
	if (rsa_context == NULL || message_hash == NULL) {
		return FALSE;
	}

	rsa = (RSA *)rsa_context;
	size = RSA_size(rsa);

	if (*sig_size < size) {
		*sig_size = size;
		return FALSE;
	}

	if (signature == NULL) {
		return FALSE;
	}

	switch (hash_nid) {
	case CRYPTO_NID_SHA256:
		digest_type = NID_sha256;
		if (hash_size != SHA256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA384:
		digest_type = NID_sha384;
		if (hash_size != SHA384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA512:
		digest_type = NID_sha512;
		if (hash_size != SHA512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_256:
		digest_type = NID_sha3_256;
		if (hash_size != SHA3_256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_384:
		digest_type = NID_sha3_384;
		if (hash_size != SHA3_384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_512:
		digest_type = NID_sha3_512;
		if (hash_size != SHA3_512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	return (boolean)RSA_sign(digest_type, message_hash, (uint32_t)hash_size,
				 signature, (uint32_t *)sig_size,
				 (RSA *)rsa_context);
}

/**
  Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
  RSA PKCS#1 v2.2.

  The salt length is same as digest length.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.

  @param[in]       rsa_context   Pointer to RSA context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message_hash  Pointer to octet message hash to be signed.
  @param[in]       hash_size     size of the message hash in bytes.
  @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in RSA-SSA PSS.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean rsa_pss_sign(IN void *rsa_context, IN uintn hash_nid,
		     IN const uint8_t *message_hash, IN uintn hash_size,
		     OUT uint8_t *signature, IN OUT uintn *sig_size)
{
	RSA *rsa;
	boolean result;
	int32_t size;
	const EVP_MD *evp_md;
	void *buffer;

	if (rsa_context == NULL || message_hash == NULL) {
		return FALSE;
	}

	rsa = (RSA *)rsa_context;
	size = RSA_size(rsa);

	if (*sig_size < (uintn)size) {
		*sig_size = size;
		return FALSE;
	}
	*sig_size = size;

	switch (hash_nid) {
	case CRYPTO_NID_SHA256:
		evp_md = EVP_sha256();
		if (hash_size != SHA256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA384:
		evp_md = EVP_sha384();
		if (hash_size != SHA384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA512:
		evp_md = EVP_sha512();
		if (hash_size != SHA512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_256:
		evp_md = EVP_sha3_256();
		if (hash_size != SHA3_256_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_384:
		evp_md = EVP_sha3_384();
		if (hash_size != SHA3_384_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	case CRYPTO_NID_SHA3_512:
		evp_md = EVP_sha3_512();
		if (hash_size != SHA3_512_DIGEST_SIZE) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	buffer = allocate_pool(size);
	if (buffer == NULL) {
		return FALSE;
	}

	result = (boolean)RSA_padding_add_PKCS1_PSS(
		rsa, buffer, message_hash, evp_md, RSA_PSS_SALTLEN_DIGEST);
	if (!result) {
		free_pool(buffer);
		return FALSE;
	}

	size = RSA_private_encrypt(size, buffer, signature, rsa,
				   RSA_NO_PADDING);
	free_pool(buffer);
	if (size <= 0) {
		return FALSE;
	} else {
		ASSERT(*sig_size == (uintn)size);
		return TRUE;
	}
}
