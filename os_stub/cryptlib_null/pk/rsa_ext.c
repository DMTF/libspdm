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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
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
	ASSERT(FALSE);
	return FALSE;
}
