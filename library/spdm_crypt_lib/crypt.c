/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <library/spdm_crypt_lib.h>

/**
  This function returns the SPDM hash algorithm size.

  @param  base_hash_algo                  SPDM base_hash_algo

  @return SPDM hash algorithm size.
**/
uint32 spdm_get_hash_size(IN uint32 base_hash_algo)
{
	switch (base_hash_algo) {
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
		return 32;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
		return 48;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
		return 64;
	}
	return 0;
}

/**
  Return cipher ID, based upon the negotiated hash algorithm.

  @param  base_hash_algo                  SPDM base_hash_algo

  @return hash cipher ID
**/
uintn get_spdm_hash_nid(IN uint32 base_hash_algo)
{
	switch (base_hash_algo) {
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
		return CRYPTO_NID_SHA256;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
		return CRYPTO_NID_SHA384;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
		return CRYPTO_NID_SHA512;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
		return CRYPTO_NID_SHA3_256;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
		return CRYPTO_NID_SHA3_384;
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
		return CRYPTO_NID_SHA3_512;
	}
	return CRYPTO_NID_NULL;
}

/**
  Return hash function, based upon the negotiated hash algorithm.

  @param  base_hash_algo                  SPDM base_hash_algo

  @return hash function
**/
hash_all_func get_spdm_hash_func(IN uint32 base_hash_algo)
{
	switch (base_hash_algo) {
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
		return sha256_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
		return sha384_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
		return sha512_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
		ASSERT(FALSE);
		break;
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  data                         Pointer to the buffer containing the data to be hashed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the hash value.

  @retval TRUE   hash computation succeeded.
  @retval FALSE  hash computation failed.
**/
boolean spdm_hash_all(IN uint32 base_hash_algo, IN const void *data,
		      IN uintn data_size, OUT uint8 *hash_value)
{
	hash_all_func hash_function;
	hash_function = get_spdm_hash_func(base_hash_algo);
	if (hash_function == NULL) {
		return FALSE;
	}
	return hash_function(data, data_size, hash_value);
}

/**
  This function returns the SPDM measurement hash algorithm size.

  @param  measurement_hash_algo          SPDM measurement_hash_algo

  @return SPDM measurement hash algorithm size.
  @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
**/
uint32 spdm_get_measurement_hash_size(IN uint32 measurement_hash_algo)
{
	switch (measurement_hash_algo) {
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
		return 32;
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
		return 48;
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
		return 64;
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY:
		return 0xFFFFFFFF;
	}
	return 0;
}

/**
  Return hash function, based upon the negotiated measurement hash algorithm.

  @param  measurement_hash_algo          SPDM measurement_hash_algo

  @return hash function
**/
hash_all_func get_spdm_measurement_hash_func(IN uint32 measurement_hash_algo)
{
	switch (measurement_hash_algo) {
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
		return sha256_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
		return sha384_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
		return sha512_hash_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
	case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
		ASSERT(FALSE);
		break;
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  measurement_hash_algo          SPDM measurement_hash_algo
  @param  data                         Pointer to the buffer containing the data to be hashed.
  @param  data_size                     size of data buffer in bytes.
  @param  hash_value                    Pointer to a buffer that receives the hash value.

  @retval TRUE   hash computation succeeded.
  @retval FALSE  hash computation failed.
**/
boolean spdm_measurement_hash_all(IN uint32 measurement_hash_algo,
				  IN const void *data, IN uintn data_size,
				  OUT uint8 *hash_value)
{
	hash_all_func hash_function;
	hash_function = get_spdm_measurement_hash_func(measurement_hash_algo);
	if (hash_function == NULL) {
		return FALSE;
	}
	return hash_function(data, data_size, hash_value);
}

/**
  Return HMAC function, based upon the negotiated HMAC algorithm.

  @param  base_hash_algo                 SPDM base_hash_algo

  @return HMAC function
**/
hmac_all_func get_spdm_hmac_func(IN uint32 base_hash_algo)
{
	switch (base_hash_algo) {
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
		return hmac_sha256_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
		return hmac_sha384_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
		return hmac_sha512_all;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
		ASSERT(FALSE);
		break;
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  data                         Pointer to the buffer containing the data to be HMACed.
  @param  data_size                     size of data buffer in bytes.
  @param  key                          Pointer to the user-supplied key.
  @param  key_size                      key size in bytes.
  @param  hash_value                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
boolean spdm_hmac_all(IN uint32 base_hash_algo, IN const void *data,
		      IN uintn data_size, IN const uint8 *key,
		      IN uintn key_size, OUT uint8 *hmac_value)
{
	hmac_all_func hmac_function;
	hmac_function = get_spdm_hmac_func(base_hash_algo);
	if (hmac_function == NULL) {
		return FALSE;
	}
	return hmac_function(data, data_size, key, key_size, hmac_value);
}

/**
  Return HKDF expand function, based upon the negotiated HKDF algorithm.

  @param  base_hash_algo                 SPDM base_hash_algo

  @return HKDF expand function
**/
hkdf_expand_func get_spdm_hkdf_expand_func(IN uint32 base_hash_algo)
{
	switch (base_hash_algo) {
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
		return hkdf_sha256_expand;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
		return hkdf_sha384_expand;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
		return hkdf_sha512_expand;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
	case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
		ASSERT(FALSE);
		break;
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  prk                          Pointer to the user-supplied key.
  @param  prk_size                      key size in bytes.
  @param  info                         Pointer to the application specific info.
  @param  info_size                     info size in bytes.
  @param  out                          Pointer to buffer to receive hkdf value.
  @param  out_size                      size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
boolean spdm_hkdf_expand(IN uint32 base_hash_algo, IN const uint8 *prk,
			 IN uintn prk_size, IN const uint8 *info,
			 IN uintn info_size, OUT uint8 *out, IN uintn out_size)
{
	hkdf_expand_func hkdf_expand_function;
	hkdf_expand_function = get_spdm_hkdf_expand_func(base_hash_algo);
	if (hkdf_expand_function == NULL) {
		return FALSE;
	}
	return hkdf_expand_function(prk, prk_size, info, info_size, out,
				    out_size);
}

/**
  This function returns the SPDM asymmetric algorithm size.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return SPDM asymmetric algorithm size.
**/
uint32 spdm_get_asym_signature_size(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
		return 256;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
		return 384;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
		return 512;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		return 32 * 2;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		return 48 * 2;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
		return 66 * 2;
	}
	return 0;
}

/**
  Return asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
asym_get_public_key_from_x509_func
get_spdm_asym_get_public_key_from_x509(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
		return rsa_get_public_key_from_x509;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
		return ec_get_public_key_from_x509;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
boolean spdm_asym_get_public_key_from_x509(IN uint32 base_asym_algo,
					   IN const uint8 *cert,
					   IN uintn cert_size,
					   OUT void **context)
{
	asym_get_public_key_from_x509_func get_public_key_from_x509_function;
	get_public_key_from_x509_function =
		get_spdm_asym_get_public_key_from_x509(base_asym_algo);
	if (get_public_key_from_x509_function == NULL) {
		return FALSE;
	}
	return get_public_key_from_x509_function(cert, cert_size, context);
}

/**
  Return asymmetric free function, based upon the negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return asymmetric free function
**/
asym_free_func get_spdm_asym_free(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
		return rsa_free;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
		return ec_free;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  context                      Pointer to the asymmetric context to be released.
**/
void spdm_asym_free(IN uint32 base_asym_algo, IN void *context)
{
	asym_free_func free_function;
	free_function = get_spdm_asym_free(base_asym_algo);
	if (free_function == NULL) {
		return;
	}
	free_function(context);
}

/**
  Return if asymmetric function need message hash.

  @param  base_asym_algo               SPDM base_asym_algo

  @retval TRUE  asymmetric function need message hash
  @retval FALSE asymmetric function need raw message
**/
boolean spdm_asym_func_need_hash(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
		return TRUE;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
		return TRUE;
	}
	ASSERT(FALSE);
	return FALSE;
}

/**
  Return asymmetric verify function, based upon the negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return asymmetric verify function
**/
asym_verify_func get_spdm_asym_verify(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
		return rsa_pkcs1_verify_with_nid;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if OPENSPDM_RSA_PSS_SUPPORT == 1
		return rsa_pss_verify;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
		return ecdsa_verify;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature verification.
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to asymmetric signature to be verified.
  @param  sig_size                      size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
boolean spdm_asym_verify(IN uint32 base_asym_algo, IN uint32 base_hash_algo,
			 IN void *context, IN const uint8 *message,
			 IN uintn message_size, IN const uint8 *signature,
			 IN uintn sig_size)
{
	asym_verify_func verify_function;
	boolean need_hash;
	uint8 message_hash[MAX_HASH_SIZE];
	uintn hash_size;
	boolean result;
	uintn hash_nid;

	hash_nid = get_spdm_hash_nid(base_hash_algo);
	need_hash = spdm_asym_func_need_hash(base_asym_algo);

	verify_function = get_spdm_asym_verify(base_asym_algo);
	if (verify_function == NULL) {
		return FALSE;
	}
	if (need_hash) {
		hash_size = spdm_get_hash_size(base_hash_algo);
		result = spdm_hash_all(base_hash_algo, message, message_size,
				       message_hash);
		if (!result) {
			return FALSE;
		}
		return verify_function(context, hash_nid, message_hash,
				       hash_size, signature, sig_size);
	} else {
		return verify_function(context, hash_nid, message, message_size,
				       signature, sig_size);
	}
}

/**
  Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
**/
asym_get_private_key_from_pem_func
get_spdm_asym_get_private_key_from_pem(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
		return rsa_get_private_key_from_pem;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
		return ec_get_private_key_from_pem;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
boolean spdm_asym_get_private_key_from_pem(IN uint32 base_asym_algo,
					   IN const uint8 *pem_data,
					   IN uintn pem_size,
					   IN const char8 *password,
					   OUT void **context)
{
	asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
	asym_get_private_key_from_pem =
		get_spdm_asym_get_private_key_from_pem(base_asym_algo);
	if (asym_get_private_key_from_pem == NULL) {
		return FALSE;
	}
	return asym_get_private_key_from_pem(pem_data, pem_size, password,
					     context);
}

/**
  Return asymmetric sign function, based upon the asymmetric algorithm.

  @param  base_asym_algo                 SPDM base_asym_algo

  @return asymmetric sign function
**/
asym_sign_func get_spdm_asym_sign(IN uint32 base_asym_algo)
{
	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
		return rsa_pkcs1_sign_with_nid;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if OPENSPDM_RSA_PSS_SUPPORT == 1
		return rsa_pss_sign;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
		return ecdsa_sign;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  base_asym_algo                 SPDM base_asym_algo
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature generation.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean spdm_asym_sign(IN uint32 base_asym_algo, IN uint32 base_hash_algo,
		       IN void *context, IN const uint8 *message,
		       IN uintn message_size, OUT uint8 *signature,
		       IN OUT uintn *sig_size)
{
	asym_sign_func asym_sign;
	boolean need_hash;
	uint8 message_hash[MAX_HASH_SIZE];
	uintn hash_size;
	boolean result;
	uintn hash_nid;

	hash_nid = get_spdm_hash_nid(base_hash_algo);
	need_hash = spdm_asym_func_need_hash(base_asym_algo);

	asym_sign = get_spdm_asym_sign(base_asym_algo);
	if (asym_sign == NULL) {
		return FALSE;
	}
	if (need_hash) {
		hash_size = spdm_get_hash_size(base_hash_algo);
		result = spdm_hash_all(base_hash_algo, message, message_size,
				       message_hash);
		if (!result) {
			return FALSE;
		}
		return asym_sign(context, hash_nid, message_hash, hash_size,
				 signature, sig_size);
	} else {
		return asym_sign(context, hash_nid, message, message_size,
				 signature, sig_size);
	}
}

/**
  This function returns the SPDM requester asymmetric algorithm size.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return SPDM requester asymmetric algorithm size.
**/
uint32 spdm_get_req_asym_signature_size(IN uint16 req_base_asym_alg)
{
	return spdm_get_asym_signature_size(req_base_asym_alg);
}

/**
  Return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
asym_get_public_key_from_x509_func
get_spdm_req_asym_get_public_key_from_x509(IN uint16 req_base_asym_alg)
{
	return get_spdm_asym_get_public_key_from_x509(req_base_asym_alg);
}

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
boolean spdm_req_asym_get_public_key_from_x509(IN uint16 req_base_asym_alg,
					       IN const uint8 *cert,
					       IN uintn cert_size,
					       OUT void **context)
{
	asym_get_public_key_from_x509_func get_public_key_from_x509_function;
	get_public_key_from_x509_function =
		get_spdm_req_asym_get_public_key_from_x509(req_base_asym_alg);
	if (get_public_key_from_x509_function == NULL) {
		return FALSE;
	}
	return get_public_key_from_x509_function(cert, cert_size, context);
}

/**
  Return requester asymmetric free function, based upon the negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return requester asymmetric free function
**/
asym_free_func get_spdm_req_asym_free(IN uint16 req_base_asym_alg)
{
	return get_spdm_asym_free(req_base_asym_alg);
}

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  context                      Pointer to the asymmetric context to be released.
**/
void spdm_req_asym_free(IN uint16 req_base_asym_alg, IN void *context)
{
	asym_free_func free_function;
	free_function = get_spdm_req_asym_free(req_base_asym_alg);
	if (free_function == NULL) {
		return;
	}
	free_function(context);
}

/**
  Return if requester asymmetric function need message hash.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @retval TRUE  requester asymmetric function need message hash
  @retval FALSE requester asymmetric function need raw message
**/
boolean spdm_req_asym_func_need_hash(IN uint16 req_base_asym_alg)
{
	return spdm_asym_func_need_hash(req_base_asym_alg);
}

/**
  Return requester asymmetric verify function, based upon the negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return requester asymmetric verify function
**/
asym_verify_func get_spdm_req_asym_verify(IN uint16 req_base_asym_alg)
{
	return get_spdm_asym_verify(req_base_asym_alg);
}

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature verification.
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to asymmetric signature to be verified.
  @param  sig_size                      size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
boolean spdm_req_asym_verify(IN uint16 req_base_asym_alg,
			     IN uint32 base_hash_algo, IN void *context,
			     IN const uint8 *message, IN uintn message_size,
			     IN const uint8 *signature, IN uintn sig_size)
{
	asym_verify_func verify_function;
	boolean need_hash;
	uint8 message_hash[MAX_HASH_SIZE];
	uintn hash_size;
	boolean result;
	uintn hash_nid;

	hash_nid = get_spdm_hash_nid(base_hash_algo);
	need_hash = spdm_req_asym_func_need_hash(req_base_asym_alg);

	verify_function = get_spdm_req_asym_verify(req_base_asym_alg);
	if (verify_function == NULL) {
		return FALSE;
	}
	if (need_hash) {
		hash_size = spdm_get_hash_size(base_hash_algo);
		result = spdm_hash_all(base_hash_algo, message, message_size,
				       message_hash);
		if (!result) {
			return FALSE;
		}
		return verify_function(context, hash_nid, message_hash,
				       hash_size, signature, sig_size);
	} else {
		return verify_function(context, hash_nid, message, message_size,
				       signature, sig_size);
	}
}

/**
  Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
**/
asym_get_private_key_from_pem_func
get_spdm_req_asym_get_private_key_from_pem(IN uint16 req_base_asym_alg)
{
	return get_spdm_asym_get_private_key_from_pem(req_base_asym_alg);
}

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
boolean spdm_req_asym_get_private_key_from_pem(IN uint16 req_base_asym_alg,
					       IN const uint8 *pem_data,
					       IN uintn pem_size,
					       IN const char8 *password,
					       OUT void **context)
{
	asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
	asym_get_private_key_from_pem =
		get_spdm_req_asym_get_private_key_from_pem(req_base_asym_alg);
	if (asym_get_private_key_from_pem == NULL) {
		return FALSE;
	}
	return asym_get_private_key_from_pem(pem_data, pem_size, password,
					     context);
}

/**
  Return asymmetric sign function, based upon the asymmetric algorithm.

  @param  req_base_asym_alg               SPDM req_base_asym_alg

  @return asymmetric sign function
**/
asym_sign_func get_spdm_req_asym_sign(IN uint16 req_base_asym_alg)
{
	return get_spdm_asym_sign(req_base_asym_alg);
}

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  req_base_asym_alg               SPDM req_base_asym_alg
  @param  base_hash_algo                 SPDM base_hash_algo
  @param  context                      Pointer to asymmetric context for signature generation.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean spdm_req_asym_sign(IN uint16 req_base_asym_alg,
			   IN uint32 base_hash_algo, IN void *context,
			   IN const uint8 *message, IN uintn message_size,
			   OUT uint8 *signature, IN OUT uintn *sig_size)
{
	asym_sign_func asym_sign;
	boolean need_hash;
	uint8 message_hash[MAX_HASH_SIZE];
	uintn hash_size;
	boolean result;
	uintn hash_nid;

	hash_nid = get_spdm_hash_nid(base_hash_algo);
	need_hash = spdm_req_asym_func_need_hash(req_base_asym_alg);

	asym_sign = get_spdm_req_asym_sign(req_base_asym_alg);
	if (asym_sign == NULL) {
		return FALSE;
	}
	if (need_hash) {
		hash_size = spdm_get_hash_size(base_hash_algo);
		result = spdm_hash_all(base_hash_algo, message, message_size,
				       message_hash);
		if (!result) {
			return FALSE;
		}
		return asym_sign(context, hash_nid, message_hash, hash_size,
				 signature, sig_size);
	} else {
		return asym_sign(context, hash_nid, message, message_size,
				 signature, sig_size);
	}
}

/**
  This function returns the SPDM DHE algorithm key size.

  @param  dhe_named_group                SPDM dhe_named_group

  @return SPDM DHE algorithm key size.
**/
uint32 spdm_get_dhe_pub_key_size(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
		return 256;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
		return 384;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
		return 512;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
		return 32 * 2;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
		return 48 * 2;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
		return 66 * 2;
	}
	return 0;
}

/**
  Return cipher ID, based upon the negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return DHE cipher ID
**/
uintn get_spdm_dhe_nid(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
		return CRYPTO_NID_FFDHE2048;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
		return CRYPTO_NID_FFDHE3072;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
		return CRYPTO_NID_FFDHE4096;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
		return CRYPTO_NID_SECP256R1;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
		return CRYPTO_NID_SECP384R1;
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
		return CRYPTO_NID_SECP521R1;
	}
	return CRYPTO_NID_NULL;
}

/**
  Return DHE new by NID function, based upon the negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return DHE new by NID function
**/
dhe_new_by_nid_func get_spdm_dhe_new(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
		return dh_new_by_nid;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
		return ec_new_by_nid;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
void *spdm_dhe_new(IN uint16 dhe_named_group)
{
	dhe_new_by_nid_func new_function;
	uintn nid;

	new_function = get_spdm_dhe_new(dhe_named_group);
	if (new_function == NULL) {
		return NULL;
	}
	nid = get_spdm_dhe_nid(dhe_named_group);
	if (nid == 0) {
		return NULL;
	}
	return new_function(nid);
}

/**
  Return DHE free function, based upon the negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return DHE free function
**/
dhe_free_func get_spdm_dhe_free(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
		return dh_free;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
		return ec_free;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context to be released.
**/
void spdm_dhe_free(IN uint16 dhe_named_group, IN void *context)
{
	dhe_free_func free_function;
	free_function = get_spdm_dhe_free(dhe_named_group);
	if (free_function == NULL) {
		return;
	}
	free_function(context);
}

/**
  Return DHE generate key function, based upon the negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return DHE generate key function
**/
dhe_generate_key_func get_spdm_dhe_generate_key(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
		return dh_generate_key;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
		return ec_generate_key;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  public_key_size is not large enough.
**/
boolean spdm_dhe_generate_key(IN uint16 dhe_named_group, IN OUT void *context,
			      OUT uint8 *public_key,
			      IN OUT uintn *public_key_size)
{
	dhe_generate_key_func generate_key_function;
	generate_key_function = get_spdm_dhe_generate_key(dhe_named_group);
	if (generate_key_function == NULL) {
		return FALSE;
	}
	return generate_key_function(context, public_key, public_key_size);
}

/**
  Return DHE compute key function, based upon the negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group

  @return DHE compute key function
**/
dhe_compute_key_func get_spdm_dhe_compute_key(IN uint16 dhe_named_group)
{
	switch (dhe_named_group) {
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
		return dh_compute_key;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
	case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
		return ec_compute_key;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  context                      Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  key                          Pointer to the buffer to receive generated key.
  @param  key_size                      On input, the size of key buffer in bytes.
                                       On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
boolean spdm_dhe_compute_key(IN uint16 dhe_named_group, IN OUT void *context,
			     IN const uint8 *peer_public,
			     IN uintn peer_public_size, OUT uint8 *key,
			     IN OUT uintn *key_size)
{
	dhe_compute_key_func compute_key_function;
	compute_key_function = get_spdm_dhe_compute_key(dhe_named_group);
	if (compute_key_function == NULL) {
		return FALSE;
	}
	return compute_key_function(context, peer_public, peer_public_size, key,
				  key_size);
}

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm key size.
**/
uint32 spdm_get_aead_key_size(IN uint16 aead_cipher_suite)
{
	switch (aead_cipher_suite) {
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
		return 16;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
		return 32;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
		return 32;
	}
	return 0;
}

/**
  This function returns the SPDM AEAD algorithm iv size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm iv size.
**/
uint32 spdm_get_aead_iv_size(IN uint16 aead_cipher_suite)
{
	switch (aead_cipher_suite) {
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
		return 12;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
		return 12;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
		return 12;
	}
	return 0;
}

/**
  This function returns the SPDM AEAD algorithm tag size.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return SPDM AEAD algorithm tag size.
**/
uint32 spdm_get_aead_tag_size(IN uint16 aead_cipher_suite)
{
	switch (aead_cipher_suite) {
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
		return 16;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
		return 16;
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
		return 16;
	}
	return 0;
}

/**
  Return AEAD encryption function, based upon the negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return AEAD encryption function
**/
aead_encrypt_func get_spdm_aead_enc_func(IN uint16 aead_cipher_suite)
{
	switch (aead_cipher_suite) {
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
		return aead_aes_gcm_encrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
		return aead_aes_gcm_encrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
		return aead_chacha20_poly1305_encrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite
  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be encrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the encryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
boolean spdm_aead_encryption(IN uint16 aead_cipher_suite, IN const uint8 *key,
			     IN uintn key_size, IN const uint8 *iv,
			     IN uintn iv_size, IN const uint8 *a_data,
			     IN uintn a_data_size, IN const uint8 *data_in,
			     IN uintn data_in_size, OUT uint8 *tag_out,
			     IN uintn tag_size, OUT uint8 *data_out,
			     OUT uintn *data_out_size)
{
	aead_encrypt_func aead_enc_function;
	aead_enc_function = get_spdm_aead_enc_func(aead_cipher_suite);
	if (aead_enc_function == NULL) {
		return FALSE;
	}
	return aead_enc_function(key, key_size, iv, iv_size, a_data,
				 a_data_size, data_in, data_in_size, tag_out,
				 tag_size, data_out, data_out_size);
}

/**
  Return AEAD decryption function, based upon the negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite

  @return AEAD decryption function
**/
aead_decrypt_func get_spdm_aead_dec_func(IN uint16 aead_cipher_suite)
{
	switch (aead_cipher_suite) {
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
		return aead_aes_gcm_decrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
		return aead_aes_gcm_decrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
		return aead_chacha20_poly1305_decrypt;
#else
		ASSERT(FALSE);
		break;
#endif
	}
	ASSERT(FALSE);
	return NULL;
}

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  aead_cipher_suite              SPDM aead_cipher_suite
  @param  key                          Pointer to the encryption key.
  @param  key_size                      size of the encryption key in bytes.
  @param  iv                           Pointer to the IV value.
  @param  iv_size                       size of the IV value in bytes.
  @param  a_data                        Pointer to the additional authenticated data (AAD).
  @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
  @param  data_in                       Pointer to the input data buffer to be decrypted.
  @param  data_in_size                   size of the input data buffer in bytes.
  @param  tag                          Pointer to a buffer that contains the authentication tag.
  @param  tag_size                      size of the authentication tag in bytes.
  @param  data_out                      Pointer to a buffer that receives the decryption output.
  @param  data_out_size                  size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
boolean spdm_aead_decryption(IN uint16 aead_cipher_suite, IN const uint8 *key,
			     IN uintn key_size, IN const uint8 *iv,
			     IN uintn iv_size, IN const uint8 *a_data,
			     IN uintn a_data_size, IN const uint8 *data_in,
			     IN uintn data_in_size, IN const uint8 *tag,
			     IN uintn tag_size, OUT uint8 *data_out,
			     OUT uintn *data_out_size)
{
	aead_decrypt_func aead_dec_function;
	aead_dec_function = get_spdm_aead_dec_func(aead_cipher_suite);
	if (aead_dec_function == NULL) {
		return FALSE;
	}
	return aead_dec_function(key, key_size, iv, iv_size, a_data,
				 a_data_size, data_in, data_in_size, tag,
				 tag_size, data_out, data_out_size);
}

/**
  Generates a random byte stream of the specified size.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  size                         size of random bytes to generate.
  @param  rand                         Pointer to buffer to receive random value.
**/
void spdm_get_random_number(IN uintn size, OUT uint8 *rand)
{
	random_bytes(rand, size);

	return;
}

/**
  Check the X509 DataTime is within a valid range.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  from                         notBefore Pointer to date_time object.
  @param  from_size                     notBefore date_time object size.
  @param  to                           notAfter Pointer to date_time object.
  @param  to_size                       notAfter date_time object size.

  @retval  TRUE   verification pass.
  @retval  FALSE  verification fail.
**/
static boolean internal_spdm_x509_date_time_check(IN uint8 *from,
						  IN uintn from_size,
						  IN uint8 *to,
						  IN uintn to_size)
{
	intn ret;
	return_status status;
	uint8 f0[64];
	uint8 t0[64];
	uintn f0_size;
	uintn t0_size;

	f0_size = 64;
	t0_size = 64;

	status = x509_set_date_time("19700101000000Z", f0, &f0_size);
	if (status != RETURN_SUCCESS) {
		return FALSE;
	}

	status = x509_set_date_time("99991231235959Z", t0, &t0_size);
	if (status != RETURN_SUCCESS) {
		return FALSE;
	}

	// from >= f0
	ret = x509_compare_date_time(from, f0);
	if (ret < 0) {
		return FALSE;
	}

	// to <= t0
	ret = x509_compare_date_time(t0, to);
	if (ret < 0) {
		return FALSE;
	}

	return TRUE;
}

/**
  Certificate Check for SPDM leaf cert.

  @param[in]  cert            Pointer to the DER-encoded certificate data.
  @param[in]  cert_size        The size of certificate data in bytes.

  @retval  TRUE   Success.
  @retval  FALSE  Certificate is not valid
**/
boolean spdm_x509_certificate_check(IN const uint8 *cert, IN uintn cert_size)
{
	uint8 end_cert_from[64];
	uintn end_cert_from_len;
	uint8 end_cert_to[64];
	uintn end_cert_to_len;
	uintn asn1_buffer_len;
	boolean status;
	uintn cert_version;
	return_status ret;
	uintn value;
	void *rsa_context;
	void *ec_context;

	if (cert == NULL || cert_size == 0) {
		return FALSE;
	}

	status = TRUE;
	rsa_context = NULL;
	ec_context = NULL;
	end_cert_from_len = 64;
	end_cert_to_len = 64;

	// 1. version
	cert_version = 0;
	ret = x509_get_version(cert, cert_size, &cert_version);
	if (RETURN_ERROR(ret)) {
		status = FALSE;
		goto cleanup;
	}
	if (cert_version != 2) {
		status = FALSE;
		goto cleanup;
	}

	// 2. serial_number
	asn1_buffer_len = 0;
	ret = x509_get_serial_number(cert, cert_size, NULL, &asn1_buffer_len);
	if (ret != RETURN_BUFFER_TOO_SMALL) {
		status = FALSE;
		goto cleanup;
	}

	// 3. SinatureAlgorithem
	value = 0;
	ret = x509_get_signature_algorithm(cert, cert_size, NULL, &value);
	if (ret != RETURN_BUFFER_TOO_SMALL || value == 0) {
		status = FALSE;
		goto cleanup;
	}

	// 4. Issuer
	asn1_buffer_len = 0;
	status = x509_get_issuer_name(cert, cert_size, NULL, &asn1_buffer_len);
	if (status && asn1_buffer_len == 0) {
		goto cleanup;
	}
	if (asn1_buffer_len <= 0) {
		status = FALSE;
		goto cleanup;
	}

	// 5. SubjectName
	asn1_buffer_len = 0;
	status = x509_get_subject_name(cert, cert_size, NULL, &asn1_buffer_len);
	if (status && asn1_buffer_len == 0) {
		goto cleanup;
	}
	if (asn1_buffer_len <= 0) {
		status = FALSE;
		goto cleanup;
	}

	// 6. Validaity
	status = x509_get_validity(cert, cert_size, end_cert_from,
				   &end_cert_from_len, end_cert_to,
				   &end_cert_to_len);
	if (!status) {
		goto cleanup;
	}

	status = internal_spdm_x509_date_time_check(
		end_cert_from, end_cert_from_len, end_cert_to, end_cert_to_len);
	if (!status) {
		goto cleanup;
	}

	// 7. SubjectPublic KeyInfo
	status = rsa_get_public_key_from_x509(cert, cert_size, &rsa_context);
	if (!status) {
		status = ec_get_public_key_from_x509(cert, cert_size,
						     &ec_context);
	}
	if (!status) {
		goto cleanup;
	}

	// 8. Extended key usage
	value = 0;
	ret = x509_get_extended_key_usage(cert, cert_size, NULL, &value);
	if (ret != RETURN_BUFFER_TOO_SMALL || value == 0) {
		goto cleanup;
	}

	// 9. key usage
	status = x509_get_key_usage(cert, cert_size, &value);
	if (!status) {
		goto cleanup;
	}
	if (CRYPTO_X509_KU_DIGITAL_SIGNATURE & value) {
		status = TRUE;
	} else {
		status = FALSE;
	}

cleanup:
	if (rsa_context != NULL) {
		rsa_free(rsa_context);
	}
	if (ec_context != NULL) {
		ec_free(ec_context);
	}
	return status;
}

static const uint8 m_oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

/**
  Retrieve the SubjectAltName from SubjectAltName Bytes.

  @param[in]      buffer           Pointer to subjectAltName oct bytes.
  @param[in]      len              size of buffer in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate
                                   SubjectAltName. At most name_buffer_size bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     oid              OID of otherName
  @param[in,out]  oid_size          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   name_buffer_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status spdm_get_dmtf_subject_alt_name_from_bytes(
	IN const uint8 *buffer, IN intn len, OUT char8 *name_buffer,
	OPTIONAL IN OUT uintn *name_buffer_size, OUT uint8 *oid,
	OPTIONAL IN OUT uintn *oid_size)
{
	uint8 *ptr;
	int32 length;
	uintn obj_len;
	int32 ret;

	length = (int32)len;
	ptr = (uint8 *)buffer;
	obj_len = 0;

	// Sequence
	ret = asn1_get_tag(&ptr, ptr + length, &obj_len,
			   CRYPTO_ASN1_SEQUENCE | CRYPTO_ASN1_CONSTRUCTED);
	if (!ret) {
		return RETURN_NOT_FOUND;
	}

	ret = asn1_get_tag(&ptr, ptr + obj_len, &obj_len,
			   CRYPTO_ASN1_CONTEXT_SPECIFIC |
				   CRYPTO_ASN1_CONSTRUCTED);

	ret = asn1_get_tag(&ptr, ptr + obj_len, &obj_len, CRYPTO_ASN1_OID);
	if (!ret) {
		return RETURN_NOT_FOUND;
	}
	// CopyData to OID
	if (*oid_size < (uintn)obj_len) {
		*oid_size = (uintn)obj_len;
		return RETURN_BUFFER_TOO_SMALL;
	}
	if (oid != NULL) {
		copy_mem(oid, ptr, obj_len);
		*oid_size = obj_len;
	}

	// Move to next element
	ptr += obj_len;

	ret = asn1_get_tag(&ptr, (uint8 *)(buffer + length), &obj_len,
			   CRYPTO_ASN1_CONTEXT_SPECIFIC |
				   CRYPTO_ASN1_CONSTRUCTED);
	ret = asn1_get_tag(&ptr, (uint8 *)(buffer + length), &obj_len,
			   CRYPTO_ASN1_UTF8_STRING);
	if (!ret) {
		return RETURN_NOT_FOUND;
	}

	if (*name_buffer_size < (uintn)obj_len + 1) {
		*name_buffer_size = (uintn)obj_len + 1;
		return RETURN_BUFFER_TOO_SMALL;
	}

	if (name_buffer != NULL) {
		copy_mem(name_buffer, ptr, obj_len);
		*name_buffer_size = obj_len + 1;
		name_buffer[obj_len] = 0;
	}
	return RETURN_SUCCESS;
}

/**
  Retrieve the SubjectAltName from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate
                                   SubjectAltName. At most name_buffer_size bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     oid              OID of otherName
  @param[in,out]  oid_size          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   name_buffer_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status
spdm_get_dmtf_subject_alt_name(IN const uint8 *cert, IN intn cert_size,
			       OUT char8 *name_buffer,
			       OPTIONAL IN OUT uintn *name_buffer_size,
			       OUT uint8 *oid, OPTIONAL IN OUT uintn *oid_size)
{
	return_status status;
	uintn extension_data_size;

	extension_data_size = 0;
	status = x509_get_extension_data(cert, cert_size,
					 (uint8 *)m_oid_subject_alt_name,
					 sizeof(m_oid_subject_alt_name), NULL,
					 &extension_data_size);
	if (status != RETURN_BUFFER_TOO_SMALL) {
		return RETURN_NOT_FOUND;
	}
	if (extension_data_size > *name_buffer_size) {
		*name_buffer_size = extension_data_size;
		return RETURN_BUFFER_TOO_SMALL;
	}
	status =
		x509_get_extension_data(cert, cert_size,
					(uint8 *)m_oid_subject_alt_name,
					sizeof(m_oid_subject_alt_name),
					(uint8 *)name_buffer, name_buffer_size);
	if (RETURN_ERROR(status)) {
		return status;
	}

	return spdm_get_dmtf_subject_alt_name_from_bytes(
		(const uint8 *)name_buffer, *name_buffer_size, name_buffer,
		name_buffer_size, oid, oid_size);
}

/**
  This function verifies the integrity of certificate chain data without spdm_cert_chain_t header.

  @param  cert_chain_data          The certificate chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size      size in bytes of the certificate chain data.

  @retval TRUE  certificate chain data integrity verification pass.
  @retval FALSE certificate chain data integrity verification fail.
**/
boolean spdm_verify_cert_chain_data(IN uint8 *cert_chain_data,
				    IN uintn cert_chain_data_size)
{
	uint8 *root_cert_buffer;
	uintn root_cert_buffer_size;
	uint8 *leaf_cert_buffer;
	uintn leaf_cert_buffer_size;

	if (cert_chain_data_size >
	    MAX_UINT16 - (sizeof(spdm_cert_chain_t) + MAX_HASH_SIZE)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainData - FAIL (chain size too large) !!!\n"));
		return FALSE;
	}

	if (!x509_get_cert_from_cert_chain(
		    cert_chain_data, cert_chain_data_size, 0, &root_cert_buffer,
		    &root_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainData - FAIL (get root certificate failed)!!!\n"));
		return FALSE;
	}

	if (!x509_verify_cert_chain(root_cert_buffer, root_cert_buffer_size,
				    cert_chain_data, cert_chain_data_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainData - FAIL (cert chain verify failed)!!!\n"));
		return FALSE;
	}

	if (!x509_get_cert_from_cert_chain(
		    cert_chain_data, cert_chain_data_size, -1,
		    &leaf_cert_buffer, &leaf_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainData - FAIL (get leaf certificate failed)!!!\n"));
		return FALSE;
	}

	if (!spdm_x509_certificate_check(leaf_cert_buffer,
					 leaf_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainData - FAIL (leaf certificate check failed)!!!\n"));
		return FALSE;
	}

	return TRUE;
}

/**
  This function verifies the integrity of certificate chain buffer including spdm_cert_chain_t header.

  @param  base_hash_algo                 SPDM base_hash_algo
  @param  cert_chain_buffer              The certificate chain buffer including spdm_cert_chain_t header.
  @param  cert_chain_buffer_size          size in bytes of the certificate chain buffer.

  @retval TRUE  certificate chain buffer integrity verification pass.
  @retval FALSE certificate chain buffer integrity verification fail.
**/
boolean spdm_verify_certificate_chain_buffer(IN uint32 base_hash_algo,
					     IN void *cert_chain_buffer,
					     IN uintn cert_chain_buffer_size)
{
	uint8 *cert_chain_data;
	uintn cert_chain_data_size;
	uint8 *root_cert_buffer;
	uintn root_cert_buffer_size;
	uintn hash_size;
	uint8 calc_root_cert_hash[MAX_HASH_SIZE];
	uint8 *leaf_cert_buffer;
	uintn leaf_cert_buffer_size;

	hash_size = spdm_get_hash_size(base_hash_algo);

	if (cert_chain_buffer_size > MAX_SPDM_MESSAGE_BUFFER_SIZE) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (buffer too large) !!!\n"));
		return FALSE;
	}

	if (cert_chain_buffer_size <= sizeof(spdm_cert_chain_t) + hash_size) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (buffer too small) !!!\n"));
		return FALSE;
	}

	cert_chain_data = (uint8 *)cert_chain_buffer +
			  sizeof(spdm_cert_chain_t) + hash_size;
	cert_chain_data_size =
		cert_chain_buffer_size - sizeof(spdm_cert_chain_t) - hash_size;
	if (!x509_get_cert_from_cert_chain(
		    cert_chain_data, cert_chain_data_size, 0, &root_cert_buffer,
		    &root_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (get root certificate failed)!!!\n"));
		return FALSE;
	}

	spdm_hash_all(base_hash_algo, root_cert_buffer, root_cert_buffer_size,
		      calc_root_cert_hash);
	if (const_compare_mem((uint8 *)cert_chain_buffer + sizeof(spdm_cert_chain_t),
			calc_root_cert_hash, hash_size) != 0) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (cert root hash mismatch) !!!\n"));
		return FALSE;
	}

	if (!x509_verify_cert_chain(root_cert_buffer, root_cert_buffer_size,
				    cert_chain_data, cert_chain_data_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (cert chain verify failed)!!!\n"));
		return FALSE;
	}

	if (!x509_get_cert_from_cert_chain(
		    cert_chain_data, cert_chain_data_size, -1,
		    &leaf_cert_buffer, &leaf_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (get leaf certificate failed)!!!\n"));
		return FALSE;
	}

	if (!spdm_x509_certificate_check(leaf_cert_buffer,
					 leaf_cert_buffer_size)) {
		DEBUG((DEBUG_INFO,
		       "!!! VerifyCertificateChainBuffer - FAIL (leaf certificate check failed)!!!\n"));
		return FALSE;
	}

	return TRUE;
}
