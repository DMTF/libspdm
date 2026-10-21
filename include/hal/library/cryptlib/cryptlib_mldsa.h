/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_MLDSA_H
#define CRYPTLIB_MLDSA_H

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * nid is LIBSPDM_CRYPTO_NID_ML_DSA_44, LIBSPDM_CRYPTO_NID_ML_DSA_65 or
 * LIBSPDM_CRYPTO_NID_ML_DSA_87. This function can also generate a key pair, which
 * libspdm_mldsa_set_pubkey() and libspdm_mldsa_set_privkey() replace.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized, or NULL if nid is not supported
 *          or the context cannot be created.
 **/
extern void *libspdm_mldsa_new(size_t nid);

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
extern void libspdm_mldsa_free(void *dsa_context);

/**
 * Sets the key component into the established DSA context.
 *
 * key_data is the public key, encoded as in FIPS 204. key_size must be exactly 1312, 1952 or 2592
 * bytes for ML-DSA-44, ML-DSA-65 or ML-DSA-87.
 *
 * This function can replace any key that the context holds. So to set both keys, call this function
 * before libspdm_mldsa_set_privkey().
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to the public key.
 * @param[in]       key_size     Size of the public key in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 * @retval  false  The public key is invalid or has the wrong size.
 **/
extern bool libspdm_mldsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Gets the key component from the established DSA context.
 *
 * key_data receives the public key, encoded as in FIPS 204, which is 1312, 1952 or 2592 bytes for
 * ML-DSA-44, ML-DSA-65 or ML-DSA-87. If key_size is too small then false is returned and key_size
 * is set to the size needed. key_data and key_size must not be NULL.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context.
 * @param[out]      key_data     Pointer to the buffer to receive the public key.
 * @param[in, out]  key_size     On input, the size of the key_data buffer in bytes.
 *                               On output, the size of the public key in bytes.
 *
 * @retval  true   DSA key component was retrieved successfully.
 * @retval  false  key_size is too small, or the public key could not be retrieved.
 **/
extern bool libspdm_mldsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size);

/**
 * Sets the key component into the established DSA context.
 *
 * key_data is the private key, encoded as in FIPS 204, which is the expanded private key rather
 * than the 32-byte seed. key_size must be exactly 2560, 4032 or 4896 bytes for ML-DSA-44,
 * ML-DSA-65 or ML-DSA-87.
 *
 * This function can replace any key that the context holds. So to set both keys, call
 * libspdm_mldsa_set_pubkey() before this function.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to the private key.
 * @param[in]       key_size     Size of the private key in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 * @retval  false  The private key is invalid or has the wrong size.
 **/
extern bool libspdm_mldsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in RFC9881
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_mldsa_free() function to free the resource.
 *
 * der_data and dsa_context must not be NULL.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
extern bool libspdm_mldsa_get_public_key_from_der(const uint8_t *der_data,
                                                  size_t der_size,
                                                  void **dsa_context);

/**
 * Carries out the MLDSA signature generation.
 *
 * The signature is pure ML-DSA as FIPS 204 defines it, not HashML-DSA. context is the FIPS 204
 * context string, which is at most 255 bytes and can be empty. libspdm passes the SPDM signing
 * context string there. The signature is 2420, 3309 or 4627 bytes for ML-DSA-44, ML-DSA-65 or
 * ML-DSA-87. If sig_size is too small then false is returned and sig_size is set to the size
 * needed. signature must not be NULL.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The MLDSA signing context.
 * @param[in]      context_size  Size of MLDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_mldsa_sign(void *dsa_context,
                               const uint8_t *context, size_t context_size,
                               const uint8_t *message, size_t message_size,
                               uint8_t *signature, size_t *sig_size);

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the MLDSA signature generation. This API can be used for FIPS test.
 *
 * This function is libspdm_mldsa_sign() with a choice of variant. If deterministic is true, then
 * the signature uses the deterministic variant of ML-DSA.Sign in FIPS 204, in which rnd is 32 zero
 * bytes. Otherwise it uses the hedged variant, in which rnd is random.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The MLDSA signing context.
 * @param[in]      context_size  Size of MLDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 * @param[in]      deterministic If true, then generate the signature in deterministic way.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_mldsa_sign_ex(void *dsa_context,
                                  const uint8_t *context, size_t context_size,
                                  const uint8_t *message, size_t message_size,
                                  uint8_t *signature, size_t *sig_size,
                                  bool deterministic);
#endif /* LIBSPDM_FIPS_MODE */

/**
 * Verifies the MLDSA signature.
 *
 * The signature is pure ML-DSA as FIPS 204 defines it, not HashML-DSA. context is the FIPS 204
 * context string, which is at most 255 bytes and can be empty. sig_size must be exactly 2420, 3309
 * or 4627 bytes for ML-DSA-44, ML-DSA-65 or ML-DSA-87.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The MLDSA signing context.
 * @param[in]  context_size  Size of MLDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
extern bool libspdm_mldsa_verify(void *dsa_context,
                                 const uint8_t *context, size_t context_size,
                                 const uint8_t *message, size_t message_size,
                                 const uint8_t *signature, size_t sig_size);

#endif /* LIBSPDM_ML_DSA_SUPPORT */
#endif /* CRYPTLIB_MLDSA_H */
