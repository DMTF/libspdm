/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_SLHDSA_H
#define CRYPTLIB_SLHDSA_H

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * nid is one of the LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_* and LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_* NIDs.
 * This function can also generate a key pair, which libspdm_slhdsa_set_pubkey() and
 * libspdm_slhdsa_set_privkey() replace.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized, or NULL if nid is not supported
 *          or the context cannot be created.
 **/
extern void *libspdm_slhdsa_new(size_t nid);

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
extern void libspdm_slhdsa_free(void *dsa_context);

/**
 * Sets the key component into the established DSA context.
 *
 * key_data is the public key, encoded as in FIPS 205. key_size must be exactly 32, 48 or 64 bytes
 * for the 128, 192 or 256 parameter sets.
 *
 * This function can replace any key that the context holds. So to set both keys, call this function
 * before libspdm_slhdsa_set_privkey().
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to the public key.
 * @param[in]       key_size     Size of the public key in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 * @retval  false  The public key is invalid or has the wrong size.
 **/
extern bool libspdm_slhdsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Gets the key component from the established DSA context.
 *
 * key_data receives the public key, encoded as in FIPS 205, which is 32, 48 or 64 bytes for the
 * 128, 192 or 256 parameter sets. If key_size is too small then false is returned and key_size is
 * set to the size needed. key_data and key_size must not be NULL.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context.
 * @param[out]      key_data     Pointer to the buffer to receive the public key.
 * @param[in, out]  key_size     On input, the size of the key_data buffer in bytes.
 *                               On output, the size of the public key in bytes.
 *
 * @retval  true   DSA key component was retrieved successfully.
 * @retval  false  key_size is too small, or the public key could not be retrieved.
 **/
extern bool libspdm_slhdsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size);

/**
 * Sets the key component into the established DSA context.
 *
 * key_data is the private key, encoded as in FIPS 205. key_size must be exactly 64, 96 or 128
 * bytes for the 128, 192 or 256 parameter sets.
 *
 * This function can replace any key that the context holds. So to set both keys, call
 * libspdm_slhdsa_set_pubkey() before this function.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to the private key.
 * @param[in]       key_size     Size of the private key in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 * @retval  false  The private key is invalid or has the wrong size.
 **/
extern bool libspdm_slhdsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in RFC9909
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_slhdsa_free() function to free the resource.
 *
 * der_data and dsa_context must not be NULL.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
extern bool libspdm_slhdsa_get_public_key_from_der(const uint8_t *der_data,
                                                   size_t der_size,
                                                   void **dsa_context);

/**
 * Carries out the SLHDSA signature generation.
 *
 * The signature is pure SLH-DSA as FIPS 205 defines it, not HashSLH-DSA. context is the FIPS 205
 * context string, which is at most 255 bytes and can be empty. libspdm passes the SPDM signing
 * context string there. The signature is 7856, 17088, 16224, 35664, 29792 or 49856 bytes for the
 * 128s, 128f, 192s, 192f, 256s or 256f parameter sets. If sig_size is too small then false is
 * returned and sig_size is set to the size needed. signature must not be NULL.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
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
extern bool libspdm_slhdsa_sign(void *dsa_context,
                                const uint8_t *context, size_t context_size,
                                const uint8_t *message, size_t message_size,
                                uint8_t *signature, size_t *sig_size);

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the SLHDSA signature generation. This API can be used for FIPS test.
 *
 * This function is libspdm_slhdsa_sign() with a choice of variant. If deterministic is true, then
 * the signature uses the deterministic variant of slh_sign in FIPS 205, in which opt_rand is
 * PK.seed. Otherwise opt_rand is random.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
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
extern bool libspdm_slhdsa_sign_ex(void *dsa_context,
                                   const uint8_t *context, size_t context_size,
                                   const uint8_t *message, size_t message_size,
                                   uint8_t *signature, size_t *sig_size,
                                   bool deterministic);
#endif /* LIBSPDM_FIPS_MODE */

/**
 * Verifies the SLHDSA signature.
 *
 * The signature is pure SLH-DSA as FIPS 205 defines it, not HashSLH-DSA. context is the FIPS 205
 * context string, which is at most 255 bytes and can be empty. sig_size must be exactly the
 * signature size of the parameter set.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The SLHDSA signing context.
 * @param[in]  context_size  Size of SLHDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
extern bool libspdm_slhdsa_verify(void *dsa_context,
                                  const uint8_t *context, size_t context_size,
                                  const uint8_t *message, size_t message_size,
                                  const uint8_t *signature, size_t sig_size);

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
#endif /* CRYPTLIB_SLHDSA_H */
