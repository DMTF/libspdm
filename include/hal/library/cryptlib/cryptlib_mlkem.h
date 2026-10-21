/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_MLKEM_H
#define CRYPTLIB_MLKEM_H

#if LIBSPDM_ML_KEM_SUPPORT
/**
 * Allocates and initializes one KEM context for subsequent use with the NID.
 *
 * nid is LIBSPDM_CRYPTO_NID_ML_KEM_512, LIBSPDM_CRYPTO_NID_ML_KEM_768 or
 * LIBSPDM_CRYPTO_NID_ML_KEM_1024. This function can also generate the key pair, and then
 * libspdm_mlkem_generate_key() only returns its encapsulation key.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the KEM context that has been initialized, or NULL if nid is not supported
 *          or the context cannot be created.
 **/
extern void *libspdm_mlkem_new_by_name(size_t nid);

/**
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
extern void libspdm_mlkem_free(void *kem_context);

/**
 * Generates KEM public key.
 *
 * The public key is the encapsulation key, encoded as in FIPS 203, which is 800, 1184 or 1568 bytes
 * for ML-KEM-512, ML-KEM-768 or ML-KEM-1024. If libspdm_mlkem_new_by_name() generated the key pair,
 * then this function only returns its encapsulation key.
 *
 * @param[in, out]  kem_context       Pointer to the KEM context.
 * @param[out]      encap_key        Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size   On input, the size of encap_key buffer in bytes.
 *                                   On output, the size of data returned in encap_key buffer in
 *                                   bytes.
 *
 * @retval true   KEM public key generation succeeded.
 * @retval false  KEM public key generation failed.
 * @retval false  encap_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size);

/**
 * Computes exchanged common key.
 *
 * peer_encap_key is the peer's encapsulation key, encoded as in FIPS 203, and peer_encap_key_size
 * must be exactly 800, 1184 or 1568 bytes for ML-KEM-512, ML-KEM-768 or ML-KEM-1024. This function
 * must perform the encapsulation key checks of FIPS 203, because libspdm checks only the size of
 * the key that it receives from the Requester. The cipher text is 768, 1088 or 1568 bytes, and the
 * shared secret is 32 bytes.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive cipher text.
 * @param[in, out]  cipher_text_size      On input, the size of cipher text buffer in bytes.
 *                                        On output, the size of data returned in cipher text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared secret buffer in bytes.
 *                                        On output, the size of data returned in shared secret buffer in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  cipher_text_size or shared_secret_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                                      size_t peer_encap_key_size, uint8_t *cipher_text,
                                      size_t *cipher_text_size, uint8_t *shared_secret,
                                      size_t *shared_secret_size);

/**
 * Computes exchanged common key.
 *
 * peer_cipher_text_size must be exactly 768, 1088 or 1568 bytes for ML-KEM-512, ML-KEM-768 or
 * ML-KEM-1024, and the shared secret is 32 bytes.
 *
 * @param[in, out]  kem_context            Pointer to the KEM context.
 * @param[in]       peer_cipher_text       Pointer to the peer's cipher text.
 * @param[in]       peer_cipher_text_size  size of peer's cipher text in bytes.
 * @param[out]      shared_secret          Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size     On input, the size of shared secret buffer in bytes.
 *                                         On output, the size of data returned in shared secret buffer in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                                      size_t peer_cipher_text_size, uint8_t *shared_secret,
                                      size_t *shared_secret_size);

#if LIBSPDM_FIPS_MODE
/**
 * Computes exchanged common key. This API can be used for FIPS test.
 *
 * This function is libspdm_mlkem_encapsulate() with randomness from the caller. entropy is the
 * 32-byte random value m of ML-KEM.Encaps in FIPS 203, so entropy_size must be 32. If entropy is
 * NULL, then the random number generator provides m, as in libspdm_mlkem_encapsulate().
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive cipher text.
 * @param[in, out]  cipher_text_size      On input, the size of cipher text buffer in bytes.
 *                                        On output, the size of data returned in cipher text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared secret buffer in bytes.
 *                                        On output, the size of data returned in shared secret buffer in bytes.
 * @param[in]       entropy               Pointer to the random value, or NULL.
 * @param[in]       entropy_size          Size of the random value in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  cipher_text_size is not large enough.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  entropy is not NULL and entropy_size is not 32.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_encapsulate_ex(void *kem_context, const uint8_t *peer_encap_key,
                                         size_t peer_encap_key_size, uint8_t *cipher_text,
                                         size_t *cipher_text_size, uint8_t *shared_secret,
                                         size_t *shared_secret_size, uint8_t *entropy,
                                         size_t entropy_size);

/**
 * Sets the key component into the established KEM context.
 *
 * key_data is the decapsulation key, encoded as in FIPS 203, which is the expanded key rather than
 * the 64-byte seed. key_size must be exactly 1632, 2400 or 3168 bytes for ML-KEM-512, ML-KEM-768 or
 * ML-KEM-1024. This function can replace any key that the context holds.
 *
 * @param[in, out]  kem_context  Pointer to KEM context being set.
 * @param[in]       key_data     Pointer to the decapsulation key.
 * @param[in]       key_size     Size of the decapsulation key in bytes.
 *
 * @retval  true   KEM key component was set successfully.
 * @retval  false  The decapsulation key is invalid or has the wrong size.
 **/
extern bool libspdm_mlkem_set_privkey(void *kem_context, const uint8_t *key_data, size_t key_size);
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_ML_KEM_SUPPORT */
#endif /* CRYPTLIB_MLKEM_H */
