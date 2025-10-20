/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_MLKEM_H
#define CRYPTLIB_MLKEM_H

#if LIBSPDM_ML_KEM_SUPPORT
/**
 * Allocates and initializes one KEM context for subsequent use with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the KEM context that has been initialized.
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
 * @param[in, out]  kem_context       Pointer to the KEM context.
 * @param[out]      encap_key        Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size   On input, the size of public_key buffer in bytes.
 *                                   On output, the size of data returned in public_key buffer in
 *                                   bytes.
 *
 * @retval true   KEM public key generation succeeded.
 * @retval false  KEM public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size);

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                                      size_t peer_encap_key_size, uint8_t *cipher_text,
                                      size_t *cipher_text_size, uint8_t *shared_secret,
                                      size_t *shared_secret_size);

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                                      size_t peer_cipher_text_size, uint8_t *shared_secret,
                                      size_t *shared_secret_size);

#if LIBSPDM_FIPS_MODE
/**
 * Computes exchanged common key. This API can be used for FIPS test.
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
 * @param[in]       entropy               Pointer to the buffer to receive entropy.
 * @param[in]       entropy_size          size of entropy buffer in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  cipher_text_size is not large enough.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  entropy_size is not large enough.
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
 * @param[in, out]  dsa_context  Pointer to KEM context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   KEM key component was set successfully.
 **/
extern bool libspdm_mlkem_set_privkey(void *kem_context, const uint8_t *key_data, size_t key_size);
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_ML_KEM_SUPPORT */
#endif /* CRYPTLIB_MLKEM_H */
