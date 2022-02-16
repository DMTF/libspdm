/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_CRYPTO_LIB_H__
#define __SPDM_CRYPTO_LIB_H__

#ifndef LIBSPDM_CONFIG
#include "spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#include "hal/base.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"

#define LIBSPDM_MAX_DHE_KEY_SIZE 512
#define LIBSPDM_MAX_ASYM_KEY_SIZE 512
#define LIBSPDM_MAX_HASH_SIZE 64
#define LIBSPDM_MAX_AEAD_KEY_SIZE 32
#define LIBSPDM_MAX_AEAD_IV_SIZE 12
#define LIBSPDM_MAX_AEAD_TAG_SIZE 16

/**
 * Allocates and initializes one HASH_CTX context for subsequent hash use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hash_new_func() returns NULL.
 **/
typedef void * (*libspdm_hash_new_func)();

/**
 * Release the specified HASH_CTX context.
 *
 * @param  hash_context                   Pointer to the HASH_CTX context to be released.
 **/
typedef void (*libspdm_hash_free_func)(void *hash_context);

/**
 * Initializes user-supplied memory pointed by hash_context as hash context for
 * subsequent use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hash_context                   Pointer to hash context being initialized.
 *
 * @retval true   Hash context initialization succeeded.
 * @retval false  Hash context initialization failed.
 **/
typedef bool (*libspdm_hash_init_func)(void *hash_context);

/**
 * Makes a copy of an existing hash context.
 *
 * If hash_ctx is NULL, then return false.
 * If new_hash_ctx is NULL, then return false.
 *
 * @param[in]  hash_ctx     Pointer to hash context being copied.
 * @param[out] new_hash_ctx  Pointer to new hash context.
 *
 * @retval true   hash context copy succeeded.
 * @retval false  hash context copy failed.
 *
 **/
typedef bool (*libspdm_hash_duplicate_func)(const void *hash_ctx,
                                            void *new_hash_ctx);

/**
 * Digests the input data and updates hash context.
 *
 * This function performs hash digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * Hash context should be already correctly initialized by hash_init(), and should not be finalized
 * by hash_final(). Behavior with invalid context is undefined.
 *
 * If hash_context is NULL, then return false.
 *
 * @param[in, out]  hash_context   Pointer to the MD context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size      Size of data buffer in bytes.
 *
 * @retval true   hash data digest succeeded.
 * @retval false  hash data digest failed.
 **/
typedef bool (*libspdm_hash_update_func)(void *hash_context, const void *data,
                                         uintn data_size);

/**
 * Completes computation of the hash digest value.
 *
 * This function completes hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the hash context cannot
 * be used again.
 * hash context should be already correctly initialized by hash_init(), and should not be
 * finalized by hash_final(). Behavior with invalid hash context is undefined.
 *
 * If hash_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  hash_context    Pointer to the hash context.
 * @param[out]      hash_value      Pointer to a buffer that receives the hash digest value.
 *
 * @retval true   hash digest computation succeeded.
 * @retval false  hash digest computation failed.
 **/
typedef bool (*libspdm_hash_final_func)(void *hash_context, uint8_t *hash_value);

/**
 * Computes the hash of a input data buffer.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  data                         Pointer to the buffer containing the data to be hashed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
typedef bool (*libspdm_hash_all_func)(const void *data, uintn data_size,
                                      uint8_t *hash_value);

/**
 * Allocates and initializes one HMAC context for subsequent hash use.
 *
 * @return  Pointer to the HMAC context that has been initialized.
 *         If the allocations fails, libspdm_hmac_new_func() returns NULL.
 **/
typedef void * (*libspdm_hmac_new_func)();

/**
 * Release the specified HMAC context.
 *
 * @param  hmac_ctx                   Pointer to the HMAC context to be released.
 **/
typedef void (*libspdm_hmac_free_func)(void *hmac_ctx);

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to hmac_update().
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[out]  hmac_ctx  Pointer to HMAC context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
typedef bool (*libspdm_hmac_set_key_func)(void *hmac_ctx, const uint8_t *key,
                                          uintn key_size);

/**
 * Makes a copy of an existing HMAC context.
 *
 * If hmac_ctx is NULL, then return false.
 * If new_hmac_ctx is NULL, then return false.
 *
 * @param[in]  hmac_ctx     Pointer to HMAC context being copied.
 * @param[out] new_hmac_ctx  Pointer to new HMAC context.
 *
 * @retval true   HMAC context copy succeeded.
 * @retval false  HMAC context copy failed.
 *
 **/
typedef bool (*libspdm_hmac_duplicate_func)(const void *hmac_ctx,
                                            void *new_hmac_ctx);

/**
 * Digests the input data and updates HMAC context.
 *
 * This function performs HMAC digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC context should be initialized by hmac_new(), and should not be finalized
 * by hmac_final(). Behavior with invalid context is undefined.
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx Pointer to the HMAC context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC data digest succeeded.
 * @retval false  HMAC data digest failed.
 *
 **/
typedef bool (*libspdm_hmac_update_func)(void *hmac_ctx, const void *data,
                                         uintn data_size);

/**
 * Completes computation of the HMAC digest value.
 *
 * This function completes HMAC hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC context cannot
 * be used again.
 *
 * If hmac_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx  Pointer to the HMAC context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC digest
 *                                    value.
 *
 * @retval true   HMAC digest computation succeeded.
 * @retval false  HMAC digest computation failed.
 *
 **/
typedef bool (*libspdm_hmac_final_func)(void *hmac_ctx, uint8_t *hmac_value);

/**
 * Computes the HMAC of a input data buffer.
 *
 * This function performs the HMAC of a given data buffer, and return the hash value.
 *
 * @param  data                         Pointer to the buffer containing the data to be HMACed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  key                          Pointer to the user-supplied key.
 * @param  key_size                      key size in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the HMAC value.
 *
 * @retval true   HMAC computation succeeded.
 * @retval false  HMAC computation failed.
 **/
typedef bool (*libspdm_hmac_all_func)(const void *data, uintn data_size,
                                      const uint8_t *key, uintn key_size,
                                      uint8_t *hmac_value);

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand.
 *
 * @param  prk                          Pointer to the user-supplied key.
 * @param  prk_size                      key size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
typedef bool (*libspdm_hkdf_expand_func)(const uint8_t *prk, uintn prk_size,
                                         const uint8_t *info, uintn info_size,
                                         uint8_t *out, uintn out_size);

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate.
 *
 * @param  cert                         Pointer to the DER-encoded X509 certificate.
 * @param  cert_size                     size of the X509 certificate in bytes.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
typedef bool (*libspdm_asym_get_public_key_from_x509_func)(const uint8_t *cert,
                                                           uintn cert_size,
                                                           void **context);

/**
 * Release the specified asymmetric context.
 *
 * @param  context                      Pointer to the asymmetric context to be released.
 **/
typedef void (*libspdm_asym_free_func)(void *context);

/**
 * Verifies the asymmetric signature.
 *
 * For RSA/ECDSA, param is NULL.
 * For EdDSA, param is EdDSA context.
 *  For EdDSA25519, param is NULL.
 *  For EdDSA448, param is EdDSA448 context.
 * For SM2_DSA, param is SM2 IDa.
 *
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  hash_nid                      hash NID
 * @param  param                        algorithm specific parameter
 * @param  param_size                   algorithm specific parameter size
 * @param  message                      Pointer to octet message to be checked (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
typedef bool (*libspdm_asym_verify_func)(void *context, uintn hash_nid,
                                         const uint8_t *param, uintn param_size,
                                         const uint8_t *message,
                                         uintn message_size,
                                         const uint8_t *signature,
                                         uintn sig_size);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
typedef bool (*libspdm_asym_get_private_key_from_pem_func)(const uint8_t *pem_data,
                                                           uintn pem_size,
                                                           const char *password,
                                                           void **context);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * For RSA/ECDSA/EdDSA25519, param is NULL.
 * For EdDSA448, param is EdDSA448 context.
 * For SM2_DSA, param is SM2 IDa.
 *
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  hash_nid                      hash NID
 * @param  param                        algorithm specific parameter
 * @param  param_size                   algorithm specific parameter size
 * @param  message                      Pointer to octet message to be signed (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
typedef bool (*libspdm_asym_sign_func)(void *context, uintn hash_nid,
                                       const uint8_t *param, uintn param_size,
                                       const uint8_t *message,
                                       uintn message_size, uint8_t *signature,
                                       uintn *sig_size);

/**
 * Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 **/
typedef void *(*libspdm_dhe_new_by_nid_func)(uintn nid);

/**
 * Generates DHE public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * @param  context                      Pointer to the DHE context.
 * @param  public_key                    Pointer to the buffer to receive generated public key.
 * @param  public_key_size                On input, the size of public_key buffer in bytes.
 *                                     On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DHE public key generation succeeded.
 * @retval false  DHE public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
typedef bool (*libspdm_dhe_generate_key_func)(void *context,
                                              uint8_t *public_key,
                                              uintn *public_key_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * @param  context                      Pointer to the DHE context.
 * @param  peer_public_key                Pointer to the peer's public key.
 * @param  peer_public_key_size            size of peer's public key in bytes.
 * @param  key                          Pointer to the buffer to receive generated key.
 * @param  key_size                      On input, the size of key buffer in bytes.
 *                                     On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DHE exchanged key generation succeeded.
 * @retval false  DHE exchanged key generation failed.
 * @retval false  key_size is not large enough.
 **/
typedef bool (*libspdm_dhe_compute_key_func)(void *context,
                                             const uint8_t *peer_public,
                                             uintn peer_public_size,
                                             uint8_t *key, uintn *key_size);

/**
 * Release the specified DHE context.
 *
 * @param  context                      Pointer to the DHE context to be released.
 **/
typedef void (*libspdm_dhe_free_func)(void *context);

/**
 * Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD).
 *
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                       size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be encrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the encryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated encryption succeeded.
 * @retval false  AEAD authenticated encryption failed.
 **/
typedef bool (*libspdm_aead_encrypt_func)(
    const uint8_t *key, uintn key_size, const uint8_t *iv,
    uintn iv_size, const uint8_t *a_data, uintn a_data_size,
    const uint8_t *data_in, uintn data_in_size, uint8_t *tag_out,
    uintn tag_size, uint8_t *data_out, uintn *data_out_size);

/**
 * Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD).
 *
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                       size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be decrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag                          Pointer to a buffer that contains the authentication tag.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the decryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated decryption succeeded.
 * @retval false  AEAD authenticated decryption failed.
 **/
typedef bool (*libspdm_aead_decrypt_func)(
    const uint8_t *key, uintn key_size, const uint8_t *iv,
    uintn iv_size, const uint8_t *a_data, uintn a_data_size,
    const uint8_t *data_in, uintn data_in_size, const uint8_t *tag,
    uintn tag_size, uint8_t *data_out, uintn *data_out_size);

/**
 * This function returns the SPDM hash algorithm size.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return SPDM hash algorithm size.
 **/
uint32_t libspdm_get_hash_size(uint32_t base_hash_algo);

/**
 * Allocates and initializes one HASH_CTX context for subsequent hash use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hash_new() returns NULL.
 **/
void *libspdm_hash_new(uint32_t base_hash_algo);

/**
 * Release the specified HASH_CTX context.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hash_context                   Pointer to the HASH_CTX context to be released.
 **/
void libspdm_hash_free(uint32_t base_hash_algo, void *hash_context);

/**
 * Initializes user-supplied memory pointed by hash_context as hash context for
 * subsequent use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hash_context                   Pointer to hash context being initialized.
 *
 * @retval true   Hash context initialization succeeded.
 * @retval false  Hash context initialization failed.
 **/
bool libspdm_hash_init(uint32_t base_hash_algo, void *hash_context);

/**
 * Makes a copy of an existing hash context.
 *
 * If hash_ctx is NULL, then return false.
 * If new_hash_ctx is NULL, then return false.
 *
 * @param[in]  hash_ctx     Pointer to hash context being copied.
 * @param[out] new_hash_ctx  Pointer to new hash context.
 *
 * @retval true   hash context copy succeeded.
 * @retval false  hash context copy failed.
 *
 **/
bool libspdm_hash_duplicate(uint32_t base_hash_algo,
                            const void *hash_ctx, void *new_hash_ctx);

/**
 * Digests the input data and updates hash context.
 *
 * This function performs hash digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * Hash context should be already correctly initialized by hash_init(), and should not be finalized
 * by hash_final(). Behavior with invalid context is undefined.
 *
 * If hash_context is NULL, then return false.
 *
 * @param[in, out]  hash_context   Pointer to the MD context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size      Size of data buffer in bytes.
 *
 * @retval true   hash data digest succeeded.
 * @retval false  hash data digest failed.
 **/
bool libspdm_hash_update(uint32_t base_hash_algo, void *hash_context,
                         const void *data, uintn data_size);

/**
 * Completes computation of the hash digest value.
 *
 * This function completes hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the hash context cannot
 * be used again.
 * hash context should be already correctly initialized by hash_init(), and should not be
 * finalized by hash_final(). Behavior with invalid hash context is undefined.
 *
 * If hash_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  hash_context    Pointer to the hash context.
 * @param[out]      hash_value      Pointer to a buffer that receives the hash digest value.
 *
 * @retval true   hash digest computation succeeded.
 * @retval false  hash digest computation failed.
 **/
bool libspdm_hash_final(uint32_t base_hash_algo, void *hash_context,
                        uint8_t *hash_value);

/**
 * Allocates and initializes one HMAC context for subsequent use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return  Pointer to the HMAC context that has been initialized.
 *         If the allocations fails, libspdm_hash_new() returns NULL.
 **/
void *libspdm_hmac_new(uint32_t base_hash_algo);

/**
 * Release the specified HMAC context.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hmac_ctx                   Pointer to the HMAC context to be released.
 **/
void libspdm_hmac_free(uint32_t base_hash_algo, void *hmac_ctx);

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to hmac_update().
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[out]  hmac_ctx  Pointer to HMAC context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
bool libspdm_hmac_init(uint32_t base_hash_algo,
                       void *hmac_ctx, const uint8_t *key,
                       uintn key_size);

/**
 * Makes a copy of an existing HMAC context.
 *
 * If hmac_ctx is NULL, then return false.
 * If new_hmac_ctx is NULL, then return false.
 *
 * @param[in]  hmac_ctx     Pointer to HMAC context being copied.
 * @param[out] new_hmac_ctx  Pointer to new HMAC context.
 *
 * @retval true   HMAC context copy succeeded.
 * @retval false  HMAC context copy failed.
 *
 **/
bool libspdm_hmac_duplicate(uint32_t base_hash_algo,
                            const void *hmac_ctx, void *new_hmac_ctx);
/**
 * Digests the input data and updates HMAC context.
 *
 * This function performs HMAC digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC context should be initialized by hmac_new(), and should not be finalized
 * by hmac_final(). Behavior with invalid context is undefined.
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx Pointer to the HMAC context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC data digest succeeded.
 * @retval false  HMAC data digest failed.
 *
 **/
bool libspdm_hmac_update(uint32_t base_hash_algo,
                         void *hmac_ctx, const void *data,
                         uintn data_size);
/**
 * Completes computation of the HMAC digest value.
 *
 * This function completes HMAC hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC context cannot
 * be used again.
 *
 * If hmac_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx  Pointer to the HMAC context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC digest
 *                                    value.
 *
 * @retval true   HMAC digest computation succeeded.
 * @retval false  HMAC digest computation failed.
 *
 **/
bool libspdm_hmac_final(uint32_t base_hash_algo,
                        void *hmac_ctx,  uint8_t *hmac_value);

/**
 * Computes the hash of a input data buffer, based upon the negotiated hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be hashed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
bool libspdm_hash_all(uint32_t base_hash_algo, const void *data,
                      uintn data_size, uint8_t *hash_value);

/**
 * This function returns the SPDM measurement hash algorithm size.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 *
 * @return SPDM measurement hash algorithm size.
 * @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
 **/
uint32_t libspdm_get_measurement_hash_size(uint32_t measurement_hash_algo);

/**
 * Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be hashed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, uintn data_size,
                                  uint8_t *hash_value);

/**
 * Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.
 *
 * This function performs the HMAC of a given data buffer, and return the hash value.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be HMACed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  key                          Pointer to the user-supplied key.
 * @param  key_size                      key size in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the HMAC value.
 *
 * @retval true   HMAC computation succeeded.
 * @retval false  HMAC computation failed.
 **/
bool libspdm_hmac_all(uint32_t base_hash_algo, const void *data,
                      uintn data_size, const uint8_t *key,
                      uintn key_size, uint8_t *hmac_value);

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  prk                          Pointer to the user-supplied key.
 * @param  prk_size                      key size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_hkdf_expand(uint32_t base_hash_algo, const uint8_t *prk,
                         uintn prk_size, const uint8_t *info,
                         uintn info_size, uint8_t *out, uintn out_size);

/**
 * This function returns the SPDM asymmetric algorithm size.
 *
 * @param  base_asym_algo                 SPDM base_hash_algo
 *
 * @return SPDM asymmetric algorithm size.
 **/
uint32_t libspdm_get_asym_signature_size(uint32_t base_asym_algo);

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  cert                         Pointer to the DER-encoded X509 certificate.
 * @param  cert_size                     size of the X509 certificate in bytes.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_asym_get_public_key_from_x509(uint32_t base_asym_algo,
                                           const uint8_t *cert,
                                           uintn cert_size,
                                           void **context);

/**
 * Release the specified asymmetric context,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  context                      Pointer to the asymmetric context to be released.
 **/
void libspdm_asym_free(uint32_t base_asym_algo, void *context);

/**
 * Verifies the asymmetric signature,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message                      Pointer to octet message to be checked (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_asym_verify(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    uintn message_size, const uint8_t *signature,
    uintn sig_size);

/**
 * Verifies the asymmetric signature,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message_hash                      Pointer to octet message hash to be checked (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_asym_verify_hash(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    uintn hash_size, const uint8_t *signature,
    uintn sig_size);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           uintn pem_size,
                                           const char *password,
                                           void **context);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message                      Pointer to octet message to be signed (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_asym_sign(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    uintn message_size, uint8_t *signature,
    uintn *sig_size);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message_hash                      Pointer to octet message hash to be signed (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_asym_sign_hash(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    uintn hash_size, uint8_t *signature,
    uintn *sig_size);

/**
 * This function returns the SPDM requester asymmetric algorithm size.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return SPDM requester asymmetric algorithm size.
 **/
uint32_t libspdm_get_req_asym_signature_size(uint16_t req_base_asym_alg);

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  cert                         Pointer to the DER-encoded X509 certificate.
 * @param  cert_size                     size of the X509 certificate in bytes.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_req_asym_get_public_key_from_x509(uint16_t req_base_asym_alg,
                                               const uint8_t *cert,
                                               uintn cert_size,
                                               void **context);

/**
 * Release the specified asymmetric context,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  context                      Pointer to the asymmetric context to be released.
 **/
void libspdm_req_asym_free(uint16_t req_base_asym_alg, void *context);

/**
 * Verifies the asymmetric signature,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message                      Pointer to octet message to be checked (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_req_asym_verify(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, uintn message_size,
    const uint8_t *signature, uintn sig_size);

/**
 * Verifies the asymmetric signature,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message_hash                      Pointer to octet message hash to be checked (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_req_asym_verify_hash(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, uintn hash_size,
    const uint8_t *signature, uintn sig_size);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               uintn pem_size,
                                               const char *password,
                                               void **context);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message                      Pointer to octet message to be signed (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_req_asym_sign(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, uintn message_size,
    uint8_t *signature, uintn *sig_size);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message_hash                      Pointer to octet message hash to be signed (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_req_asym_sign_hash(
    const spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, uintn hash_size,
    uint8_t *signature, uintn *sig_size);

/**
 * This function returns the SPDM DHE algorithm key size.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return SPDM DHE algorithm key size.
 **/
uint32_t libspdm_get_dhe_pub_key_size(uint16_t dhe_named_group);

/**
 * Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
 * based upon negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  is_initiator                   if the caller is initiator.
 *                                       true: initiator
 *                                       false: not an initiator
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 **/
void *libspdm_dhe_new(const spdm_version_number_t spdm_version,
                      uint16_t dhe_named_group, bool is_initiator);

/**
 * Release the specified DHE context,
 * based upon negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context to be released.
 **/
void libspdm_dhe_free(uint16_t dhe_named_group, void *context);

/**
 * Generates DHE public key,
 * based upon negotiated DHE algorithm.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context.
 * @param  public_key                    Pointer to the buffer to receive generated public key.
 * @param  public_key_size                On input, the size of public_key buffer in bytes.
 *                                     On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DHE public key generation succeeded.
 * @retval false  DHE public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
bool libspdm_dhe_generate_key(uint16_t dhe_named_group, void *context,
                              uint8_t *public_key,
                              uintn *public_key_size);

/**
 * Computes exchanged common key,
 * based upon negotiated DHE algorithm.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context.
 * @param  peer_public_key                Pointer to the peer's public key.
 * @param  peer_public_key_size            size of peer's public key in bytes.
 * @param  key                          Pointer to the buffer to receive generated key.
 * @param  key_size                      On input, the size of key buffer in bytes.
 *                                     On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DHE exchanged key generation succeeded.
 * @retval false  DHE exchanged key generation failed.
 * @retval false  key_size is not large enough.
 **/
bool libspdm_dhe_compute_key(uint16_t dhe_named_group, void *context,
                             const uint8_t *peer_public,
                             uintn peer_public_size, uint8_t *key,
                             uintn *key_size);

/**
 * This function returns the SPDM AEAD algorithm key size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm key size.
 **/
uint32_t libspdm_get_aead_key_size(uint16_t aead_cipher_suite);

/**
 * This function returns the SPDM AEAD algorithm iv size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm iv size.
 **/
uint32_t libspdm_get_aead_iv_size(uint16_t aead_cipher_suite);

/**
 * This function returns the SPDM AEAD algorithm tag size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm tag size.
 **/
uint32_t libspdm_get_aead_tag_size(uint16_t aead_cipher_suite);

/**
 * Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
 * based upon negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                       size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be encrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the encryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated encryption succeeded.
 * @retval false  AEAD authenticated encryption failed.
 **/
bool libspdm_aead_encryption(const spdm_version_number_t secured_message_version,
                             uint16_t aead_cipher_suite, const uint8_t *key,
                             uintn key_size, const uint8_t *iv,
                             uintn iv_size, const uint8_t *a_data,
                             uintn a_data_size, const uint8_t *data_in,
                             uintn data_in_size, uint8_t *tag_out,
                             uintn tag_size, uint8_t *data_out,
                             uintn *data_out_size);

/**
 * Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
 * based upon negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                       size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be decrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag                          Pointer to a buffer that contains the authentication tag.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the decryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated decryption succeeded.
 * @retval false  AEAD authenticated decryption failed.
 **/
bool libspdm_aead_decryption(const spdm_version_number_t secured_message_version,
                             uint16_t aead_cipher_suite, const uint8_t *key,
                             uintn key_size, const uint8_t *iv,
                             uintn iv_size, const uint8_t *a_data,
                             uintn a_data_size, const uint8_t *data_in,
                             uintn data_in_size, const uint8_t *tag,
                             uintn tag_size, uint8_t *data_out,
                             uintn *data_out_size);

/**
 * Generates a random byte stream of the specified size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  size                         size of random bytes to generate.
 * @param  rand                         Pointer to buffer to receive random value.
 **/
bool libspdm_get_random_number(uintn size, uint8_t *rand);

/**
 * Certificate Check for SPDM leaf cert.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 *
 * @retval  true   Success.
 * @retval  false  Certificate is not valid
 **/
bool libspdm_x509_certificate_check(const uint8_t *cert, uintn cert_size);

/**
 * Return certificate is root cert or not.
 * Certificate is considered as a root certificate if the subjectname equal issuername.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 *
 * @retval  true   Certificate is self-signed.
 * @retval  false  Certificate is not self-signed.
 **/
bool libspdm_is_root_certificate(const uint8_t *cert, uintn cert_size);

/**
 * Retrieve the SubjectAltName from SubjectAltName Bytes.
 *
 * @param[in]      buffer           Pointer to subjectAltName oct bytes.
 * @param[in]      len              size of buffer in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate
 *                                 SubjectAltName. At most name_buffer_size bytes will be
 *                                 written. Maybe NULL in order to determine the size
 *                                 buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 * @param[out]     oid              OID of otherName
 * @param[in,out]  oid_size          the buffersize for required OID
 *
 * @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 name_buffer_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
return_status libspdm_get_dmtf_subject_alt_name_from_bytes(
    uint8_t *buffer, const intn len, char *name_buffer,
    uintn *name_buffer_size, uint8_t *oid,
    uintn *oid_size);

/**
 * Retrieve the SubjectAltName from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate
 *                                 SubjectAltName. At most name_buffer_size bytes will be
 *                                 written. Maybe NULL in order to determine the size
 *                                 buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 * @param[out]     oid              OID of otherName
 * @param[in,out]  oid_size          the buffersize for required OID
 *
 * @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 name_buffer_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
return_status
libspdm_get_dmtf_subject_alt_name(const uint8_t *cert, const intn cert_size,
                                  char *name_buffer,
                                  uintn *name_buffer_size,
                                  uint8_t *oid, uintn *oid_size);

/**
 * This function verifies the integrity of certificate chain data without spdm_cert_chain_t header.
 *
 * @param  cert_chain_data          The certificate chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size      size in bytes of the certificate chain data.
 *
 * @retval true  certificate chain data integrity verification pass.
 * @retval false certificate chain data integrity verification fail.
 **/
bool libspdm_verify_cert_chain_data(uint8_t *cert_chain_data,
                                    uintn cert_chain_data_size);

/**
 * This function verifies the integrity of certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  cert_chain_buffer              The certificate chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certificate chain buffer.
 *
 * @retval true  certificate chain buffer integrity verification pass.
 * @retval false certificate chain buffer integrity verification fail.
 **/
bool libspdm_verify_certificate_chain_buffer(uint32_t base_hash_algo,
                                             const void *cert_chain_buffer,
                                             uintn cert_chain_buffer_size);

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated asymmetric or requester asymmetric algorithm.
 *
 *
 * @param  base_hash_algo                SPDM base_hash_algo.
 * @param  base_asym_alg                 SPDM base_asym_algo or req_base_asym_alg.
 * @param  cert_chain_data               Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size          size in bytes of the certitiface chain data.
 * @param  public_key                    Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_get_leaf_cert_public_key_from_cert_chain(uint32_t base_hash_algo,
                                                      uint32_t base_asym_alg,
                                                      uint8_t *cert_chain_data,
                                                      uintn cert_chain_data_size,
                                                      void **public_key);
#endif
