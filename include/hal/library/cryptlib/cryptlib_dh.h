/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_DH_H
#define CRYPTLIB_DH_H

/*=====================================================================================
 *    Diffie-Hellman Key Exchange Primitives
 *=====================================================================================
 */

/**
 * Allocates and initializes one Diffie-Hellman context for subsequent use with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 *          If the allocations fails, libspdm_dh_new_by_nid() returns NULL.
 *          If the interface is not supported, libspdm_dh_new_by_nid() returns NULL.
 **/
extern void *libspdm_dh_new_by_nid(size_t nid);

/**
 * Release the specified DH context.
 *
 * @param[in]  dh_context  Pointer to the DH context to be released.
 **/
void libspdm_dh_free(void *dh_context);

/**
 * Generates DH parameter.
 *
 * Given generator g, and length of prime number p in bits, this function generates p,
 * and sets DH context according to value of g and p.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator     Value of generator.
 * @param[in]       prime_length  Length in bits of prime to be generated.
 * @param[out]      prime         Pointer to the buffer to receive the generated prime number.
 *
 * @retval true   DH parameter generation succeeded.
 * @retval false  Value of generator is not supported.
 * @retval false  Random number generator fails to generate random prime number with prime_length.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_dh_generate_parameter(void *dh_context, size_t generator,
                                          size_t prime_length, uint8_t *prime);

/**
 * Sets generator and prime parameters for DH.
 *
 * Given generator g, and prime number p, this function and sets DH context accordingly.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator     Value of generator.
 * @param[in]       prime_length  Length in bits of prime to be generated.
 * @param[in]       prime         Pointer to the prime number.
 *
 * @retval true   DH parameter setting succeeded.
 * @retval false  Value of generator is not supported.
 * @retval false  Value of generator is not suitable for the prime.
 * @retval false  Value of prime is not a prime number.
 * @retval false  Value of prime is not a safe prime number.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_dh_set_parameter(void *dh_context, size_t generator,
                                     size_t prime_length, const uint8_t *prime);

/**
 * Generates DH public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * If dh_context is NULL, then return false.
 * If public_key_size is NULL, then return false.
 * If public_key_size is large enough but public_key is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * For FFDHE2048, the public_size is 256.
 * For FFDHE3072, the public_size is 384.
 * For FFDHE4096, the public_size is 512.
 *
 * @param[in, out]  dh_context       Pointer to the DH context.
 * @param[out]      public_key       Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
 *                                   On output, the size of data returned in public_key buffer in
 *                                   bytes.
 *
 * @retval true   DH public key generation succeeded.
 * @retval false  DH public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_dh_generate_key(void *dh_context, uint8_t *public_key, size_t *public_key_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * If dh_context is NULL, then return false.
 * If peer_public_key is NULL, then return false.
 * If key_size is NULL, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 * If this interface is not supported, then return false.
 *
 * For FFDHE2048, the peer_public_size and key_size is 256.
 * For FFDHE3072, the peer_public_size and key_size is 384.
 * For FFDHE4096, the peer_public_size and key_size is 512.
 *
 * @param[in, out]  dh_context            Pointer to the DH context.
 * @param[in]       peer_public_key       Pointer to the peer's public key.
 * @param[in]       peer_public_key_size  size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   DH exchanged key generation succeeded.
 * @retval false  DH exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_dh_compute_key(void *dh_context, const uint8_t *peer_public_key,
                                   size_t peer_public_key_size, uint8_t *key,
                                   size_t *key_size);

#endif /* CRYPTLIB_DH_H */
