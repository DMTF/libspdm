/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_MAC_H
#define CRYPTLIB_MAC_H

/*=====================================================================================
 *    Message Authentication Code (MAC) Primitives
 *=====================================================================================
 */

#if LIBSPDM_SHA256_SUPPORT
/**
 * Computes the HMAC-SHA256 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA256 digest
 *                          value (32 bytes).
 *
 * @retval true   HMAC-SHA256 digest computation succeeded.
 * @retval false  HMAC-SHA256 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sha256_all(const void *data, size_t data_size,
                                    const uint8_t *key, size_t key_size,
                                    uint8_t *hmac_value);
#endif /* LIBSPDM_SHA256_SUPPORT */

#if LIBSPDM_SHA384_SUPPORT
/**
 * Computes the HMAC-SHA384 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA384 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA384 digest
 *                          value (48 bytes).
 *
 * @retval true   HMAC-SHA384 digest computation succeeded.
 * @retval false  HMAC-SHA384 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sha384_all(const void *data, size_t data_size,
                                    const uint8_t *key, size_t key_size,
                                    uint8_t *hmac_value);
#endif /* LIBSPDM_SHA384_SUPPORT */

#if LIBSPDM_SHA512_SUPPORT
/**
 * Computes the HMAC-SHA512 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA512 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA512 digest
 *                          value (64 bytes).
 *
 * @retval true   HMAC-SHA512 digest computation succeeded.
 * @retval false  HMAC-SHA512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
extern bool libspdm_hmac_sha512_all(const void *data, size_t data_size,
                                    const uint8_t *key, size_t key_size,
                                    uint8_t *hmac_value);
#endif /* LIBSPDM_SHA512_SUPPORT */

#if LIBSPDM_SHA3_256_SUPPORT
/**
 * Computes the HMAC-SHA3-256 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3-256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA3-256 digest
 *                          value (32 bytes).
 *
 * @retval true   HMAC-SHA3-256 digest computation succeeded.
 * @retval false  HMAC-SHA3-256 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sha3_256_all(const void *data, size_t data_size,
                                      const uint8_t *key, size_t key_size,
                                      uint8_t *hmac_value);
#endif /* LIBSPDM_SHA3_256_SUPPORT */

#if LIBSPDM_SHA3_384_SUPPORT
/**
 * Computes the HMAC-SHA3-384 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3-384 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA3-384 digest
 *                          value (48 bytes).
 *
 * @retval true   HMAC-SHA3-384 digest computation succeeded.
 * @retval false  HMAC-SHA3-384 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sha3_384_all(const void *data, size_t data_size,
                                      const uint8_t *key, size_t key_size,
                                      uint8_t *hmac_value);
#endif /* LIBSPDM_SHA3_384_SUPPORT */

#if LIBSPDM_SHA3_512_SUPPORT
/**
 * Computes the HMAC-SHA3-512 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3-512 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SHA3-512 digest
 *                          value (64 bytes).
 *
 * @retval true   HMAC-SHA3-512 digest computation succeeded.
 * @retval false  HMAC-SHA3-512 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sha3_512_all(const void *data, size_t data_size,
                                      const uint8_t *key, size_t key_size,
                                      uint8_t *hmac_value);
#endif /* LIBSPDM_SHA3_512_SUPPORT */

#if LIBSPDM_SM3_256_SUPPORT
/**
 * Computes the HMAC-SM3-256 digest of a input data buffer.
 *
 * This function performs the HMAC-SM3-256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size    Key size in bytes.
 * @param[out]  hmac_value  Pointer to a buffer that receives the HMAC-SM3-256 digest
 *                          value (32 bytes).
 *
 * @retval true   HMAC-SM3-256 digest computation succeeded.
 * @retval false  HMAC-SM3-256 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_hmac_sm3_256_all(const void *data, size_t data_size,
                                     const uint8_t *key, size_t key_size,
                                     uint8_t *hmac_value);
#endif /* LIBSPDM_SM3_256_SUPPORT */

#endif /* CRYPTLIB_MAC_H */
