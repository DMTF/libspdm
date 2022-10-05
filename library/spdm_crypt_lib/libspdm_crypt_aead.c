/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * This function returns the SPDM AEAD algorithm key size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm key size.
 **/
uint32_t libspdm_get_aead_key_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 32;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 32;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 16;
    default:
        return 0;
    }
}

/**
 * This function returns the SPDM AEAD algorithm iv size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm iv size.
 **/
uint32_t libspdm_get_aead_iv_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 12;
    default:
        return 0;
    }
}

/**
 * This function returns the SPDM AEAD algorithm tag size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm tag size.
 **/
uint32_t libspdm_get_aead_tag_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 16;
    default:
        return 0;
    }
}

/**
 * Return AEAD encryption function, based upon the negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return AEAD encryption function
 **/
static libspdm_aead_encrypt_func libspdm_get_aead_enc_func(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT
        return libspdm_aead_aes_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT
        return libspdm_aead_aes_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
        return libspdm_aead_chacha20_poly1305_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
#if LIBSPDM_AEAD_SM4_SUPPORT
        return libspdm_aead_sm4_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

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
                             size_t key_size, const uint8_t *iv,
                             size_t iv_size, const uint8_t *a_data,
                             size_t a_data_size, const uint8_t *data_in,
                             size_t data_in_size, uint8_t *tag_out,
                             size_t tag_size, uint8_t *data_out,
                             size_t *data_out_size)
{
    libspdm_aead_encrypt_func aead_enc_function;
    aead_enc_function = libspdm_get_aead_enc_func(aead_cipher_suite);
    if (aead_enc_function == NULL) {
        return false;
    }
    return aead_enc_function(key, key_size, iv, iv_size, a_data,
                             a_data_size, data_in, data_in_size, tag_out,
                             tag_size, data_out, data_out_size);
}

/**
 * Return AEAD decryption function, based upon the negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return AEAD decryption function
 **/
static libspdm_aead_decrypt_func libspdm_get_aead_dec_func(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT
        return libspdm_aead_aes_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT
        return libspdm_aead_aes_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
        return libspdm_aead_chacha20_poly1305_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
#if LIBSPDM_AEAD_SM4_SUPPORT
        return libspdm_aead_sm4_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

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
                             size_t key_size, const uint8_t *iv,
                             size_t iv_size, const uint8_t *a_data,
                             size_t a_data_size, const uint8_t *data_in,
                             size_t data_in_size, const uint8_t *tag,
                             size_t tag_size, uint8_t *data_out,
                             size_t *data_out_size)
{
    libspdm_aead_decrypt_func aead_dec_function;
    aead_dec_function = libspdm_get_aead_dec_func(aead_cipher_suite);
    if (aead_dec_function == NULL) {
        return false;
    }
    return aead_dec_function(key, key_size, iv, iv_size, a_data,
                             a_data_size, data_in, data_in_size, tag,
                             tag_size, data_out, data_out_size);
}
