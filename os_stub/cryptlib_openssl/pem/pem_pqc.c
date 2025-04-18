/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int PasswordCallback(char *buf, const int size, const int flag, const void *key);

#if LIBSPDM_ML_DSA_SUPPORT

size_t libspdm_mldsa_type_name_to_nid(const char *type_name);

/**
 * Retrieve the DSA Private key from the password-protected PEM key data.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] dsa_context  Pointer to newly generated dsa context which contain the retrieved
 *                          dsa private key component. Use dsa_free() function to free the
 *                          resource.
 *
 * If pem_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   dsa Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_mldsa_get_private_key_from_pem(const uint8_t *pem_data,
                                            size_t pem_size,
                                            const char *password,
                                            void **dsa_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;

    /* Check input parameters.*/

    if (pem_data == NULL || dsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support most popular ciphers AES for the encrypted PEM.*/

    if (EVP_add_cipher(EVP_aes_128_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_192_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_256_cbc()) == 0) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    /* Retrieve Ed Private key from encrypted PEM data.*/

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    switch (libspdm_mldsa_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        break;
    default:
        goto done;
    }

    *dsa_context = pkey;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}
#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

size_t libspdm_slhdsa_type_name_to_nid(const char *type_name);

/**
 * Retrieve the DSA Private key from the password-protected PEM key data.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] dsa_context  Pointer to newly generated dsa context which contain the retrieved
 *                          dsa private key component. Use dsa_free() function to free the
 *                          resource.
 *
 * If pem_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   dsa Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_slhdsa_get_private_key_from_pem(const uint8_t *pem_data,
                                             size_t pem_size,
                                             const char *password,
                                             void **dsa_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;

    /* Check input parameters.*/

    if (pem_data == NULL || dsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support most popular ciphers AES for the encrypted PEM.*/

    if (EVP_add_cipher(EVP_aes_128_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_192_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_256_cbc()) == 0) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    /* Retrieve Ed Private key from encrypted PEM data.*/

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        break;
    default:
        goto done;
    }

    *dsa_context = pkey;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}
#endif /* LIBSPDM_SLH_DSA_SUPPORT */
