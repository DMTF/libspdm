/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) || \
    (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) || \
    (LIBSPDM_SM2_DSA_SUPPORT)

/**
 * Helper function to retrieve public key from DER data using BIO.
 *
 * @param[in]  der_data       Pointer to the DER-encoded key data.
 * @param[in]  der_size       Size of the DER key data in bytes.
 * @param[out] pkey           Pointer to receive the EVP_PKEY.
 *
 * @retval  true   Public key was retrieved successfully.
 * @retval  false  Failed to retrieve public key.
 **/
static bool get_public_key_from_der_bio(const uint8_t *der_data, size_t der_size, EVP_PKEY **pkey)
{
    BIO *der_bio;
    bool result = false;

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return false;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }

    *pkey = d2i_PUBKEY_bio(der_bio, NULL);
    if (*pkey != NULL) {
        result = true;
    }

done:
    BIO_free(der_bio);
    return result;
}

/**
 * Helper function to allocate and initialize a key context wrapper.
 *
 * @param[in]  pkey           EVP_PKEY to wrap.
 * @param[out] context        Pointer to receive the allocated context.
 *
 * @retval  true   Context was allocated successfully.
 * @retval  false  Failed to allocate context.
 **/
static bool allocate_key_context(EVP_PKEY *pkey, void **context)
{
    libspdm_key_context *ctx;

    ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        return false;
    }
    ctx->evp_pkey = pkey;
    *context = ctx;
    return true;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) || \
          (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) || \
          (LIBSPDM_SM2_DSA_SUPPORT) */

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] rsa_context  Pointer to newly generated RSA context which contain the retrieved
 *                          RSA public key component. Use libspdm_rsa_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_rsa_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **rsa_context)
{
    EVP_PKEY *pkey = NULL;

    /* Check input parameters.*/
    if (der_data == NULL || rsa_context == NULL || der_size > INT_MAX) {
        return false;
    }

    /* Read DER data using BIO */
    if (!get_public_key_from_der_bio(der_data, der_size, &pkey)) {
        return false;
    }

    /* Verify key type */
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        return false;
    }

    /* Allocate wrapper structure */
    if (!allocate_key_context(pkey, rsa_context)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    return true;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
/**
 * Retrieve the EC Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data    Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size    size of the DER key data in bytes.
 * @param[out] ec_context  Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If der_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ec_get_public_key_from_der(const uint8_t *der_data,
                                        size_t der_size,
                                        void **ec_context)
{
    bool status;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Check input parameters.*/

    if (der_data == NULL || ec_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "EC",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
    if (dctx == NULL) {
        return false;
    }

    if (!OSSL_DECODER_from_data(dctx, &der_data, &der_size)) {
        goto done;
    }

    /* Verify key type */
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        goto done;
    }

    /* Allocate wrapper structure */
    if (!allocate_key_context(pkey, ec_context)) {
        goto done;
    }

    status = true;
    pkey = NULL; /* ownership moved */

done:
    /* Release Resources.*/
    OSSL_DECODER_CTX_free(dctx);

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return status;
}
#endif /* LIBSPDM_ECDSA_SUPPORT */

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
/**
 * Retrieve the Ed Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] ecd_context  Pointer to newly generated Ed DSA context which contain the retrieved
 *                          Ed public key component. Use libspdm_ecd_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ecd_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **ecd_context)
{
    EVP_PKEY *pkey = NULL;
    int32_t type;

    /* Check input parameters.*/
    if (der_data == NULL || ecd_context == NULL || der_size > INT_MAX) {
        return false;
    }

    /* Read DER data using BIO */
    if (!get_public_key_from_der_bio(der_data, der_size, &pkey)) {
        return false;
    }

    /* Verify key type */
    type = EVP_PKEY_id(pkey);
    if ((type != EVP_PKEY_ED25519) && (type != EVP_PKEY_ED448)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    /* Allocate wrapper structure */
    if (!allocate_key_context(pkey, ecd_context)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    return true;
}
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

#if LIBSPDM_SM2_DSA_SUPPORT
/**
 * Retrieve the sm2 Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] sm2_context  Pointer to newly generated sm2 context which contain the retrieved
 *                          sm2 public key component. Use sm2_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_sm2_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **sm2_context)
{
    EVP_PKEY *pkey = NULL;

    /* Check input parameters.*/
    if (der_data == NULL || sm2_context == NULL || der_size > INT_MAX) {
        return false;
    }

    /* Read DER data using BIO */
    if (!get_public_key_from_der_bio(der_data, der_size, &pkey)) {
        return false;
    }

    /* Verify key type */
    if (EVP_PKEY_is_a(pkey, "SM2") == 0) {
        EVP_PKEY_free(pkey);
        return false;
    }

    /* Allocate wrapper structure */
    if (!allocate_key_context(pkey, sm2_context)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    return true;
}
#endif /* LIBSPDM_SM2_DSA_SUPPORT */
