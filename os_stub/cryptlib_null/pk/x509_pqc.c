/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 Certificate Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Retrieve the mldsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated mldsa context which contain the retrieved
 *                          mldsa public key component. Use mldsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   mldsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve mldsa public key from X509 certificate.
 *
 **/
bool libspdm_mldsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                            void **dsa_context)
{
    return false;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Retrieve the slhdsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated slhdsa context which contain the retrieved
 *                          slhdsa public key component. Use slhdsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   slhdsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve slhdsa public key from X509 certificate.
 *
 **/
bool libspdm_slhdsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                             void **dsa_context)
{
    return false;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
