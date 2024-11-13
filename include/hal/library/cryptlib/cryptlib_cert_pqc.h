/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_CERT_PQC_H
#define CRYPTLIB_CERT_PQC_H

#if LIBSPDM_CERT_PARSE_SUPPORT
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
extern bool libspdm_mldsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                                   void **dsa_context);
#endif /* LIBSPDM_CERT_PARSE_SUPPORT */

#endif /* CRYPTLIB_CERT_H */
