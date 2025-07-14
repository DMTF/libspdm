/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <mbedtls/pk.h>

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_mldsa_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
bool libspdm_mldsa_get_public_key_from_der(const uint8_t *der_data,
                                           size_t der_size,
                                           void **dsa_context)
{
    return false;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_slhdsa_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
bool libspdm_slhdsa_get_public_key_from_der(const uint8_t *der_data,
                                            size_t der_size,
                                            void **dsa_context)
{
    return false;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
