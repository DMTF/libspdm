/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

#if LIBSPDM_ML_DSA_SUPPORT
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
    return false;
}
#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT
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
    return false;
}
#endif /* LIBSPDM_SLH_DSA_SUPPORT */
