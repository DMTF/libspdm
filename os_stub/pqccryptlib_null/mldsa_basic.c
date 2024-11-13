/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "library/spdm_crypt_lib.h"
#include "hal/library/cryptlib.h"

#include "oqs/oqs.h"

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized.
 **/
void *libspdm_mldsa_new(size_t nid)
{
    return NULL;
}

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
void libspdm_mldsa_free(void *dsa_context)
{
}

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_mldsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    return false;
}

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 * 
 * OID is defined in https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates
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

/**
 * Verifies the MLDSA signature.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The MLDSA signing context.
 * @param[in]  context_size  Size of MLDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
bool libspdm_mldsa_verify(void *dsa_context,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t message_size,
                          const uint8_t *signature, size_t sig_size)
{
    return false;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
