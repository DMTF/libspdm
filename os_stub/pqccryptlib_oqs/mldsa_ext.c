/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_pqccrypt_lib.h"

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_mldsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    OQS_SIG_WRAP *sig_wrap;

    sig_wrap = dsa_context;
    LIBSPDM_ASSERT(key_size == sig_wrap->sig->length_secret_key);
    if (key_size != sig_wrap->sig->length_secret_key) {
        return false;
    }
    libspdm_copy_mem(sig_wrap->priv_key, sizeof(sig_wrap->priv_key), key_data, key_size);
    sig_wrap->priv_key_size = sig_wrap->sig->length_secret_key;
    return true;
}

/**
 * Retrieve the DSA Private key from the password-protected PEM key data.
 *
 * OID is defined in https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates
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
    // TBD 1.4 - Need PEM parsing for PQC.
    return false;
}

/**
 * Carries out the MLDSA signature generation.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The MLDSA signing context.
 * @param[in]      context_size  Size of MLDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_mldsa_sign(void *dsa_context,
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t message_size,
                        uint8_t *signature, size_t *sig_size)
{
    OQS_STATUS rc;
    OQS_SIG_WRAP *sig_wrap;

    sig_wrap = dsa_context;
    LIBSPDM_ASSERT(sig_wrap->priv_key_size != 0);
    LIBSPDM_ASSERT(*sig_size == sig_wrap->sig->length_signature);
    if (sig_wrap->priv_key_size == 0) {
        return false;
    }
    if (*sig_size < sig_wrap->sig->length_signature) {
        *sig_size = sig_wrap->sig->length_signature;
        return false;
    }
    *sig_size = sig_wrap->sig->length_signature;
    rc = OQS_SIG_sign_with_ctx_str(sig_wrap->sig, signature, sig_size,
                                   message, message_size,
                                   context, context_size,
                                   sig_wrap->priv_key);
    if (rc != OQS_SUCCESS) {
        return false;
    }
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
