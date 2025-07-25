/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_slhdsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    return false;
}

/**
 * Carries out the SLHDSA signature generation.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
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
bool libspdm_slhdsa_sign(void *dsa_context,
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size,
                         uint8_t *signature, size_t *sig_size)
{
    return false;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
