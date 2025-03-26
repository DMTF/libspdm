/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Diffie-Hellman Wrapper Implementation over.
 *
 * RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
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

#if LIBSPDM_ML_KEM_SUPPORT
/**
 * Allocates and initializes one KEM context for subsequent use with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the KEM context that has been initialized.
 **/
void *libspdm_mlkem_new_by_name(size_t nid)
{
    return NULL;
}

/**
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
}

/**
 * Generates KEM public key.
 *
 * @param[in, out]  kem_context       Pointer to the KEM context.
 * @param[out]      encap_key        Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size   On input, the size of public_key buffer in bytes.
 *                                   On output, the size of data returned in public_key buffer in
 *                                   bytes.
 *
 * @retval true   KEM public key generation succeeded.
 * @retval false  KEM public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size)
{
    return false;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                               size_t peer_encap_key_size, uint8_t *cipher_text,
                               size_t *cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    return false;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                               size_t peer_cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    return false;
}

#endif /* LIBSPDM_ML_KEM_SUPPORT */
