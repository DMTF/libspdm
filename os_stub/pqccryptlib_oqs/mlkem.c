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

#include "internal_pqccrypt_lib.h"

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
    OQS_KEM_WRAP *kem_wrap;

	kem_wrap = malloc(sizeof(OQS_KEM_WRAP));
    if (kem_wrap == NULL) {
        return NULL;
    }
    kem_wrap->decap_key_size = 0;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        kem_wrap->kem = OQS_KEM_ml_kem_512_new ();
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        kem_wrap->kem = OQS_KEM_ml_kem_768_new ();
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        kem_wrap->kem = OQS_KEM_ml_kem_1024_new ();
        break;
    default:
        free (kem_wrap);
        return NULL;
    }

    return kem_wrap;
}

/**
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
    OQS_KEM_WRAP *kem_wrap;

    kem_wrap = kem_context;
    OQS_KEM_free (kem_wrap->kem);
    if (kem_wrap->decap_key_size != 0) {
        libspdm_zero_mem (kem_wrap->decap_key, kem_wrap->decap_key_size);
    }
    free (kem_wrap);
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
    OQS_STATUS rc;
    OQS_KEM_WRAP *kem_wrap;

    kem_wrap = kem_context;
    LIBSPDM_ASSERT(*encap_key_size == kem_wrap->kem->length_public_key);
    if (*encap_key_size < kem_wrap->kem->length_public_key) {
        *encap_key_size = kem_wrap->kem->length_public_key;
        return false;
    }
    *encap_key_size = kem_wrap->kem->length_public_key;
    rc = OQS_KEM_keypair (kem_wrap->kem, encap_key, kem_wrap->decap_key);
    if (rc != OQS_SUCCESS) {
        return false;
    }
    kem_wrap->decap_key_size = kem_wrap->kem->length_secret_key;
    return true;
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
    OQS_STATUS rc;
    OQS_KEM_WRAP *kem_wrap;

    kem_wrap = kem_context;
    LIBSPDM_ASSERT(peer_encap_key_size == kem_wrap->kem->length_public_key);
    LIBSPDM_ASSERT(*cipher_text_size == kem_wrap->kem->length_ciphertext);
    LIBSPDM_ASSERT(*shared_secret_size == kem_wrap->kem->length_shared_secret);
    if (peer_encap_key_size != kem_wrap->kem->length_public_key) {
        return false;
    }
    if (*cipher_text_size < kem_wrap->kem->length_ciphertext) {
        *cipher_text_size = kem_wrap->kem->length_ciphertext;
        return false;
    }
    *cipher_text_size = kem_wrap->kem->length_ciphertext;
    if (*shared_secret_size < kem_wrap->kem->length_shared_secret) {
        *shared_secret_size = kem_wrap->kem->length_shared_secret;
        return false;
    }
    *shared_secret_size = kem_wrap->kem->length_shared_secret;
    rc = OQS_KEM_encaps (kem_wrap->kem, cipher_text, shared_secret, peer_encap_key);
    if (rc != OQS_SUCCESS) {
        return false;
    }
    return true;
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
    OQS_STATUS rc;
    OQS_KEM_WRAP *kem_wrap;

    kem_wrap = kem_context;
    LIBSPDM_ASSERT(kem_wrap->decap_key_size != 0);
    LIBSPDM_ASSERT(peer_cipher_text_size == kem_wrap->kem->length_ciphertext);
    LIBSPDM_ASSERT(*shared_secret_size == kem_wrap->kem->length_shared_secret);
    if (kem_wrap->decap_key_size == 0) {
        return false;
    }
    if (peer_cipher_text_size != kem_wrap->kem->length_ciphertext) {
        return false;
    }
    if (*shared_secret_size < kem_wrap->kem->length_shared_secret) {
        *shared_secret_size = kem_wrap->kem->length_shared_secret;
        return false;
    }
    *shared_secret_size = kem_wrap->kem->length_shared_secret;
    rc = OQS_KEM_decaps (kem_wrap->kem, shared_secret, peer_cipher_text, kem_wrap->decap_key);
    if (rc != OQS_SUCCESS) {
        return false;
    }
    return true;
}

#endif /* LIBSPDM_ML_KEM_SUPPORT */
