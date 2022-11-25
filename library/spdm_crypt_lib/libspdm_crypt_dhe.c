/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 **/
typedef void *(*libspdm_dhe_new_by_nid_func)(size_t nid);

/**
 * Generates DHE public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * @param  context          Pointer to the DHE context.
 * @param  public_key       Pointer to the buffer to receive generated public key.
 * @param  public_key_size  On input, the size of public_key buffer in bytes.
 *                          On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DHE public key generation succeeded.
 * @retval false  DHE public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
typedef bool (*libspdm_dhe_generate_key_func)(void *context,
                                              uint8_t *public_key,
                                              size_t *public_key_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * @param  context               Pointer to the DHE context.
 * @param  peer_public_key       Pointer to the peer's public key.
 * @param  peer_public_key_size  Size of peer's public key in bytes.
 * @param  key                   Pointer to the buffer to receive generated key.
 * @param  key_size              On input, the size of key buffer in bytes.
 *                               On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DHE exchanged key generation succeeded.
 * @retval false  DHE exchanged key generation failed.
 * @retval false  Key_size is not large enough.
 **/
typedef bool (*libspdm_dhe_compute_key_func)(void *context,
                                             const uint8_t *peer_public,
                                             size_t peer_public_size,
                                             uint8_t *key, size_t *key_size);

/**
 * Release the specified DHE context.
 *
 * @param  context  Pointer to the DHE context to be released.
 **/
typedef void (*libspdm_dhe_free_func)(void *context);

/**
 * This function returns the SPDM DHE algorithm key size.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return SPDM DHE algorithm key size.
 **/
uint32_t libspdm_get_dhe_pub_key_size(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
        return 256;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
        return 384;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
        return 512;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
        return 32 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
        return 48 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
        return 66 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
        return 32 * 2;
    default:
        return 0;
    }
}

/**
 * Return cipher ID, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE cipher ID
 **/
static size_t libspdm_get_dhe_nid(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
        return LIBSPDM_CRYPTO_NID_FFDHE2048;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
        return LIBSPDM_CRYPTO_NID_FFDHE3072;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
        return LIBSPDM_CRYPTO_NID_FFDHE4096;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
        return LIBSPDM_CRYPTO_NID_SECP256R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
        return LIBSPDM_CRYPTO_NID_SECP384R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
        return LIBSPDM_CRYPTO_NID_SECP521R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
        return LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Return DHE new by NID function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE new by NID function
 **/
static libspdm_dhe_new_by_nid_func libspdm_get_dhe_new(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT
        return libspdm_dh_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT
        return libspdm_ec_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
        return libspdm_sm2_key_exchange_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

void *libspdm_dhe_new(spdm_version_number_t spdm_version,
                      uint16_t dhe_named_group, bool is_initiator)
{
    libspdm_dhe_new_by_nid_func new_function;
    size_t nid;
    void *context;

    new_function = libspdm_get_dhe_new(dhe_named_group);
    if (new_function == NULL) {
        return NULL;
    }
    nid = libspdm_get_dhe_nid(dhe_named_group);
    if (nid == 0) {
        return NULL;
    }
    context = new_function(nid);
    if (context == NULL) {
        return NULL;
    }

#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    if (dhe_named_group == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256) {
        bool result;
        uint8_t spdm12_key_change_requester_context[
            SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE];
        uint8_t spdm12_key_change_responder_context[
            SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE];

        libspdm_copy_mem(spdm12_key_change_requester_context,
                         sizeof(spdm12_key_change_requester_context),
                         SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT,
                         SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE);
        libspdm_copy_mem(spdm12_key_change_responder_context,
                         sizeof(spdm12_key_change_responder_context),
                         SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT,
                         SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE);
        /* patch the version*/
        spdm12_key_change_requester_context[25] = (char)('0' + ((spdm_version >> 12) & 0xF));
        spdm12_key_change_requester_context[27] = (char)('0' + ((spdm_version >> 8) & 0xF));
        spdm12_key_change_responder_context[25] = (char)('0' + ((spdm_version >> 12) & 0xF));
        spdm12_key_change_responder_context[27] = (char)('0' + ((spdm_version >> 8) & 0xF));

        result = libspdm_sm2_key_exchange_init (context, LIBSPDM_CRYPTO_NID_SM3_256,
                                                spdm12_key_change_requester_context,
                                                SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE,
                                                spdm12_key_change_responder_context,
                                                SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE,
                                                is_initiator);
        if (!result) {
            libspdm_sm2_key_exchange_free (context);
            return NULL;
        }
    }
#endif

    return context;
}

/**
 * Return DHE free function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE free function
 **/
static libspdm_dhe_free_func libspdm_get_dhe_free(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT
        return libspdm_dh_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT
        return libspdm_ec_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
        return libspdm_sm2_key_exchange_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

void libspdm_dhe_free(uint16_t dhe_named_group, void *context)
{
    libspdm_dhe_free_func free_function;
    free_function = libspdm_get_dhe_free(dhe_named_group);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return DHE generate key function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE generate key function
 **/
static libspdm_dhe_generate_key_func libspdm_get_dhe_generate_key(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT
        return libspdm_dh_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT
        return libspdm_ec_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
        return libspdm_sm2_key_exchange_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

bool libspdm_dhe_generate_key(uint16_t dhe_named_group, void *context,
                              uint8_t *public_key,
                              size_t *public_key_size)
{
    libspdm_dhe_generate_key_func generate_key_function;
    generate_key_function = libspdm_get_dhe_generate_key(dhe_named_group);
    if (generate_key_function == NULL) {
        return false;
    }
    return generate_key_function(context, public_key, public_key_size);
}

/**
 * Return DHE compute key function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE compute key function
 **/
static libspdm_dhe_compute_key_func libspdm_get_dhe_compute_key(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT
        return libspdm_dh_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT
        return libspdm_ec_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
        return libspdm_sm2_key_exchange_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

bool libspdm_dhe_compute_key(uint16_t dhe_named_group, void *context,
                             const uint8_t *peer_public,
                             size_t peer_public_size, uint8_t *key,
                             size_t *key_size)
{
    libspdm_dhe_compute_key_func compute_key_function;
    compute_key_function = libspdm_get_dhe_compute_key(dhe_named_group);
    if (compute_key_function == NULL) {
        return false;
    }
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
    if (dhe_named_group == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256) {
        /* SM2 key exchange can generate arbitrary length key_size. SPDM requires SM2 key_size to be 16. */
        LIBSPDM_ASSERT (*key_size >= 16);
        *key_size = 16;
    }
#endif
    return compute_key_function(context, peer_public, peer_public_size, key, key_size);
}
