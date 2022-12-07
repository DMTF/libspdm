/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Release the specified asymmetric context.
 *
 * @param  context  Pointer to the asymmetric context to be released.
 **/
typedef void (*libspdm_asym_free_func)(void *context);

/**
 * Retrieve the Public key from the DER key data.
 *
 * @param  der_data  Pointer to the DER-encoded key data to be retrieved.
 * @param  der_size  Size of the DER key data in bytes.
 * @param  context   Pointer to new-generated asymmetric context which contain the retrieved public
 *                   key component. Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 **/
typedef bool (*libspdm_asym_get_public_key_from_der_func)(const uint8_t *der_data,
                                                          size_t der_size,
                                                          void **context);

/**
 * Verifies the asymmetric signature.
 *
 * For RSA/ECDSA, param is NULL.
 * For EdDSA, param is EdDSA context.
 * For EdDSA25519, param is NULL.
 * For EdDSA448, param is EdDSA448 context.
 * For SM2_DSA, param is SM2 IDa.
 *
 * @param  context       Pointer to asymmetric context for signature verification.
 * @param  hash_nid      Hash NID
 * @param  param         Algorithm specific parameter
 * @param  param_size    Algorithm specific parameter size
 * @param  message       Pointer to octet message to be checked (before hash).
 * @param  message_size  Size of the message in bytes.
 * @param  signature     Pointer to asymmetric signature to be verified.
 * @param  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
typedef bool (*libspdm_asym_verify_func)(void *context, size_t hash_nid,
                                         const uint8_t *param, size_t param_size,
                                         const uint8_t *message,
                                         size_t message_size,
                                         const uint8_t *signature,
                                         size_t sig_size);

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * For RSA/ECDSA/EdDSA25519, param is NULL.
 * For EdDSA448, param is EdDSA448 context.
 * For SM2_DSA, param is SM2 IDa.
 *
 * @param  context       Pointer to asymmetric context for signature generation.
 * @param  hash_nid      Hash NID
 * @param  param         Algorithm specific parameter
 * @param  param_size    Algorithm specific parameter size
 * @param  message       Pointer to octet message to be signed (before hash).
 * @param  message_size  Size of the message in bytes.
 * @param  signature     Pointer to buffer to receive signature.
 * @param  sig_size      On input, the size of signature buffer in bytes.
 *                       On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   Signature successfully generated.
 * @retval  false  Signature generation failed.
 * @retval  false  Sig_size is too small.
 **/
typedef bool (*libspdm_asym_sign_func)(void *context, size_t hash_nid,
                                       const uint8_t *param, size_t param_size,
                                       const uint8_t *message,
                                       size_t message_size, uint8_t *signature,
                                       size_t *sig_size);

typedef struct {
    bool is_requester;
    uint8_t op_code;
    const void *context;
    size_t context_size;
    size_t zero_pad_size;
} libspdm_signing_context_str_t;

static const libspdm_signing_context_str_t m_libspdm_signing_context_str_table[] = {
    {false, SPDM_CHALLENGE_AUTH, SPDM_CHALLENGE_AUTH_SIGN_CONTEXT,
     SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE, 36 - SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE},
    {true, SPDM_CHALLENGE_AUTH, SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT,
     SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE, 36 - SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE},
    {false, SPDM_MEASUREMENTS, SPDM_MEASUREMENTS_SIGN_CONTEXT, SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE,
     36 - SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE},
    {false, SPDM_KEY_EXCHANGE_RSP, SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT,
     SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE,
     36 - SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE},
    {true, SPDM_FINISH, SPDM_FINISH_SIGN_CONTEXT, SPDM_FINISH_SIGN_CONTEXT_SIZE,
     36 - SPDM_FINISH_SIGN_CONTEXT_SIZE},
};

#if LIBSPDM_RSA_SSA_SUPPORT
static bool libspdm_rsa_pkcs1_sign_with_nid_wrap (void *context, size_t hash_nid,
                                                  const uint8_t *param, size_t param_size,
                                                  const uint8_t *message,
                                                  size_t message_size, uint8_t *signature,
                                                  size_t *sig_size)
{
    return libspdm_rsa_pkcs1_sign_with_nid (context, hash_nid,
                                            message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_RSA_PSS_SUPPORT
static bool libspdm_rsa_pss_sign_wrap (void *context, size_t hash_nid,
                                       const uint8_t *param, size_t param_size,
                                       const uint8_t *message,
                                       size_t message_size, uint8_t *signature,
                                       size_t *sig_size)
{
    return libspdm_rsa_pss_sign (context, hash_nid,
                                 message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_ECDSA_SUPPORT
static bool libspdm_ecdsa_sign_wrap (void *context, size_t hash_nid,
                                     const uint8_t *param, size_t param_size,
                                     const uint8_t *message,
                                     size_t message_size, uint8_t *signature,
                                     size_t *sig_size)
{
    return libspdm_ecdsa_sign (context, hash_nid,
                               message, message_size, signature, sig_size);
}
#endif

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
static bool libspdm_eddsa_sign_wrap (void *context, size_t hash_nid,
                                     const uint8_t *param, size_t param_size,
                                     const uint8_t *message,
                                     size_t message_size, uint8_t *signature,
                                     size_t *sig_size)
{
    return libspdm_eddsa_sign (context, hash_nid, param, param_size,
                               message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_SM2_DSA_SUPPORT
static bool libspdm_sm2_dsa_sign_wrap (void *context, size_t hash_nid,
                                       const uint8_t *param, size_t param_size,
                                       const uint8_t *message,
                                       size_t message_size, uint8_t *signature,
                                       size_t *sig_size)
{
    return libspdm_sm2_dsa_sign (context, hash_nid, param, param_size,
                                 message, message_size, signature, sig_size);
}
#endif

/**
 * Get the SPDM signing context string, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  context_size                         SPDM signing context size
 **/
static const void *libspdm_get_signing_context_string (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    size_t *context_size)
{
    size_t index;

    /* It is introduced in SPDM 1.2*/
    LIBSPDM_ASSERT((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_signing_context_str_table); index++) {
        if (m_libspdm_signing_context_str_table[index].is_requester == is_requester &&
            m_libspdm_signing_context_str_table[index].op_code == op_code) {
            *context_size = m_libspdm_signing_context_str_table[index].context_size;
            return m_libspdm_signing_context_str_table[index].context;
        }
    }
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Create SPDM signing context, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  spdm_signing_context                 SPDM signing context
 **/
static void libspdm_create_signing_context (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    void *spdm_signing_context)
{
    size_t index;
    char *context_str;

    /* It is introduced in SPDM 1.2*/
    LIBSPDM_ASSERT((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11);

    /* So far, it only leaves 1 bytes for version*/
    LIBSPDM_ASSERT((((spdm_version >> 12) & 0xF) < 10) &&
                   (((spdm_version >> 8) & 0xF) < 10));

    context_str = spdm_signing_context;
    for (index = 0; index < 4; index++) {
        libspdm_copy_mem(context_str,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE);
        /* patch the version*/
        context_str[11] = (char)('0' + ((spdm_version >> 12) & 0xF));
        context_str[13] = (char)('0' + ((spdm_version >> 8) & 0xF));
        context_str[15] = (char)('*');
        context_str += SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE;
    }
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_signing_context_str_table); index++) {
        if (m_libspdm_signing_context_str_table[index].is_requester == is_requester &&
            m_libspdm_signing_context_str_table[index].op_code == op_code) {
            libspdm_zero_mem (
                context_str,
                m_libspdm_signing_context_str_table[index].zero_pad_size);
            libspdm_copy_mem(context_str + m_libspdm_signing_context_str_table[index].zero_pad_size,
                             m_libspdm_signing_context_str_table[index].context_size,
                             m_libspdm_signing_context_str_table[index].context,
                             m_libspdm_signing_context_str_table[index].context_size);
            return;
        }
    }
    LIBSPDM_ASSERT(false);
}

uint32_t libspdm_get_asym_signature_size(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return 256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return 384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return 512;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return 48 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return 66 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return 57 * 2;
    default:
        return 0;
    }
}

/**
 * Return asymmetric sign function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric sign function
 **/
static libspdm_asym_sign_func libspdm_get_asym_sign(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT
        return libspdm_rsa_pkcs1_sign_with_nid_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT
        return libspdm_rsa_pss_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ecdsa_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_eddsa_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_dsa_sign_wrap;
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

/**
 * Return asymmetric free function, based upon the negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric free function
 **/
static libspdm_asym_free_func libspdm_get_asym_free(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        return libspdm_rsa_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ec_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_ecd_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_dsa_free;
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

void libspdm_asym_free(uint32_t base_asym_algo, void *context)
{
    libspdm_asym_free_func free_function;
    free_function = libspdm_get_asym_free(base_asym_algo);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return asymmetric GET_PUBLIC_KEY_FROM_DER function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo  SPDM base_asym_algo
 *
 * @return asymmetric GET_PUBLIC_KEY_FROM_DER function
 **/
static libspdm_asym_get_public_key_from_der_func
libspdm_get_asym_get_public_key_from_der(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        return libspdm_rsa_get_public_key_from_der;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ec_get_public_key_from_der;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_ecd_get_public_key_from_der;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_get_public_key_from_der;
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

bool libspdm_asym_get_public_key_from_der(uint32_t base_asym_algo,
                                          const uint8_t *der_data,
                                          size_t der_size,
                                          void **context)
{
    libspdm_asym_get_public_key_from_der_func asym_get_public_key_from_der;
    asym_get_public_key_from_der = libspdm_get_asym_get_public_key_from_der(base_asym_algo);
    if (asym_get_public_key_from_der == NULL) {
        return false;
    }
    return asym_get_public_key_from_der(der_data, der_size, context);
}

/**
 * Return if asymmetric function need message hash.
 *
 * @param  base_asym_algo               SPDM base_asym_algo
 *
 * @retval true  asymmetric function need message hash
 * @retval false asymmetric function need raw message
 **/
static bool libspdm_asym_func_need_hash(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return true;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return true;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return false;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return false;
}

#if LIBSPDM_RSA_SSA_SUPPORT
static bool libspdm_rsa_pkcs1_verify_with_nid_wrap (void *context, size_t hash_nid,
                                                    const uint8_t *param, size_t param_size,
                                                    const uint8_t *message,
                                                    size_t message_size,
                                                    const uint8_t *signature,
                                                    size_t sig_size)
{
    return libspdm_rsa_pkcs1_verify_with_nid (context, hash_nid,
                                              message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_RSA_PSS_SUPPORT
static bool libspdm_rsa_pss_verify_wrap (void *context, size_t hash_nid,
                                         const uint8_t *param, size_t param_size,
                                         const uint8_t *message,
                                         size_t message_size,
                                         const uint8_t *signature,
                                         size_t sig_size)
{
    return libspdm_rsa_pss_verify (context, hash_nid, message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_ECDSA_SUPPORT
bool libspdm_ecdsa_verify_wrap (void *context, size_t hash_nid,
                                const uint8_t *param, size_t param_size,
                                const uint8_t *message,
                                size_t message_size,
                                const uint8_t *signature,
                                size_t sig_size)
{
    return libspdm_ecdsa_verify (context, hash_nid, message, message_size, signature, sig_size);
}
#endif

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
bool libspdm_eddsa_verify_wrap (void *context, size_t hash_nid,
                                const uint8_t *param, size_t param_size,
                                const uint8_t *message,
                                size_t message_size,
                                const uint8_t *signature,
                                size_t sig_size)
{
    return libspdm_eddsa_verify (context, hash_nid, param, param_size,
                                 message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_SM2_DSA_SUPPORT
bool libspdm_sm2_dsa_verify_wrap (void *context, size_t hash_nid,
                                  const uint8_t *param, size_t param_size,
                                  const uint8_t *message,
                                  size_t message_size,
                                  const uint8_t *signature,
                                  size_t sig_size)
{
    return libspdm_sm2_dsa_verify (context, hash_nid, param, param_size,
                                   message, message_size, signature, sig_size);
}
#endif

/**
 * Return asymmetric verify function, based upon the negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric verify function
 **/
static libspdm_asym_verify_func libspdm_get_asym_verify(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT
        return libspdm_rsa_pkcs1_verify_with_nid_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT
        return libspdm_rsa_pss_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ecdsa_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_eddsa_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_dsa_verify_wrap;
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

bool libspdm_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, const uint8_t *signature,
    size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    verify_function = libspdm_get_asym_verify(base_asym_algo);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        return verify_function(context, hash_nid, param, param_size, message, message_size,
                               signature, sig_size);
    }
}

bool libspdm_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, const uint8_t *signature,
    size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    verify_function = libspdm_get_asym_verify(base_asym_algo);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return verify_function(context, hash_nid, param, param_size, full_message_hash,
                                   hash_size, signature, sig_size);
        } else {
            return verify_function(context, hash_nid, param, param_size, message, message_size,
                                   signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    asym_sign = libspdm_get_asym_sign(base_asym_algo);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        return asym_sign(context, hash_nid, param, param_size, message, message_size,
                         signature, sig_size);
    }
}

bool libspdm_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, uint8_t *signature,
    size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    asym_sign = libspdm_get_asym_sign(base_asym_algo);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return asym_sign(context, hash_nid, param, param_size, full_message_hash, hash_size,
                             signature, sig_size);
        } else {
            return asym_sign(context, hash_nid, param, param_size, message, message_size,
                             signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

uint32_t libspdm_get_req_asym_signature_size(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_signature_size(req_base_asym_alg);
}

/**
 * Return requester asymmetric free function, based upon the negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return requester asymmetric free function
 **/
static libspdm_asym_free_func libspdm_get_req_asym_free(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_free(req_base_asym_alg);
}

void libspdm_req_asym_free(uint16_t req_base_asym_alg, void *context)
{
    libspdm_asym_free_func free_function;
    free_function = libspdm_get_req_asym_free(req_base_asym_alg);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return asymmetric GET_PUBLIC_KEY_FROM_DER function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg  SPDM req_base_asym_alg
 *
 * @return asymmetric GET_PUBLIC_KEY_FROM_DER function
 **/
static libspdm_asym_get_public_key_from_der_func
libspdm_get_req_asym_get_public_key_from_der(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_get_public_key_from_der(req_base_asym_alg);
}

bool libspdm_req_asym_get_public_key_from_der(uint16_t req_base_asym_alg,
                                              const uint8_t *der_data,
                                              size_t der_size,
                                              void **context)
{
    libspdm_asym_get_public_key_from_der_func asym_get_public_key_from_der;
    asym_get_public_key_from_der =
        libspdm_get_req_asym_get_public_key_from_der(req_base_asym_alg);
    if (asym_get_public_key_from_der == NULL) {
        return false;
    }
    return asym_get_public_key_from_der(der_data, der_size, context);
}

bool libspdm_req_asym_func_need_hash(uint16_t req_base_asym_alg)
{
    return libspdm_asym_func_need_hash(req_base_asym_alg);
}

/**
 * Return requester asymmetric verify function, based upon the negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return requester asymmetric verify function
 **/
static libspdm_asym_verify_func libspdm_get_req_asym_verify(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_verify(req_base_asym_alg);
}

bool libspdm_req_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);

    verify_function = libspdm_get_req_asym_verify(req_base_asym_alg);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        return verify_function(context, hash_nid, param, param_size, message, message_size,
                               signature, sig_size);
    }
}

bool libspdm_req_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    const uint8_t *signature, size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    verify_function = libspdm_get_req_asym_verify(req_base_asym_alg);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return verify_function(context, hash_nid, param, param_size, full_message_hash,
                                   hash_size, signature, sig_size);
        } else {
            return verify_function(context, hash_nid, param, param_size, message, message_size,
                                   signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

/**
 * Return asymmetric sign function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return asymmetric sign function
 **/
static libspdm_asym_sign_func libspdm_get_req_asym_sign(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_sign(req_base_asym_alg);
}

bool libspdm_req_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);

    asym_sign = libspdm_get_req_asym_sign(req_base_asym_alg);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        return asym_sign(context, hash_nid, param, param_size, message, message_size,
                         signature, sig_size);
    }
}

bool libspdm_req_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    uint8_t *signature, size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    asym_sign = libspdm_get_req_asym_sign(req_base_asym_alg);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return asym_sign(context, hash_nid, param, param_size, full_message_hash, hash_size,
                             signature, sig_size);
        } else {
            return asym_sign(context, hash_nid, param, param_size, message, message_size,
                             signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}
