/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

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
#if LIBSPDM_RSA_SSA_2048_SUPPORT
        return 256;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
#if LIBSPDM_RSA_PSS_2048_SUPPORT
        return 256;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
#if LIBSPDM_RSA_SSA_3072_SUPPORT
        return 384;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
#if LIBSPDM_RSA_PSS_3072_SUPPORT
        return 384;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_4096_SUPPORT
        return 512;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_4096_SUPPORT
        return 512;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
#if LIBSPDM_ECDSA_P256_SUPPORT
        return 32 * 2;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
#if LIBSPDM_ECDSA_P384_SUPPORT
        return 48 * 2;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_P521_SUPPORT
        return 66 * 2;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_P256_SUPPORT
        return 32 * 2;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
#if LIBSPDM_EDDSA_ED25519_SUPPORT
        return 32 * 2;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if LIBSPDM_EDDSA_ED448_SUPPORT
        return 57 * 2;
#else
        return 0;
#endif
    default:
        return 0;
    }
}

static bool libspdm_asym_sign_wrap (void *context, size_t hash_nid, uint32_t base_asym_algo,
                                    const uint8_t *param, size_t param_size,
                                    const uint8_t *message, size_t message_size,
                                    uint8_t *signature, size_t *sig_size)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT
#if !LIBSPDM_RSA_SSA_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048);
#endif
#if !LIBSPDM_RSA_SSA_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072);
#endif
#if !LIBSPDM_RSA_SSA_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096);
#endif
        return libspdm_rsa_pkcs1_sign_with_nid_wrap(context, hash_nid,
                                                    param, param_size,
                                                    message, message_size,
                                                    signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT
#if !LIBSPDM_RSA_PSS_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048);
#endif
#if !LIBSPDM_RSA_PSS_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072);
#endif
#if !LIBSPDM_RSA_PSS_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096);
#endif
        return libspdm_rsa_pss_sign_wrap(context, hash_nid,
                                         param, param_size,
                                         message, message_size,
                                         signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
#if !LIBSPDM_ECDSA_P256_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256);
#endif
#if !LIBSPDM_ECDSA_P384_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
#endif
#if !LIBSPDM_ECDSA_P521_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
#endif
        return libspdm_ecdsa_sign_wrap(context, hash_nid,
                                       param, param_size,
                                       message, message_size,
                                       signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
#if !LIBSPDM_EDDSA_ED25519_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519);
#endif
#if !LIBSPDM_EDDSA_ED448_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
#endif
        return libspdm_eddsa_sign_wrap(context, hash_nid,
                                       param, param_size,
                                       message, message_size,
                                       signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_dsa_sign_wrap(context, hash_nid,
                                         param, param_size,
                                         message, message_size,
                                         signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

void libspdm_asym_free(uint32_t base_asym_algo, void *context)
{
    if (context == NULL) {
        return;
    }
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        libspdm_rsa_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        libspdm_ec_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        libspdm_ecd_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        libspdm_sm2_dsa_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }
}

static bool libspdm_asym_get_public_key_from_der_wrap(uint32_t base_asym_algo,
                                                      const uint8_t *der_data,
                                                      size_t der_size,
                                                      void **context)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
#if !LIBSPDM_RSA_SSA_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048);
#endif
#if !LIBSPDM_RSA_SSA_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072);
#endif
#if !LIBSPDM_RSA_SSA_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096);
#endif
#if !LIBSPDM_RSA_PSS_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048);
#endif
#if !LIBSPDM_RSA_PSS_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072);
#endif
#if !LIBSPDM_RSA_PSS_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096);
#endif
        return libspdm_rsa_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
#if !LIBSPDM_ECDSA_P256_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256);
#endif
#if !LIBSPDM_ECDSA_P384_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
#endif
#if !LIBSPDM_ECDSA_P521_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
#endif
        return libspdm_ec_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_ecd_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
#if !LIBSPDM_EDDSA_ED25519_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519);
#endif
#if !LIBSPDM_EDDSA_ED448_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
#endif
        return libspdm_sm2_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_asym_get_public_key_from_der(uint32_t base_asym_algo,
                                          const uint8_t *der_data,
                                          size_t der_size,
                                          void **context)
{
    return libspdm_asym_get_public_key_from_der_wrap(base_asym_algo,
                                                     der_data,
                                                     der_size,
                                                     context);
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

static void libspdm_copy_signature_swap_endian(
    uint8_t *endian_swapped_signature_buffer,
    size_t   endian_swapped_signature_buffer_size,
    bool is_dual_buffer,
    const uint8_t *signature,
    size_t sig_size)
{
    LIBSPDM_ASSERT(endian_swapped_signature_buffer_size >= sig_size);

    size_t i;

    if (is_dual_buffer) {
        /* ECDSA signature is actually 2 buffers and each must be swapped individually */

        size_t buf_size;
        const uint8_t* buf;

        buf_size = sig_size / 2;
        buf = signature;
        for (i = 0; i < buf_size; i++) {
            /* Copy the first buffer endian swapped */
            endian_swapped_signature_buffer[i] = buf[buf_size - i - 1];
            /* Copy the second buffer endian swapped */
            endian_swapped_signature_buffer[i + buf_size] = buf[2 * buf_size - i - 1];
        }

    } else {
        /* RSA signature is a single buffer to be swapped */
        for (i = 0; i < sig_size; i++) {
            endian_swapped_signature_buffer[i] = signature[sig_size - i - 1];
        }
    }
}

static bool libspdm_asym_verify_wrap(
    void *context, size_t hash_nid, uint32_t base_asym_algo,
    const uint8_t *param, size_t param_size,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size, bool try_endian_swapped_signature)
{
    bool result;
    uint8_t endian_swapped_signature[LIBSPDM_MAX_ASYM_SIG_SIZE];

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT
#if !LIBSPDM_RSA_SSA_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048);
#endif
#if !LIBSPDM_RSA_SSA_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072);
#endif
#if !LIBSPDM_RSA_SSA_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096);
#endif
        result = libspdm_rsa_pkcs1_verify_with_nid_wrap(context, hash_nid,
                                                        param, param_size,
                                                        message, message_size,
                                                        signature, sig_size);
        if (!result && try_endian_swapped_signature) {
            libspdm_copy_signature_swap_endian(endian_swapped_signature,
                                               sizeof(endian_swapped_signature),
                                               false, signature, sig_size);

            result = libspdm_rsa_pkcs1_verify_with_nid_wrap(context, hash_nid,
                                                            param, param_size,
                                                            message, message_size,
                                                            endian_swapped_signature, sig_size);
        }

        return result;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT
#if !LIBSPDM_RSA_PSS_2048_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048);
#endif
#if !LIBSPDM_RSA_PSS_3072_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072);
#endif
#if !LIBSPDM_RSA_PSS_4096_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096);
#endif
        result = libspdm_rsa_pss_verify_wrap(context, hash_nid,
                                             param, param_size,
                                             message, message_size,
                                             signature, sig_size);
        if (!result && try_endian_swapped_signature) {
            libspdm_copy_signature_swap_endian(endian_swapped_signature,
                                               sizeof(endian_swapped_signature),
                                               false, signature, sig_size);

            result = libspdm_rsa_pss_verify_wrap(context, hash_nid,
                                                 param, param_size,
                                                 message, message_size,
                                                 endian_swapped_signature, sig_size);
        }
        return result;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
#if !LIBSPDM_ECDSA_P256_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256);
#endif
#if !LIBSPDM_ECDSA_P384_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
#endif
#if !LIBSPDM_ECDSA_P521_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
#endif
        result = libspdm_ecdsa_verify_wrap(context, hash_nid,
                                           param, param_size,
                                           message, message_size,
                                           signature, sig_size);
        if (!result && try_endian_swapped_signature) {
            libspdm_copy_signature_swap_endian(endian_swapped_signature,
                                               sizeof(endian_swapped_signature),
                                               true, signature, sig_size);

            result = libspdm_ecdsa_verify_wrap(context, hash_nid,
                param, param_size,
                message, message_size,
                signature, sig_size);
        }
        return result;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
#if !LIBSPDM_EDDSA_ED25519_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519);
#endif
#if !LIBSPDM_EDDSA_ED448_SUPPORT
        LIBSPDM_ASSERT(base_asym_algo!= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
#endif
        return libspdm_eddsa_verify_wrap(context, hash_nid,
                                         param, param_size,
                                         message, message_size,
                                         signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_dsa_verify_wrap(context, hash_nid,
                                           param, param_size,
                                           message, message_size,
                                           signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_try_endian_swapped_signature(
    spdm_version_number_t spdm_version, uint32_t base_asym_algo)
{
    bool try_swap = false;
#if LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_DUAL_ENDIAN_RSA_ECDSA

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) == SPDM_MESSAGE_VERSION_10) {
        try_swap |=
            (LIBSPDM_SPDM_10_VERIFY_SIGNATURE_DUAL_ENDIAN_RSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
        try_swap |=
            (LIBSPDM_SPDM_10_VERIFY_SIGNATURE_DUAL_ENDIAN_ECDSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
    }

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) == SPDM_MESSAGE_VERSION_11) {
        try_swap |=
            (LIBSPDM_SPDM_11_VERIFY_SIGNATURE_DUAL_ENDIAN_RSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
        try_swap |=
            (LIBSPDM_SPDM_11_VERIFY_SIGNATURE_DUAL_ENDIAN_ECDSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
    }
#endif /* LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_DUAL_ENDIAN_RSA_ECDSA */
    return try_swap;
}

bool libspdm_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, const uint8_t *signature,
    size_t sig_size)
{
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;
    bool try_endian_swapped_signature;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing. */
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

        /* re-assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru */
    }

    try_endian_swapped_signature
        = libspdm_try_endian_swapped_signature(spdm_version, base_asym_algo);

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size, message_hash);
        if (!result) {
            return false;
        }
        result = libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          message_hash, hash_size,
                                          signature, sig_size,
                                          try_endian_swapped_signature);
    } else {
        result = libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size,
                                          try_endian_swapped_signature);
    }

    return result;
}

bool libspdm_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, const uint8_t *signature,
    size_t sig_size)
{
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
    bool try_endian_swapped_signature;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size, full_message_hash);
            if (!result) {
                return false;
            }
            return libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                            param, param_size,
                                            full_message_hash, hash_size,
                                            signature, sig_size,
                                            false);
        } else {
            return libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                            param, param_size,
                                            message, message_size,
                                            signature, sig_size,
                                            false);
        }

        /* SPDM 1.2 signing done. */
    }

    if (need_hash) {
        try_endian_swapped_signature
            = libspdm_try_endian_swapped_signature(spdm_version, base_asym_algo);

        return libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                        param, param_size,
                                        message_hash, hash_size,
                                        signature, sig_size,
                                        try_endian_swapped_signature);
    } else {
        LIBSPDM_ASSERT(false);
        return false;
    }
}

void libspdm_asym_signature_swap_endian_if_necessary(
    spdm_version_number_t spdm_version, uint32_t base_asym_algo,
    uint8_t *signature, size_t sig_size)
{
#if LIBSPDM_SPDM_10_11_SIGN_LITTLE_ENDIAN_RSA_ECDSA
    uint32_t swap_endian_rsa = 0;
    uint32_t swap_endian_ecdsa = 0;
    size_t i;
    uint8_t byte;

#if LIBSPDM_SPDM_10_SIGN_LITTLE_ENDIAN_RSA || LIBSPDM_SPDM_10_SIGN_LITTLE_ENDIAN_ECDSA
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) == SPDM_MESSAGE_VERSION_10) {
        swap_endian_rsa =
            (LIBSPDM_SPDM_10_SIGN_LITTLE_ENDIAN_RSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
        swap_endian_ecdsa =
            (LIBSPDM_SPDM_10_SIGN_LITTLE_ENDIAN_RSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
    }
#endif

#if LIBSPDM_SPDM_11_SIGN_LITTLE_ENDIAN_RSA || LIBSPDM_SPDM_11_SIGN_LITTLE_ENDIAN_ECDSA
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) == SPDM_MESSAGE_VERSION_11) {
        swap_endian_rsa =
            (LIBSPDM_SPDM_11_SIGN_LITTLE_ENDIAN_RSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSA_ALL));
        swap_endian_ecdsa =
            (LIBSPDM_SPDM_11_SIGN_LITTLE_ENDIAN_ECDSA &&
             (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ALL));
    }
#endif
    if (swap_endian_rsa) {
        /* RSA signature is a single buffer to be swapped */

        for (i = 0; i < sig_size / 2; i++) {
            byte = signature[i];
            signature[i] = signature[sig_size - i - 1];
            signature[sig_size - i - 1] = byte;
        }
    } else if (swap_endian_ecdsa) {
        /* ECDSA signature is actually 2 buffers and each must be swapped individually */
        size_t buf_size;
        uint8_t* buf;

        buf_size = sig_size / 2;
        buf = signature;
        for (i = 0; i < buf_size / 2; i++) {
            byte = buf[i];
            buf[i] = buf[buf_size - i - 1];
            buf[buf_size - i - 1] = byte;
        }

        buf = signature + buf_size;
        for (i = 0; i < buf_size / 2; i++) {
            byte = buf[i];
            buf[i] = buf[buf_size - i - 1];
            buf[buf_size - i - 1] = byte;
        }
    }

#endif /* LIBSPDM_SPDM_10_11_SIGN_LITTLE_ENDIAN_RSA_ECDSA */
}

bool libspdm_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
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

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* re-assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/
    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size, message_hash);
        if (!result) {
            return false;
        }
        result = libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                        param, param_size,
                                        message_hash, hash_size,
                                        signature, sig_size);
    } else {
        result = libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                        param, param_size,
                                        message, message_size,
                                        signature, sig_size);
    }
    libspdm_asym_signature_swap_endian_if_necessary(spdm_version, base_asym_algo,
                                                    signature, *sig_size);
    return result;
}

bool libspdm_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, uint8_t *signature,
    size_t *sig_size)
{
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

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size, full_message_hash);
            if (!result) {
                return false;
            }
            return libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          full_message_hash, hash_size,
                                          signature, sig_size);
        } else {
            return libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size);
        }

        /* SPDM 1.2 signing done. */
    }

    if (need_hash) {
        result = libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                        param, param_size,
                                        message_hash, hash_size,
                                        signature, sig_size);
        libspdm_asym_signature_swap_endian_if_necessary(spdm_version, base_asym_algo,
                                                        signature, *sig_size);
        return result;
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

uint32_t libspdm_get_req_asym_signature_size(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_signature_size(req_base_asym_alg);
}

void libspdm_req_asym_free(uint16_t req_base_asym_alg, void *context)
{
    libspdm_asym_free(req_base_asym_alg, context);
}

bool libspdm_req_asym_get_public_key_from_der(uint16_t req_base_asym_alg,
                                              const uint8_t *der_data,
                                              size_t der_size,
                                              void **context)
{
    return libspdm_asym_get_public_key_from_der_wrap(req_base_asym_alg,
                                                     der_data,
                                                     der_size,
                                                     context);
}

bool libspdm_req_asym_func_need_hash(uint16_t req_base_asym_alg)
{
    return libspdm_asym_func_need_hash(req_base_asym_alg);
}

bool libspdm_req_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;
    bool try_endian_swapped_signature;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* re-assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru */
    }

    try_endian_swapped_signature =
        libspdm_try_endian_swapped_signature(spdm_version, req_base_asym_alg);

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size, message_hash);
        if (!result) {
            return false;
        }
        return libspdm_asym_verify_wrap(context, hash_nid, req_base_asym_alg,
                                        param, param_size,
                                        message_hash, hash_size,
                                        signature, sig_size,
                                        try_endian_swapped_signature);
    } else {
        return libspdm_asym_verify_wrap(context, hash_nid, req_base_asym_alg,
                                        param, param_size,
                                        message, message_size,
                                        signature, sig_size,
                                        try_endian_swapped_signature);
    }
}

bool libspdm_req_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    const uint8_t *signature, size_t sig_size)
{
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
    bool try_endian_swapped_signature;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return libspdm_asym_verify_wrap(context, hash_nid, req_base_asym_alg,
                                            param, param_size,
                                            full_message_hash, hash_size,
                                            signature, sig_size, false);
        } else {
            return libspdm_asym_verify_wrap(context, hash_nid, req_base_asym_alg,
                                            param, param_size,
                                            message, message_size,
                                            signature, sig_size, false);
        }
        /* SPDM 1.2 signing done. */
    }

    if (need_hash) {
        try_endian_swapped_signature =
            libspdm_try_endian_swapped_signature(spdm_version, req_base_asym_alg);

        return libspdm_asym_verify_wrap(context, hash_nid, req_base_asym_alg,
                                        param, param_size,
                                        message_hash, hash_size,
                                        signature, sig_size,
                                        try_endian_swapped_signature);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

bool libspdm_req_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
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

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* re-assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru */
    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return libspdm_asym_sign_wrap(context, hash_nid, req_base_asym_alg,
                                      param, param_size,
                                      message_hash, hash_size,
                                      signature, sig_size);
    } else {
        return libspdm_asym_sign_wrap(context, hash_nid, req_base_asym_alg,
                                      param, param_size,
                                      message, message_size,
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

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {
        /* Need use SPDM 1.2 signing */
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

        /* assign message and message_size for signing */
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return libspdm_asym_sign_wrap(context, hash_nid, req_base_asym_alg,
                                          param, param_size,
                                          full_message_hash, hash_size,
                                          signature, sig_size);
        } else {
            return libspdm_asym_sign_wrap(context, hash_nid, req_base_asym_alg,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size);
        }

        /* SPDM 1.2 signing done. */
    }

    if (need_hash) {
        return libspdm_asym_sign_wrap(context, hash_nid, req_base_asym_alg,
                                      param, param_size,
                                      message_hash, hash_size,
                                      signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}
