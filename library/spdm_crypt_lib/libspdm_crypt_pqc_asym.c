/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "library/spdm_common_lib.h"

uint32_t libspdm_get_pqc_asym_signature_size(uint32_t pqc_asym_algo)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
#if LIBSPDM_ML_DSA_44_SUPPORT
        return 2420;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
#if LIBSPDM_ML_DSA_65_SUPPORT
        return 3309;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_87_SUPPORT
        return 4627;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
#if LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT
        return 7856;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
#if LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT
        return 7856;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
#if LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT
        return 17088;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
#if LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT
        return 17088;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
#if LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT
        return 16224;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
#if LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT
        return 16224;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
#if LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT
        return 35664;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
#if LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT
        return 35664;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
#if LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT
        return 29792;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
#if LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT
        return 29792;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
#if LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT
        return 49856;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT
        return 49856;
#else
        return 0;
#endif
    default:
        return 0;
    }
}

bool libspdm_pqc_asym_get_public_key_from_x509(uint32_t pqc_asym_algo,
                                               const uint8_t *cert,
                                               size_t cert_size,
                                               void **context)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        return libspdm_mldsa_get_public_key_from_x509(cert, cert_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        return libspdm_slhdsa_get_public_key_from_x509(cert, cert_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_pqc_asym_get_public_key_from_der(uint32_t pqc_asym_algo,
                                              const uint8_t *der_data,
                                              size_t der_size,
                                              void **context)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        return libspdm_mldsa_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        return libspdm_slhdsa_get_public_key_from_der(der_data, der_size, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

void libspdm_pqc_asym_free(uint32_t pqc_asym_algo, void *context)
{
    if (context == NULL) {
        return;
    }
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        libspdm_mldsa_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        libspdm_slhdsa_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }
    return;
}

static bool libspdm_pqc_asym_sign_wrap (
    void *context, uint32_t pqc_asym_algo,
    const uint8_t *param, size_t param_size,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        return libspdm_mldsa_sign(context,
                                  param, param_size,
                                  message, message_size,
                                  signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        return libspdm_slhdsa_sign(context,
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

static bool libspdm_pqc_asym_verify_wrap(
    void *context, uint32_t pqc_asym_algo,
    const uint8_t *param, size_t param_size,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        return libspdm_mldsa_verify(context,
                                    param, param_size,
                                    message, message_size,
                                    signature, sig_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        return libspdm_slhdsa_verify(context,
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

bool libspdm_pqc_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t pqc_asym_algo, uint32_t base_hash_algo,
    void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    size_t hash_size;
    bool result;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);

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

    result = libspdm_pqc_asym_verify_wrap(context, pqc_asym_algo,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size);
    return result;
}

bool libspdm_pqc_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t pqc_asym_algo, uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    const uint8_t *signature, size_t sig_size)
{
    uint8_t *message;
    size_t message_size;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);

    libspdm_create_signing_context (spdm_version, op_code, false,
                                    spdm12_signing_context_with_hash);
    libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                     sizeof(spdm12_signing_context_with_hash) -
                     SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE,
                     message_hash, hash_size);

    /* assign message and message_size for signing */
    message = spdm12_signing_context_with_hash;
    message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

    return libspdm_pqc_asym_verify_wrap(context, pqc_asym_algo,
                                        param, param_size,
                                        message, message_size,
                                        signature, sig_size);
}

bool libspdm_pqc_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t pqc_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
    size_t hash_size;
    bool result;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);

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

    return libspdm_pqc_asym_sign_wrap(context, pqc_asym_algo,
                                      param, param_size,
                                      message, message_size,
                                      signature, sig_size);
}

bool libspdm_pqc_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t pqc_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, uint8_t *signature,
    size_t *sig_size)
{
    uint8_t *message;
    size_t message_size;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);

    libspdm_create_signing_context (spdm_version, op_code, false,
                                    spdm12_signing_context_with_hash);
    libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                     sizeof(spdm12_signing_context_with_hash) -
                     SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE,
                     message_hash, hash_size);

    /* assign message and message_size for signing */
    message = spdm12_signing_context_with_hash;
    message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

    return libspdm_pqc_asym_sign_wrap(context, pqc_asym_algo,
                                      param, param_size,
                                      message, message_size,
                                      signature, sig_size);

}

uint32_t libspdm_get_req_pqc_asym_signature_size(uint32_t req_pqc_asym_alg)
{
    return libspdm_get_pqc_asym_signature_size(req_pqc_asym_alg);
}

bool libspdm_req_pqc_asym_get_public_key_from_x509(uint32_t pqc_asym_algo,
                                                   const uint8_t *cert,
                                                   size_t cert_size,
                                                   void **context)
{
    return libspdm_pqc_asym_get_public_key_from_x509(
        pqc_asym_algo, cert, cert_size, context);
}

bool libspdm_req_pqc_asym_get_public_key_from_der(uint32_t req_pqc_asym_alg,
                                                  const uint8_t *der_data,
                                                  size_t der_size,
                                                  void **context)
{
    return libspdm_pqc_asym_get_public_key_from_der(
        req_pqc_asym_alg, der_data, der_size, context);
}

void libspdm_req_pqc_asym_free(uint32_t req_pqc_asym_alg, void *context)
{
    libspdm_pqc_asym_free(req_pqc_asym_alg, context);
}

bool libspdm_req_pqc_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    size_t hash_size;
    bool result;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);

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
    result = libspdm_pqc_asym_verify_wrap(context, req_pqc_asym_alg,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size);

    return result;
}

bool libspdm_req_pqc_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    const uint8_t *signature, size_t sig_size)
{
    uint8_t *message;
    size_t message_size;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);

    libspdm_create_signing_context (spdm_version, op_code, true,
                                    spdm12_signing_context_with_hash);
    libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                     sizeof(spdm12_signing_context_with_hash) -
                     SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE,
                     message_hash, hash_size);

    /* assign message and message_size for signing */
    message = spdm12_signing_context_with_hash;
    message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

    return libspdm_pqc_asym_verify_wrap(context, req_pqc_asym_alg,
                                        param, param_size,
                                        message, message_size,
                                        signature, sig_size);
}

bool libspdm_req_pqc_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    size_t hash_size;
    bool result;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);

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

    return libspdm_pqc_asym_sign_wrap(context, req_pqc_asym_alg,
                                      param, param_size,
                                      message, message_size,
                                      signature, sig_size);
}

bool libspdm_req_pqc_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    uint8_t *signature, size_t *sig_size)
{
    uint8_t *message;
    size_t message_size;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);

    libspdm_create_signing_context (spdm_version, op_code, true,
                                    spdm12_signing_context_with_hash);
    libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                     sizeof(spdm12_signing_context_with_hash) -
                     SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE,
                     message_hash, hash_size);

    /* assign message and message_size for signing */
    message = spdm12_signing_context_with_hash;
    message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

    return libspdm_pqc_asym_sign_wrap(context, req_pqc_asym_alg,
                                      param, param_size,
                                      message, message_size,
                                      signature, sig_size);
}
