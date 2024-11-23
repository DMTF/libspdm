/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_lib_config.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "hal/library/cryptlib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  pqc_asym_algo   SPDM pqc_asym_algo
 * @param  pem_data        Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size        Size of the PEM key data in bytes.
 * @param  password        NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context         Pointer to newly generated asymmetric context which contain the retrieved
 *                         private key component.
 *                         Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_pqc_asym_get_private_key_from_pem(uint32_t pqc_asym_algo,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        return libspdm_mldsa_get_private_key_from_pem(pem_data, pem_size, password, context);
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
        return libspdm_slhdsa_get_private_key_from_pem(pem_data, pem_size, password, context);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}
/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_pqc_asym_alg   SPDM req_pqc_asym_alg
 * @param  pem_data           Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size           Size of the PEM key data in bytes.
 * @param  password           NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context            Pointer to newly generated asymmetric context which contain the
 *                            retrieved private key component. Use libspdm_asym_free() function to
 *                            free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_pqc_asym_get_private_key_from_pem(uint32_t req_pqc_asym_alg,
                                                   const uint8_t *pem_data,
                                                   size_t pem_size,
                                                   const char *password,
                                                   void **context)
{
    return libspdm_pqc_asym_get_private_key_from_pem (
        req_pqc_asym_alg,
        pem_data, pem_size,
        password, context);
}

size_t libspdm_get_pqc_aysm_nid(uint32_t pqc_asym_algo)
{
    switch (pqc_asym_algo)
    {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        return LIBSPDM_CRYPTO_NID_ML_DSA_44;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        return LIBSPDM_CRYPTO_NID_ML_DSA_65;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        return LIBSPDM_CRYPTO_NID_ML_DSA_87;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}
