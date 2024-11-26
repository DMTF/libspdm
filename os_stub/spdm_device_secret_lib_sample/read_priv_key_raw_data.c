/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "raw_data_key.h"
#include "internal/libspdm_common_lib.h"

/* "g_private_key_mode = 1" means use the PEM mode
 * "g_private_key_mode = 0" means use the RAW mode
 **/
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool g_private_key_mode = 1;
#endif

#if LIBSPDM_ECDSA_SUPPORT
uint8_t m_libspdm_ec256_responder_private_key[] = LIBSPDM_EC256_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec256_responder_public_key[] = LIBSPDM_EC256_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec384_responder_private_key[] = LIBSPDM_EC384_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec384_responder_public_key[] = LIBSPDM_EC384_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec521_responder_private_key[] = LIBSPDM_EC521_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec521_responder_public_key[] = LIBSPDM_EC521_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec256_requester_private_key[] = LIBSPDM_EC256_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec256_requester_public_key[] = LIBSPDM_EC256_REQUESTER_PUBLIC_KEY;

uint8_t m_libspdm_ec384_requester_private_key[] = LIBSPDM_EC384_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec384_requester_public_key[] = LIBSPDM_EC384_REQUESTER_PUBLIC_KEY;

uint8_t m_libspdm_ec521_requester_private_key[] = LIBSPDM_EC521_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec521_requester_public_key[] = LIBSPDM_EC521_REQUESTER_PUBLIC_KEY;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
uint8_t m_libspdm_rsa2048_res_n[] = LIBSPDM_RSA2048_RES_N;
uint8_t m_libspdm_rsa2048_res_e[] = LIBSPDM_RSA2048_RES_E;
uint8_t m_libspdm_rsa2048_res_d[] = LIBSPDM_RSA2048_RES_D;
uint8_t m_libspdm_rsa3072_res_n[] = LIBSPDM_RSA3072_RES_N;
uint8_t m_libspdm_rsa3072_res_e[] = LIBSPDM_RSA3072_RES_E;
uint8_t m_libspdm_rsa3072_res_d[] = LIBSPDM_RSA3072_RES_D;
uint8_t m_libspdm_rsa4096_res_n[] = LIBSPDM_RSA4096_RES_N;
uint8_t m_libspdm_rsa4096_res_e[] = LIBSPDM_RSA4096_RES_E;
uint8_t m_libspdm_rsa4096_res_d[] = LIBSPDM_RSA4096_RES_D;
uint8_t m_libspdm_rsa2048_req_n[] = LIBSPDM_RSA2048_REQ_N;
uint8_t m_libspdm_rsa2048_req_e[] = LIBSPDM_RSA2048_REQ_E;
uint8_t m_libspdm_rsa2048_req_d[] = LIBSPDM_RSA2048_REQ_D;
uint8_t m_libspdm_rsa3072_req_n[] = LIBSPDM_RSA3072_REQ_N;
uint8_t m_libspdm_rsa3072_req_e[] = LIBSPDM_RSA3072_REQ_E;
uint8_t m_libspdm_rsa3072_req_d[] = LIBSPDM_RSA3072_REQ_D;
uint8_t m_libspdm_rsa4096_req_n[] = LIBSPDM_RSA4096_REQ_N;
uint8_t m_libspdm_rsa4096_req_e[] = LIBSPDM_RSA4096_REQ_E;
uint8_t m_libspdm_rsa4096_req_d[] = LIBSPDM_RSA4096_REQ_D;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT)
    bool result;

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    void *rsa_context;
    uint8_t *rsa_n;
    uint8_t *rsa_e;
    uint8_t *rsa_d;
    size_t rsa_n_size;
    size_t rsa_e_size;
    size_t rsa_d_size;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    void *ec_context;
    size_t ec_nid;
    uint8_t *ec_public;
    uint8_t *ec_private;
    size_t ec_public_size;
    size_t ec_private_size;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

    switch (base_asym_algo) {
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        rsa_n = m_libspdm_rsa2048_res_n;
        rsa_e = m_libspdm_rsa2048_res_e;
        rsa_d = m_libspdm_rsa2048_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa2048_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa2048_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa2048_res_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        rsa_n = m_libspdm_rsa3072_res_n;
        rsa_e = m_libspdm_rsa3072_res_e;
        rsa_d = m_libspdm_rsa3072_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa3072_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa3072_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa3072_res_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        rsa_n = m_libspdm_rsa4096_res_n;
        rsa_e = m_libspdm_rsa4096_res_e;
        rsa_d = m_libspdm_rsa4096_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa4096_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa4096_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa4096_res_d);
        break;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
        ec_public = m_libspdm_ec256_responder_public_key;
        ec_private = m_libspdm_ec256_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec256_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec256_responder_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
        ec_public = m_libspdm_ec384_responder_public_key;
        ec_private = m_libspdm_ec384_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec384_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec384_responder_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
        ec_public = m_libspdm_ec521_responder_public_key;
        ec_private = m_libspdm_ec521_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec521_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec521_responder_private_key);
        break;
#endif /*LIBSPDM_ECDSA_SUPPORT*/
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        rsa_context = libspdm_rsa_new();
        if (rsa_context == NULL) {
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_N, rsa_n, rsa_n_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_E, rsa_e, rsa_e_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_D, rsa_d, rsa_d_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        *context = rsa_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        ec_context = libspdm_ec_new_by_nid(ec_nid);
        if (ec_context == NULL) {
            return false;
        }
        result = libspdm_ec_set_pub_key(ec_context, ec_public, ec_public_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        result = libspdm_ec_set_priv_key(ec_context, ec_private, ec_private_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        *context = ec_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /*#LIBSPDM_ECDSA_SUPPORT*/
    }

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) */
    return false;
}

bool libspdm_get_requester_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT)
    bool result;

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    void *rsa_context;
    uint8_t *rsa_n;
    uint8_t *rsa_e;
    uint8_t *rsa_d;
    size_t rsa_n_size;
    size_t rsa_e_size;
    size_t rsa_d_size;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    void *ec_context;
    size_t ec_nid;
    uint8_t *ec_public;
    uint8_t *ec_private;
    size_t ec_public_size;
    size_t ec_private_size;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

    switch (base_asym_algo) {
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        rsa_n = m_libspdm_rsa2048_req_n;
        rsa_e = m_libspdm_rsa2048_req_e;
        rsa_d = m_libspdm_rsa2048_req_d;
        rsa_n_size = sizeof(m_libspdm_rsa2048_req_n);
        rsa_e_size = sizeof(m_libspdm_rsa2048_req_e);
        rsa_d_size = sizeof(m_libspdm_rsa2048_req_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        rsa_n = m_libspdm_rsa3072_req_n;
        rsa_e = m_libspdm_rsa3072_req_e;
        rsa_d = m_libspdm_rsa3072_req_d;
        rsa_n_size = sizeof(m_libspdm_rsa3072_req_n);
        rsa_e_size = sizeof(m_libspdm_rsa3072_req_e);
        rsa_d_size = sizeof(m_libspdm_rsa3072_req_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        rsa_n = m_libspdm_rsa4096_req_n;
        rsa_e = m_libspdm_rsa4096_req_e;
        rsa_d = m_libspdm_rsa4096_req_d;
        rsa_n_size = sizeof(m_libspdm_rsa4096_req_n);
        rsa_e_size = sizeof(m_libspdm_rsa4096_req_e);
        rsa_d_size = sizeof(m_libspdm_rsa4096_req_d);
        break;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
        ec_public = m_libspdm_ec256_requester_public_key;
        ec_private = m_libspdm_ec256_requester_private_key;
        ec_public_size = sizeof(m_libspdm_ec256_requester_public_key);
        ec_private_size = sizeof(m_libspdm_ec256_requester_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
        ec_public = m_libspdm_ec384_requester_public_key;
        ec_private = m_libspdm_ec384_requester_private_key;
        ec_public_size = sizeof(m_libspdm_ec384_requester_public_key);
        ec_private_size = sizeof(m_libspdm_ec384_requester_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
        ec_public = m_libspdm_ec521_requester_public_key;
        ec_private = m_libspdm_ec521_requester_private_key;
        ec_public_size = sizeof(m_libspdm_ec521_requester_public_key);
        ec_private_size = sizeof(m_libspdm_ec521_requester_private_key);
        break;
#endif /*LIBSPDM_ECDSA_SUPPORT*/
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        rsa_context = libspdm_rsa_new();
        if (rsa_context == NULL) {
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_N, rsa_n, rsa_n_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_E, rsa_e, rsa_e_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_D, rsa_d, rsa_d_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        *context = rsa_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        ec_context = libspdm_ec_new_by_nid(ec_nid);
        if (ec_context == NULL) {
            return false;
        }
        result = libspdm_ec_set_pub_key(ec_context, ec_public, ec_public_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        result = libspdm_ec_set_priv_key(ec_context, ec_private, ec_private_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        *context = ec_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /*#LIBSPDM_ECDSA_SUPPORT*/
    }

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) */
    return false;
}
