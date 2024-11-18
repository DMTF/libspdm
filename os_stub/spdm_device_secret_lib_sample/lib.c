/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/
#include <base.h>
#if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
    defined(LIBSPDM_CPU_ARM)))
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "raw_data_key.h"
#include "internal/libspdm_common_lib.h"

bool g_in_trusted_environment = false;
bool g_set_cert_is_busy = false;
uint32_t g_supported_event_groups_list_len = 8;
uint8_t g_event_group_count = 1;
bool g_event_all_subscribe = false;
bool g_event_all_unsubscribe = false;

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
typedef struct {
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];
} libspdm_key_pair_info_t;

#ifndef LIBSPDM_MAX_KEY_PAIR_COUNT
#define LIBSPDM_MAX_KEY_PAIR_COUNT 16
#endif

libspdm_key_pair_info_t m_key_pair_info[LIBSPDM_MAX_KEY_PAIR_COUNT];

bool g_need_init_key_pair_info = true;
#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/

/* "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 1" means use the RAW private key only
 * "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 0" means controlled by g_private_key_mode
 **/
#define LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY 0
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

#if (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP)

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000
uint8_t m_libspdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) */

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

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_private_key(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    bool res;
    char *file;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_responder.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif

bool libspdm_read_responder_certificate(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    bool res;
    char *file;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_responder.cert.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_read_requester_private_key(uint16_t req_base_asym_alg,
                                        void **data, size_t *size)
{
    bool res;
    char *file;

    switch (req_base_asym_alg) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_requester.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_read_responder_public_key(uint32_t base_asym_algo,
                                       void **data, size_t *size)
{
    bool res;
    char *file;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_responder.key.pub.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}

bool libspdm_read_requester_public_key(uint16_t req_base_asym_alg,
                                       void **data, size_t *size)
{
    bool res;
    char *file;

    switch (req_base_asym_alg) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_requester.key.pub.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_read_cached_last_csr_request(uint8_t **last_csr_request,
                                          size_t *last_csr_request_len,
                                          uint8_t req_csr_tracking_tag,
                                          uint8_t *available_rsp_csr_tracking_tag)
{
    bool res;
    uint8_t index;
    size_t file_size;
    uint8_t *file_data;

    file_data = NULL;
    *available_rsp_csr_tracking_tag = 0;
    char file[] = "cached_last_csr_x_request";
    /*change the file name, for example: cached_last_csr_1_request*/
    file[16] = (char)(req_csr_tracking_tag + '0');
    res = libspdm_read_input_file(file, (void **)last_csr_request, last_csr_request_len);

    for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
        file[16] = (char)(index + '0');
        libspdm_read_input_file(file, (void **)(&file_data), &file_size);
        if (file_size == 0) {
            *available_rsp_csr_tracking_tag |=  (1 << index);
        } else {
            if (file_data != NULL) {
                free(file_data);
            }
        }
    }

    return res;
}

bool libspdm_cache_last_csr_request(const uint8_t *last_csr_request,
                                    size_t last_csr_request_len,
                                    uint8_t req_csr_tracking_tag)
{
    bool res;

    char file[] = "cached_last_csr_x_request";
    /*change the file name, for example: cached_last_csr_1_request*/
    file[16] = (char)(req_csr_tracking_tag + '0');
    res = libspdm_write_output_file(file, last_csr_request, last_csr_request_len);

    return res;
}

/*clean the cached last SPDM csr request*/
bool libspdm_discard_all_cached_last_request()
{
    uint8_t index;

    char file[] = "cached_last_csr_x_request";

    for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
        file[16] = (char)(index + '0');
        if (!libspdm_write_output_file(file, NULL, 0)) {
            return false;
        }
    }

    return true;
}

/*
 * return true represent that: the device complete the csr by reset successfully
 * return false represent that: the device complete the csr need reset
 **/
bool libspdm_read_cached_csr(uint8_t **csr_pointer, size_t *csr_len)
{
    bool res;
    char *file;

    file = "test_csr/cached.csr";

    res = libspdm_read_input_file(file, (void **)csr_pointer, csr_len);
    return res;
}

bool libspdm_gen_csr_without_reset(uint32_t base_hash_algo, uint32_t base_asym_algo,
                                   uint8_t *requester_info, size_t requester_info_length,
                                   uint8_t *opaque_data, uint16_t opaque_data_length,
                                   size_t *csr_len, uint8_t *csr_pointer,
                                   bool is_device_cert_model)
{
    bool result;
    size_t hash_nid;
    size_t asym_nid;
    void *context;
    size_t csr_buffer_size;

    csr_buffer_size = *csr_len;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *x509_ca_cert;
        void *prikey, *cert;
        size_t prikey_size, cert_size;

        result = libspdm_read_responder_private_key(
            base_asym_algo, &prikey, &prikey_size);
        if (!result) {
            return false;
        }

        result = libspdm_read_responder_certificate(
            base_asym_algo, &cert, &cert_size);
        if (!result) {
            return false;
        }

        result = libspdm_x509_construct_certificate(cert, cert_size,
                                                    (uint8_t **)&x509_ca_cert);
        if ((x509_ca_cert == NULL) || (!result)) {
            return false;
        }

        result = libspdm_asym_get_private_key_from_pem(
            base_asym_algo, prikey, prikey_size, NULL, &context);
        if (!result) {
            libspdm_zero_mem(prikey, prikey_size);
            free(prikey);
            return false;
        }
        hash_nid = libspdm_get_hash_nid(base_hash_algo);
        asym_nid = libspdm_get_aysm_nid(base_asym_algo);

        char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";

        result = libspdm_gen_x509_csr(hash_nid, asym_nid,
                                      requester_info, requester_info_length,
                                      !is_device_cert_model,
                                      context, subject_name,
                                      csr_len, csr_pointer,
                                      x509_ca_cert);
        libspdm_asym_free(base_asym_algo, context);
        libspdm_zero_mem(prikey, prikey_size);
        free(prikey);
        free(cert);
    } else {
#endif
    void *x509_ca_cert;
    void *cert;
    size_t cert_size;

    result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
    if (!result) {
        return false;
    }

    result = libspdm_read_responder_certificate(
        base_asym_algo, &cert, &cert_size);
    if (!result) {
        return false;
    }

    result = libspdm_x509_construct_certificate(cert, cert_size,
                                                (uint8_t **)&x509_ca_cert);
    if ((x509_ca_cert == NULL) || (!result)) {
        return false;
    }

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    asym_nid = libspdm_get_aysm_nid(base_asym_algo);

    char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";

    result = libspdm_gen_x509_csr(hash_nid, asym_nid,
                                  requester_info, requester_info_length,
                                  !is_device_cert_model,
                                  context, subject_name,
                                  csr_len, csr_pointer,
                                  x509_ca_cert);
    libspdm_asym_free(base_asym_algo, context);
    free(cert);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

    if (csr_buffer_size < *csr_len) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"csr buffer is too small to store generated csr! \n"));
        result = false;
    }
    return result;
}

bool libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    bool is_device_cert_model)
{
    bool result;
    uint8_t *cached_last_csr_request;
    size_t cached_last_request_len;
    uint8_t *cached_csr;
    size_t csr_buffer_size;
    uint8_t rsp_csr_tracking_tag;

    csr_buffer_size = *csr_len;

    /*device gen csr need reset*/
    if (*need_reset) {
        result = libspdm_read_cached_last_csr_request(&cached_last_csr_request,
                                                      &cached_last_request_len,
                                                      1, &rsp_csr_tracking_tag);

        /*get the cached last csr request and csr*/
        if ((result) &&
            (cached_last_request_len == request_size) &&
            (libspdm_consttime_is_mem_equal(cached_last_csr_request, request,
                                            request_size)) &&
            (libspdm_read_cached_csr(&cached_csr, csr_len)) &&
            (*csr_len != 0)) {

            /*get and save cached csr*/
            if (csr_buffer_size < *csr_len) {
                free(cached_csr);
                free(cached_last_csr_request);
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "csr buffer is too small to store cached csr! \n"));
                return false;
            } else {
                libspdm_copy_mem(csr_pointer, csr_buffer_size, cached_csr, *csr_len);
            }

            /*device don't need reset this time*/
            *need_reset = false;

            free(cached_csr);
            free(cached_last_csr_request);
            return true;
        } else {
            if (cached_last_csr_request != NULL) {
                free(cached_last_csr_request);
            }

            /*device need reset this time: cache the last_csr_request */
            result = libspdm_cache_last_csr_request(request, request_size, 1);
            if (!result) {
                return result;
            }

            /*device need reset this time*/
            *need_reset = true;
            return true;
        }
    } else {
        result = libspdm_gen_csr_without_reset(base_hash_algo, base_asym_algo,
                                               requester_info, requester_info_length,
                                               opaque_data, opaque_data_length,
                                               csr_len, csr_pointer, is_device_cert_model);
        return result;
    }

}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
bool libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    uint8_t req_cert_model,
    uint8_t *req_csr_tracking_tag,
    uint8_t req_key_pair_id,
    bool overwrite)
{
    bool result;
    uint8_t *cached_last_csr_request;
    size_t cached_last_request_len;
    uint8_t *cached_csr;
    size_t csr_buffer_size;
    uint8_t rsp_csr_tracking_tag;
    uint8_t available_csr_tracking_tag;
    uint8_t *request_change;
    uint8_t index;
    bool flag;
    bool is_device_cert_model;

    available_csr_tracking_tag = 0;
    csr_buffer_size = *csr_len;

    /*device gen csr need reset*/
    if (*need_reset) {
        result = libspdm_read_cached_last_csr_request(&cached_last_csr_request,
                                                      &cached_last_request_len,
                                                      *req_csr_tracking_tag,
                                                      &rsp_csr_tracking_tag);

        for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
            if (((rsp_csr_tracking_tag >> index) & 0x01) == 0x01) {
                available_csr_tracking_tag = index;
                break;
            }
        }

        if (*req_csr_tracking_tag == 0) {
            if (available_csr_tracking_tag == 0) {
                /*no available tracking tag*/
                *req_csr_tracking_tag = 0xFF;
                return false;
            } else {
                flag = false;
            }
        } else {
            /*matched csr_tracking_tag*/
            if (((rsp_csr_tracking_tag >> *req_csr_tracking_tag) & 0x01) == 0) {
                flag = true;
            } else {
                /*unexpected*/
                return false;
            }
        }

        /*get the cached last csr request and csr*/
        if ((result) &&
            (cached_last_request_len == request_size) &&
            (libspdm_consttime_is_mem_equal(cached_last_csr_request, request,
                                            request_size)) &&
            (libspdm_read_cached_csr(&cached_csr, csr_len)) &&
            (*csr_len != 0) &&
            (flag)) {

            /*get and save cached csr*/
            if (csr_buffer_size < *csr_len) {
                free(cached_csr);
                free(cached_last_csr_request);
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "csr buffer is too small to store cached csr! \n"));
                return false;
            } else {
                libspdm_copy_mem(csr_pointer, csr_buffer_size, cached_csr, *csr_len);
            }

            /*device don't need reset this time*/
            *need_reset = false;

            free(cached_csr);
            free(cached_last_csr_request);
            return true;
        } else {
            if (cached_last_csr_request != NULL) {
                free(cached_last_csr_request);
            }

            if ((*req_csr_tracking_tag == 0) && (available_csr_tracking_tag != 0)) {
                request_change = malloc(request_size);
                libspdm_copy_mem(request_change, request_size, request,request_size);

                if (overwrite) {
                    available_csr_tracking_tag = 1;
                    /*discard all previously generated CSRTrackingTags. */
                    result = libspdm_discard_all_cached_last_request();
                    if (!result) {
                        free(request_change);
                        return result;
                    }
                }

                request_change[3] |=
                    (available_csr_tracking_tag <<
                        SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET);

                /*device need reset this time: cache the last_csr_request */
                result = libspdm_cache_last_csr_request(request_change,
                                                        request_size, available_csr_tracking_tag);
                if (!result) {
                    free(request_change);
                    return result;
                }

                /*device need reset this time*/
                *need_reset = true;
                *req_csr_tracking_tag = available_csr_tracking_tag;
                free(request_change);
                return true;
            } else {
                /*the device is busy*/
                *req_csr_tracking_tag = 0xFF;
                return false;
            }
        }
    } else {
        if (req_cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT) {
            is_device_cert_model = true;
        } else {
            is_device_cert_model = false;
        }
        result = libspdm_gen_csr_without_reset(base_hash_algo, base_asym_algo,
                                               requester_info, requester_info_length,
                                               opaque_data, opaque_data_length,
                                               csr_len, csr_pointer, is_device_cert_model);
        return result;
    }
}
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/

#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#if (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)
void libspdm_generate_mel(uint32_t measurement_hash_algo)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry1;
    spdm_mel_entry_dmtf_t *mel_entry2;
    spdm_mel_entry_dmtf_t *mel_entry3;

    uint8_t rom_informational[] = "ROM";
    uint8_t bootfv_informational[] = "Boot FW";
    uint32_t version = 0x0100030A;

    /*generate MEL*/
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;

    measurement_extension_log->number_of_entries = 3;
    measurement_extension_log->mel_entries_len =
        measurement_extension_log->number_of_entries * sizeof(spdm_mel_entry_dmtf_t) +
        sizeof(rom_informational) - 1 + sizeof(bootfv_informational) - 1 + sizeof(version);
    measurement_extension_log->reserved = 0;

    /*MEL Entry 1: informational ROM */
    mel_entry1 = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                           sizeof(spdm_measurement_extension_log_dmtf_t));
    mel_entry1->mel_index = 1;
    mel_entry1->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry1->reserved, 0);
    mel_entry1->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry1->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        sizeof(rom_informational) - 1;
    libspdm_copy_mem((void *)(mel_entry1 + 1), sizeof(rom_informational) - 1,
                     rom_informational, sizeof(rom_informational) - 1);

    /*MEL Entry 2: informational Boot FW */
    mel_entry2 = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry1 + 1) +
                                           sizeof(rom_informational) - 1);
    mel_entry2->mel_index = 2;
    mel_entry2->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry2->reserved, 0);
    mel_entry2->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry2->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        sizeof(bootfv_informational) - 1;
    libspdm_copy_mem((void *)(mel_entry2 + 1), sizeof(bootfv_informational) - 1,
                     bootfv_informational, sizeof(bootfv_informational) - 1);

    /*MEL Entry 3: version 0x0100030A */
    mel_entry3 = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry2 + 1) +
                                           sizeof(bootfv_informational) - 1);
    mel_entry3->mel_index = 3;
    mel_entry3->meas_index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    libspdm_write_uint24(mel_entry3->reserved, 0);
    mel_entry3->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    mel_entry3->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = sizeof(version);
    libspdm_copy_mem((void *)(mel_entry3 + 1), sizeof(version), &version, sizeof(version));
}
#endif /*(LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * Fill image hash measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_image_hash_block (
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    size_t hash_size;
    uint8_t data[LIBSPDM_MEASUREMENT_RAW_DATA_SIZE];
    bool result;

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);

    measurement_block->measurement_block_common_header
    .index = measurements_index;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data), (uint8_t)(measurements_index));

    if (!use_bit_stream) {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1);
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)hash_size;

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)hash_size);

        result = libspdm_measurement_hash_all(
            measurement_hash_algo, data,
            sizeof(data),
            (void *)(measurement_block + 1));
        if (!result) {
            return 0;
        }

        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;

    } else {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1) |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)sizeof(data);

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)sizeof(data));

        libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
    }
}

/**
 * Fill svn measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_svn_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_secure_version_number_t svn;

    measurement_block->measurement_block_common_header
    .index = LIBSPDM_MEASUREMENT_INDEX_SVN;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    svn = 0x7;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(svn);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(svn));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(svn), (void *)&svn, sizeof(svn));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(svn);
}

/**
 * Fill HEM measurement block.
 *
 * @param  measurement_block          A pointer to store measurement block.
 * @param  measurement_hash_algo      Indicates the measurement hash algorithm.
 *                                    It must align with measurement_hash_alg
 *                                    (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_hem_block (
    spdm_measurement_block_dmtf_t *measurement_block, uint32_t measurement_hash_algo
    )
{
    size_t hash_size;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint32_t index;
    uint8_t *verify_hem;

    if (measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) {
        return 0;
    }

    libspdm_generate_mel(measurement_hash_algo);

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
    }

    /*MEL*/
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;

    /*generate measurement block*/
    measurement_block->measurement_block_common_header
    .index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HASH_EXTEND_MEASUREMENT;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)hash_size;

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)hash_size);

    verify_hem = malloc(measurement_extension_log->mel_entries_len + hash_size);
    if (verify_hem == NULL) {
        return 0;
    }

    libspdm_zero_mem(verify_hem, measurement_extension_log->mel_entries_len + hash_size);
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));
    for (index = 0; index < measurement_extension_log->number_of_entries; index++) {
        libspdm_copy_mem(
            verify_hem + hash_size,
            measurement_extension_log->mel_entries_len,
            mel_entry,
            sizeof(spdm_mel_entry_dmtf_t) +
            mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);

        if (!libspdm_measurement_hash_all(
                measurement_hash_algo,
                verify_hem,
                hash_size + sizeof(spdm_mel_entry_dmtf_t) +
                mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size,
                verify_hem
                )) {
            free(verify_hem);
            return 0;
        }
        mel_entry = (spdm_mel_entry_dmtf_t *)
                    ((uint8_t *)mel_entry + sizeof(spdm_mel_entry_dmtf_t)+
                     mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
    }

    libspdm_copy_mem((void *)(measurement_block + 1), hash_size, verify_hem, hash_size);
    free(verify_hem);
    return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
}

/**
 * Fill manifest measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_manifest_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    uint8_t data[LIBSPDM_MEASUREMENT_MANIFEST_SIZE];

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data),
                    (uint8_t)SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST);

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(data);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(data));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
}

/**
 * Fill device mode measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_device_mode_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_device_mode_t device_mode;

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    device_mode.operational_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_MANUFACTURING_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_VALIDATION_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RECOVERY_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RMA_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_DECOMMISSIONED_MODE;
    device_mode.operational_mode_state =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE;
    device_mode.device_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;
    device_mode.device_mode_state =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(device_mode);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(device_mode));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(device_mode),
                     (void *)&device_mode, sizeof(device_mode));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(device_mode);
}

libspdm_return_t libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size)
{
    spdm_measurement_block_dmtf_t *measurement_block;
    size_t hash_size;
    uint8_t index;
    size_t total_size_needed;
    bool use_bit_stream;
    size_t measurement_block_size;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    LIBSPDM_ASSERT(hash_size != 0);

    use_bit_stream = false;
    if ((measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) ||
        ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED) !=
         0)) {
        use_bit_stream = true;
    }

    if (measurements_index ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        goto successful_return;
    } else if (measurements_index ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* Calculate total_size_needed based on hash algo selected.
         * If we have an hash algo, then the first HASH_NUMBER elements will be
         * hash values, otherwise HASH_NUMBER raw bitstream values.*/
        if (!use_bit_stream) {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        } else {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_RAW_DATA_SIZE);
        }
        /* Next one - SVN is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) +
             sizeof(spdm_measurements_secure_version_number_t));
        /* Next one - HEM is always digest data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        /* Next one - manifest is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_MANIFEST_SIZE);
        /* Next one - device_mode is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + sizeof(spdm_measurements_device_mode_t));

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_size = total_size_needed;
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        measurement_block = measurements;

        /* The first HASH_NUMBER blocks may be hash values or raw bitstream*/
        for (index = 1; index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER; index++) {
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - SVN is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - HEM is always digest data.*/
        {
            measurement_block_size = libspdm_fill_measurement_hem_block (measurement_block,
                                                                         measurement_hash_algo);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - manifest is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - device_mode is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }

        goto successful_return;
    } else {
        /* One Index */
        if (measurements_index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER) {
            if (!use_bit_stream) {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    hash_size;
            } else {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    LIBSPDM_MEASUREMENT_RAW_DATA_SIZE;
            }
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                measurements_index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == LIBSPDM_MEASUREMENT_INDEX_SVN) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_secure_version_number_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == LIBSPDM_MEASUREMENT_INDEX_HEM) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) + hash_size;
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_hem_block (measurement_block,
                                                                         measurement_hash_algo);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index ==
                   SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                LIBSPDM_MEASUREMENT_MANIFEST_SIZE;
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_device_mode_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else {
            *measurements_count = 0;
            return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
        }
    }

successful_return:
    if ((content_changed != NULL) &&
        ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_12)) {
        /* return content change*/
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
        } else {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

size_t libspdm_secret_lib_meas_opaque_data_size;

bool libspdm_measurement_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_meas_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_meas_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

bool libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
{
    uint8_t measurement_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t index;
    spdm_measurement_block_dmtf_t *cached_measurement_block;
    size_t measurement_data_size;
    size_t measurement_block_size;
    uint8_t device_measurement[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t device_measurement_count;
    size_t device_measurement_size;
    libspdm_return_t status;
    bool result;

    switch (measurement_summary_hash_type) {
    case SPDM_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        break;

    case SPDM_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_REQUEST_ALL_MEASUREMENTS_HASH:
        if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
            return false;
        }

        /* get all measurement data*/
        device_measurement_size = sizeof(device_measurement);
        status = libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_version, measurement_specification,
            measurement_hash_algo,
            0xFF, /* Get all measurements*/
            0,
            NULL,
            &device_measurement_count, device_measurement,
            &device_measurement_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }

        /* double confirm that MeasurementData internal size is correct*/
        measurement_data_size = 0;
        cached_measurement_block = (void *)device_measurement;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            LIBSPDM_ASSERT(cached_measurement_block
                           ->measurement_block_common_header
                           .measurement_size ==
                           sizeof(spdm_measurement_block_dmtf_header_t) +
                           cached_measurement_block
                           ->measurement_block_dmtf_header
                           .dmtf_spec_measurement_value_size);
            measurement_data_size +=
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        LIBSPDM_ASSERT(measurement_data_size <=
                       LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);

        /* get required data and hash them*/
        cached_measurement_block = (void *)device_measurement;
        measurement_data_size = 0;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            /* filter unneeded data*/
            if ((measurement_summary_hash_type ==
                 SPDM_REQUEST_ALL_MEASUREMENTS_HASH) ||
                ((cached_measurement_block
                  ->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
                libspdm_copy_mem(&measurement_data[measurement_data_size],
                                 sizeof(measurement_data)
                                 - (&measurement_data[measurement_data_size] - measurement_data),
                                 cached_measurement_block,
                                 sizeof(cached_measurement_block->
                                        measurement_block_common_header) +
                                 cached_measurement_block->measurement_block_common_header
                                 .measurement_size);
                measurement_data_size +=
                    sizeof(cached_measurement_block->measurement_block_common_header) +
                    cached_measurement_block
                    ->measurement_block_common_header
                    .measurement_size;
            }
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        result = libspdm_hash_all(base_hash_algo, measurement_data,
                                  measurement_data_size, measurement_summary_hash);
        if (!result) {
            return false;
        }
        break;
    default:
        return false;
        break;
    }
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
size_t libspdm_secret_lib_challenge_opaque_data_size;

bool libspdm_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
bool libspdm_encap_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/*Collect the measurement extension log.*/
bool libspdm_measurement_extension_log_collection(
    void *spdm_context,
    uint8_t mel_specification,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    void **spdm_mel,
    size_t *spdm_mel_size)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (mel_specification != SPDM_MEL_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return false;
    }

    libspdm_generate_mel(measurement_hash_algo);

    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel_size = (size_t)(measurement_extension_log->mel_entries_len) +
                     sizeof(spdm_measurement_extension_log_dmtf_t);
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_requester_private_key(
            req_base_asym_alg, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_get_private_key_from_pem(req_base_asym_alg,
                                                           private_pem,
                                                           private_pem_size, NULL,
                                                           &context);
        if (!result) {
            libspdm_zero_mem(private_pem, private_pem_size);
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_req_asym_sign_hash(spdm_version, op_code, req_base_asym_alg,
                                                base_hash_algo, context,
                                                message, message_size, signature, sig_size);
        } else {
            result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                           base_hash_algo, context,
                                           message, message_size,
                                           signature, sig_size);
        }
        libspdm_req_asym_free(req_base_asym_alg, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_requester_private_key_from_raw_data(req_base_asym_alg, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_req_asym_sign_hash(spdm_version, op_code, req_base_asym_alg,
                                            base_hash_algo, context,
                                            message, message_size, signature, sig_size);
    } else {
        result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
    }
    libspdm_req_asym_free(req_base_asym_alg, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

#if LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) <= SPDM_MESSAGE_VERSION_11) {
        if (result) {
            libspdm_copy_signature_swap_endian(
                req_base_asym_alg, signature, *sig_size, signature, *sig_size);
        }
    }
#endif

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_responder_private_key(
            base_asym_algo, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_asym_get_private_key_from_pem(
            base_asym_algo, private_pem, private_pem_size, NULL, &context);
        if (!result) {
            libspdm_zero_mem(private_pem, private_pem_size);
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                            context,
                                            message, message_size, signature, sig_size);
        } else {
            result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
        }
        libspdm_asym_free(base_asym_algo, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                        context,
                                        message, message_size, signature, sig_size);
    } else {
        result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                   base_hash_algo, context,
                                   message, message_size,
                                   signature, sig_size);
    }
    libspdm_asym_free(base_asym_algo, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

#if LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) <= SPDM_MESSAGE_VERSION_11) {
        if (result) {
            libspdm_copy_signature_swap_endian(
                base_asym_algo, signature, *sig_size, signature, *sig_size);
        }
    }
#endif

    return result;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

uint8_t m_libspdm_my_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_libspdm_my_salt0[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_libspdm_bin_str0[0x11] = {
    0x00, 0x00, /* length - to be filled*/
    /* SPDM_VERSION_1_1_BIN_CONCAT_LABEL */
    0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20,
    /* SPDM_BIN_STR_0_LABEL */
    0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64,
};

uint8_t m_cxl_tsp_2nd_session_psk[CXL_TSP_2ND_SESSION_COUNT][CXL_TSP_2ND_SESSION_KEY_SIZE] = {
    LIBSPDM_CXL_TSP_2ND_SESSION_0_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_1_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_2_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_3_PSK_DATA_STRING,
};

uint8_t m_cxl_tsp_current_psk_session_index = 0xFF;

bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
        libspdm_set_mem(m_libspdm_my_salt0, sizeof(m_libspdm_my_salt0), 0xff);
    }

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[0];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[0]);
        m_cxl_tsp_current_psk_session_index = 0;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[1];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[1]);
        m_cxl_tsp_current_psk_session_index = 1;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[2];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[2]);
        m_cxl_tsp_current_psk_session_index = 2;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[3];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[3]);
        m_cxl_tsp_current_psk_session_index = 3;
    } else {
        return false;
    }
    printf("[PSK]: ");
    libspdm_dump_hex_str(psk, psk_size);
    printf("\n");

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(handshake_secret, hash_size);

    return result;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t salt1[LIBSPDM_MAX_HASH_SIZE];
    uint8_t master_secret[LIBSPDM_MAX_HASH_SIZE];

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[0];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[0]);
        m_cxl_tsp_current_psk_session_index = 0;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[1];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[1]);
        m_cxl_tsp_current_psk_session_index = 1;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[2];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[2]);
        m_cxl_tsp_current_psk_session_index = 2;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[3];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[3]);
        m_cxl_tsp_current_psk_session_index = 3;
    } else {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    *(uint16_t *)m_libspdm_bin_str0 = (uint16_t)hash_size;
    /* patch the version*/
    m_libspdm_bin_str0[6] = (char)('0' + ((spdm_version >> 12) & 0xF));
    m_libspdm_bin_str0[8] = (char)('0' + ((spdm_version >> 8) & 0xF));
    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 m_libspdm_bin_str0, sizeof(m_libspdm_bin_str0), salt1,
                                 hash_size);
    libspdm_zero_mem(handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_extract(base_hash_algo, m_libspdm_my_zero_filled_buffer,
                                  hash_size, salt1, hash_size, master_secret, hash_size);
    libspdm_zero_mem(salt1, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, master_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(master_secret, hash_size);

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context
#endif
    )
{
    return g_in_trusted_environment;
}

bool libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t base_asym_algo
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *need_reset, bool *is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
    )
{
    if (g_set_cert_is_busy) {
        *is_busy = true;

        return false;
    } else {
    #if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
        defined(LIBSPDM_CPU_ARM)))
        FILE *fp_out;
    #else
        int64_t fp_out;
    #endif

        char file_name[] = "slot_id_0_cert_chain.der";
        /*change the file name, for example: slot_id_1_cert_chain.der*/
        file_name[8] = (char)(slot_id+'0');

        /*check the input parameter*/
        if ((cert_chain == NULL) ^ (cert_chain_size == 0) ) {
            return false;
        }

    #if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
        defined(LIBSPDM_CPU_ARM)))
        if ((fp_out = fopen(file_name, "w+b")) == NULL) {
            printf("Unable to open file %s\n", file_name);
            return false;
        }

        if (cert_chain != NULL) {
            if ((fwrite(cert_chain, 1, cert_chain_size, fp_out)) != cert_chain_size) {
                printf("Write output file error %s\n", file_name);
                fclose(fp_out);
                return false;
            }
        }

        fclose(fp_out);
    #else
        if (cert_chain != NULL) {
            if ((fp_out = open(file_name, O_WRONLY | O_CREAT, S_IRWXU)) == -1) {
                printf("Unable to open file %s\n", file_name);
                return false;
            }

            if ((write(fp_out, cert_chain, cert_chain_size)) != cert_chain_size) {
                printf("Write output file error %s\n", file_name);
                close(fp_out);
                return false;
            }
        } else {
            if ((fp_out = open(file_name, O_WRONLY | O_TRUNC)) == -1) {
                printf("Unable to open file %s\n", file_name);
                return false;
            }

            close(fp_out);
        }

        close(fp_out);
    #endif

        return true;
    }
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count)
{
    *supported_event_groups_list_len = g_supported_event_groups_list_len;

    for (uint32_t index = 0; index < *supported_event_groups_list_len; index++)
    {
        ((char *)supported_event_groups_list)[index] = (char)index;
    }

    *event_group_count = g_event_group_count;

    return true;
}

bool libspdm_event_subscribe(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    uint8_t subscribe_type,
    uint8_t subscribe_event_group_count,
    uint32_t subscribe_list_len,
    const void *subscribe_list)
{
    switch (subscribe_type) {
    case LIBSPDM_EVENT_SUBSCRIBE_ALL:
        if ((subscribe_list_len != 0) || (subscribe_list != NULL)) {
            return false;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "Subscribing to all events for session ID 0x%x.\n", session_id));
        g_event_all_subscribe = true;
        g_event_all_unsubscribe = false;
        return true;
    case LIBSPDM_EVENT_SUBSCRIBE_NONE:
        if ((subscribe_list_len != 0) || (subscribe_list != NULL)) {
            return false;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "Unsubscribing from all events for session ID 0x%x.\n", session_id));
        g_event_all_subscribe = false;
        g_event_all_unsubscribe = true;
        return true;
    case LIBSPDM_EVENT_SUBSCRIBE_LIST:
        if ((subscribe_list_len == 0) || (subscribe_list == NULL)) {
            return false;
        }
        break;
    default:
        return false;
    }

    g_event_all_subscribe = false;
    g_event_all_unsubscribe = false;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "subscribe_event_group_count == %d, subscribe_list_len = %d\n",
                   subscribe_event_group_count, subscribe_list_len));

    for (uint32_t index = 0; index < subscribe_list_len; index++) {
        printf("%02x ", ((const char *)subscribe_list)[index]);
    }
    printf("\n");

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

void libspdm_init_key_pair_info(uint8_t total_key_pairs) {
    uint8_t public_key_info_rsa[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                     0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    uint8_t public_key_info_ecp256[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x03, 0x01, 0x07};
    uint8_t public_key_info_ecp384[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    uint8_t public_key_info_ecp521[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
    uint8_t public_key_info_sm2[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                     0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
                                     0x01, 0x82, 0x2D};
    uint8_t public_key_info_ed25519[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};
    uint8_t public_key_info_ed448[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71};
    uint8_t index;
    /*provisioned key pair info*/

    /*key_pair_id 1*/
    m_key_pair_info[0].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[0].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[0].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[0].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[0].assoc_cert_slot_mask = 0x01;
    m_key_pair_info[0].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    m_key_pair_info[0].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[0].public_key_info, m_key_pair_info[0].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[0].public_key_info_len);

    /*key_pair_id 2*/
    m_key_pair_info[1].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[1].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[1].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[1].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[1].assoc_cert_slot_mask = 0x02;
    m_key_pair_info[1].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    m_key_pair_info[1].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[1].public_key_info, m_key_pair_info[1].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[1].public_key_info_len);

    /*key_pair_id 3*/
    m_key_pair_info[2].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[2].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[2].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[2].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[2].assoc_cert_slot_mask = 0x04;
    m_key_pair_info[2].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    m_key_pair_info[2].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[2].public_key_info, m_key_pair_info[2].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[2].public_key_info_len);

    /*key_pair_id 4*/
    m_key_pair_info[3].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[3].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[3].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[3].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[3].assoc_cert_slot_mask = 0x08;
    m_key_pair_info[3].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    m_key_pair_info[3].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp256);
    libspdm_copy_mem(m_key_pair_info[3].public_key_info, m_key_pair_info[3].public_key_info_len,
                     public_key_info_ecp256, m_key_pair_info[3].public_key_info_len);

    /*key_pair_id 5*/
    m_key_pair_info[4].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[4].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[4].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[4].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[4].assoc_cert_slot_mask = 0x10;
    m_key_pair_info[4].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    m_key_pair_info[4].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp384);
    libspdm_copy_mem(m_key_pair_info[4].public_key_info, m_key_pair_info[4].public_key_info_len,
                     public_key_info_ecp384, m_key_pair_info[4].public_key_info_len);

    /*key_pair_id 6*/
    m_key_pair_info[5].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[5].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[5].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[5].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[5].assoc_cert_slot_mask = 0x20;
    m_key_pair_info[5].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    m_key_pair_info[5].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp521);
    libspdm_copy_mem(m_key_pair_info[5].public_key_info, m_key_pair_info[5].public_key_info_len,
                     public_key_info_ecp521, m_key_pair_info[5].public_key_info_len);

    /*key_pair_id 7*/
    m_key_pair_info[6].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[6].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[6].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[6].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[6].assoc_cert_slot_mask = 0x40;
    m_key_pair_info[6].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2;
    m_key_pair_info[6].public_key_info_len = (uint16_t)sizeof(public_key_info_sm2);
    libspdm_copy_mem(m_key_pair_info[6].public_key_info, m_key_pair_info[6].public_key_info_len,
                     public_key_info_sm2, m_key_pair_info[6].public_key_info_len);

    /*key_pair_id 8*/
    m_key_pair_info[7].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[7].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[7].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[7].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[7].assoc_cert_slot_mask = 0x80;
    m_key_pair_info[7].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519;
    m_key_pair_info[7].public_key_info_len = (uint16_t)sizeof(public_key_info_ed25519);
    libspdm_copy_mem(m_key_pair_info[7].public_key_info, m_key_pair_info[7].public_key_info_len,
                     public_key_info_ed25519, m_key_pair_info[7].public_key_info_len);

    /*key_pair_id 9*/
    m_key_pair_info[8].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[8].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[8].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[8].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[8].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[8].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
    m_key_pair_info[8].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
    libspdm_copy_mem(m_key_pair_info[8].public_key_info, m_key_pair_info[8].public_key_info_len,
                     public_key_info_ed448, m_key_pair_info[8].public_key_info_len);

    /*provisioned more key pair info*/
    for (index = 10; index <= total_key_pairs; index++) {
        m_key_pair_info[index - 1].capabilities = SPDM_KEY_PAIR_CAP_MASK;
        m_key_pair_info[index - 1].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        m_key_pair_info[index - 1].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        m_key_pair_info[index - 1].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
        m_key_pair_info[index - 1].assoc_cert_slot_mask = 0x00;
        m_key_pair_info[index - 1].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
        m_key_pair_info[index - 1].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
        libspdm_copy_mem(m_key_pair_info[index - 1].public_key_info,
                         m_key_pair_info[index - 1].public_key_info_len,
                         public_key_info_ed448, m_key_pair_info[index - 1].public_key_info_len);
    }
}

/**
 * read the key pair info of the key_pair_id.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  key_pair_id                Indicate which key pair ID's information to retrieve.
 *
 * @param  capabilities               Indicate the capabilities of the requested key pairs.
 * @param  key_usage_capabilities     Indicate the key usages the responder allows.
 * @param  current_key_usage          Indicate the currently configured key usage for the requested key pairs ID.
 * @param  asym_algo_capabilities     Indicate the asymmetric algorithms the Responder supports for this key pair ID.
 * @param  current_asym_algo          Indicate the currently configured asymmetric algorithm for this key pair ID.
 * @param  assoc_cert_slot_mask       This field is a bit mask representing the currently associated certificate slots.
 * @param  public_key_info_len        On input, indicate the size in bytes of the destination buffer to store.
 *                                    On output, indicate the size in bytes of the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 * @param  public_key_info            A pointer to a destination buffer to store the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 *
 * @retval true  get key pair info successfully.
 * @retval false get key pair info failed.
 **/
bool libspdm_read_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint16_t *capabilities,
    uint16_t *key_usage_capabilities,
    uint16_t *current_key_usage,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint8_t *assoc_cert_slot_mask,
    uint16_t *public_key_info_len,
    uint8_t *public_key_info)
{
    uint8_t total_key_pairs;
    libspdm_data_parameter_t parameter;
    size_t data_return_size;
    libspdm_return_t status;

    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_return_size = sizeof(uint8_t);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS,
                              &parameter, &total_key_pairs, &data_return_size);
    if (status != LIBSPDM_STATUS_SUCCESS) {
        return false;
    }

    LIBSPDM_ASSERT(total_key_pairs <= LIBSPDM_MAX_KEY_PAIR_COUNT);

    if (g_need_init_key_pair_info) {
        libspdm_init_key_pair_info(total_key_pairs);
        g_need_init_key_pair_info = false;
    }

    /*check*/
    if (key_pair_id > total_key_pairs) {
        return false;
    }

    if (public_key_info_len != NULL) {
        if (*public_key_info_len < m_key_pair_info[key_pair_id - 1].public_key_info_len) {
            return false;
        }
    }

    /*output*/
    *capabilities = m_key_pair_info[key_pair_id - 1].capabilities;
    *key_usage_capabilities = m_key_pair_info[key_pair_id - 1].key_usage_capabilities;
    *current_key_usage = m_key_pair_info[key_pair_id - 1].current_key_usage;
    *asym_algo_capabilities = m_key_pair_info[key_pair_id - 1].asym_algo_capabilities;
    *current_asym_algo = m_key_pair_info[key_pair_id - 1].current_asym_algo;
    *assoc_cert_slot_mask = m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask;

    if (public_key_info_len != NULL) {
        *public_key_info_len = m_key_pair_info[key_pair_id - 1].public_key_info_len;
    }
    if (public_key_info != NULL) {
        libspdm_copy_mem(public_key_info, *public_key_info_len,
                         m_key_pair_info[key_pair_id - 1].public_key_info, *public_key_info_len);

    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

typedef struct
{
    uint8_t key_pair_id;
    uint8_t operation;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;
} libspdm_cached_key_pair_info_data_t;


bool libspdm_read_cached_last_set_key_pair_info_request(uint8_t **last_set_key_pair_info_request,
                                                        size_t *last_set_key_pair_info_request_len)
{
    bool res;
    char file[] = "cached_last_set_key_pair_info_request";

    res = libspdm_read_input_file(file, (void **)last_set_key_pair_info_request,
                                  last_set_key_pair_info_request_len);

    return res;
}

bool libspdm_cache_last_set_key_pair_info_request(const uint8_t *last_set_key_pair_info_request,
                                                  size_t last_set_key_pair_info_request_len)
{
    bool res;
    char file[] = "cached_last_set_key_pair_info_request";

    res = libspdm_write_output_file(file, last_set_key_pair_info_request,
                                    last_set_key_pair_info_request_len);

    return res;
}

bool libspdm_write_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset)
{
    bool result;
    libspdm_cached_key_pair_info_data_t *cached_key_pair_info;
    libspdm_cached_key_pair_info_data_t current_key_pair_info;
    size_t cached_key_pair_info_len;


    cached_key_pair_info_len = 0;
    if (*need_reset) {
        result = libspdm_read_cached_last_set_key_pair_info_request(
            (uint8_t **)&cached_key_pair_info,
            &cached_key_pair_info_len);

        if ((result) &&
            (cached_key_pair_info_len == sizeof(libspdm_cached_key_pair_info_data_t)) &&
            (cached_key_pair_info->operation == operation) &&
            (cached_key_pair_info->key_pair_id == key_pair_id) &&
            (cached_key_pair_info->desired_key_usage == desired_key_usage) &&
            (cached_key_pair_info->desired_asym_algo == desired_asym_algo) &&
            (cached_key_pair_info->desired_assoc_cert_slot_mask == desired_assoc_cert_slot_mask)) {
            if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = 0;
                m_key_pair_info[key_pair_id - 1].current_asym_algo = 0;
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask =
                    desired_assoc_cert_slot_mask;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
                if (desired_key_usage != 0) {
                    m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                }
                if (desired_asym_algo != 0) {
                    m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
                }
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask =
                    desired_assoc_cert_slot_mask;
            } else {
                return false;
            }

            /*device don't need reset this time*/
            *need_reset = false;
            free(cached_key_pair_info);
            return true;
        } else {
            if (cached_key_pair_info != NULL) {
                free(cached_key_pair_info);
            }

            current_key_pair_info.operation = operation;
            current_key_pair_info.key_pair_id = key_pair_id;
            current_key_pair_info.desired_key_usage = desired_key_usage;
            current_key_pair_info.desired_asym_algo = desired_asym_algo;
            current_key_pair_info.desired_assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
            /*device need reset this time: cache the last_set_key_pair_info_request */
            result = libspdm_cache_last_set_key_pair_info_request(
                (const uint8_t *)&current_key_pair_info,
                sizeof(libspdm_cached_key_pair_info_data_t));
            if (!result) {
                return result;
            }

            /*device need reset this time*/
            *need_reset = true;
            return true;
        }
    } else {
        if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
            m_key_pair_info[key_pair_id - 1].current_key_usage = 0;
            m_key_pair_info[key_pair_id - 1].current_asym_algo = 0;
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
            m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
            if (desired_key_usage != 0) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            }
            if (desired_asym_algo != 0) {
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            }
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else {
            return false;
        }

        return true;
    }
}
#endif /* #if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
