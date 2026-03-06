/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link:
 * https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/key_pair_info.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"

/**
 * This file contains compatibility method stubs used in unit tests that are
 * not supported by the TPM implementation.
 */

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_private_key(uint32_t base_asym_algo, void **data,
                                        size_t *size) {
    return false;
}
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) ||                                \
    (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_read_requester_private_key(uint16_t req_base_asym_alg, void **data,
                                        size_t *size) {
    return false;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (...) */

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_pqc_private_key(uint32_t pqc_asym_algo, void **data,
                                            size_t *size) {
    return false;
}
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) ||                                \
    (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_read_requester_pqc_private_key(uint32_t req_pqc_asym_alg,
                                            void **data, size_t *size) {
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP || (...) */

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool g_private_key_mode = 1;
#endif

#if LIBSPDM_ECDSA_SUPPORT
uint8_t m_libspdm_ec256_responder_private_key[] = {};
uint8_t m_libspdm_ec256_responder_public_key[] = {};
uint8_t m_libspdm_ec384_responder_private_key[] = {};
uint8_t m_libspdm_ec384_responder_public_key[] = {};
uint8_t m_libspdm_ec521_responder_private_key[] = {};
uint8_t m_libspdm_ec521_responder_public_key[] = {};
uint8_t m_libspdm_ec256_requester_private_key[] = {};
uint8_t m_libspdm_ec256_requester_public_key[] = {};
uint8_t m_libspdm_ec384_requester_private_key[] = {};
uint8_t m_libspdm_ec384_requester_public_key[] = {};
uint8_t m_libspdm_ec521_requester_private_key[] = {};
uint8_t m_libspdm_ec521_requester_public_key[] = {};
#endif /*LIBSPDM_ECDSA_SUPPORT*/

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
uint8_t m_libspdm_rsa2048_res_n[] = {};
uint8_t m_libspdm_rsa2048_res_e[] = {};
uint8_t m_libspdm_rsa2048_res_d[] = {};
uint8_t m_libspdm_rsa3072_res_n[] = {};
uint8_t m_libspdm_rsa3072_res_e[] = {};
uint8_t m_libspdm_rsa3072_res_d[] = {};
uint8_t m_libspdm_rsa4096_res_n[] = {};
uint8_t m_libspdm_rsa4096_res_e[] = {};
uint8_t m_libspdm_rsa4096_res_d[] = {};
uint8_t m_libspdm_rsa2048_req_n[] = {};
uint8_t m_libspdm_rsa2048_req_e[] = {};
uint8_t m_libspdm_rsa2048_req_d[] = {};
uint8_t m_libspdm_rsa3072_req_n[] = {};
uint8_t m_libspdm_rsa3072_req_e[] = {};
uint8_t m_libspdm_rsa3072_req_d[] = {};
uint8_t m_libspdm_rsa4096_req_n[] = {};
uint8_t m_libspdm_rsa4096_req_e[] = {};
uint8_t m_libspdm_rsa4096_req_d[] = {};
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo,
                                                     void **context) {
    return false;
}

bool libspdm_get_requester_private_key_from_raw_data(uint32_t base_asym_algo,
                                                     void **context) {
    return false;
}

bool libspdm_get_responder_pqc_private_key_from_raw_data(uint32_t pqc_asym_algo,
                                                         void **context) {
    return false;
}

bool libspdm_get_requester_pqc_private_key_from_raw_data(
    uint32_t req_pqc_asym_algo, void **context) {
    return false;
}

bool libspdm_read_responder_public_key(uint32_t base_asym_algo, void **data,
                                       size_t *size) {
    return false;
}

bool libspdm_read_requester_public_key(uint16_t req_base_asym_alg, void **data,
                                       size_t *size) {
    return false;
}

bool libspdm_read_responder_pqc_public_key(uint32_t pqc_asym_algo, void **data,
                                           size_t *size) {
    return false;
}

bool libspdm_read_requester_pqc_public_key(uint32_t req_pqc_asym_alg,
                                           void **data, size_t *size) {
    return false;
}

bool libspdm_read_responder_root_public_certificate_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t chain_id,
    void **data, size_t *size, void **hash, size_t *hash_size) {
    return false;
}

bool libspdm_read_responder_public_certificate_chain_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t chain_id,
    void **data, size_t *size, void **hash, size_t *hash_size) {
    return false;
}
