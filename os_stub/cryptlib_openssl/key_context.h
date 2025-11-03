/**
 *  Copyright Notice:
 *  Copyright 2025-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Key context wrapper structure definition.
 * Unified context structure for EC, RSA, PQC (ML-DSA, SLH-DSA), EdDSA, DH, and ML-KEM keys.
 * Also includes HMAC context wrapper structure.
 **/

#ifndef __KEY_CONTEXT_H__
#define __KEY_CONTEXT_H__

#include <openssl/evp.h>

/**
 * Unified key context wrapper structure
 * Wraps EVP_PKEY to provide a clean interface and future extensibility
 * Supports EC, RSA, PQC (ML-DSA, SLH-DSA), EdDSA, DH, and ML-KEM keys
 */
typedef struct {
    EVP_PKEY *evp_pkey;  /* Common: EVP_PKEY pointer for all key types */
} libspdm_key_context;

/**
 * HMAC context wrapper structure
 * Wraps EVP_MAC_CTX for HMAC operations
 */
typedef struct {
    EVP_MAC_CTX *mac_ctx;  /* OpenSSL MAC context */
} libspdm_mac_context;

#endif /* __KEY_CONTEXT_H__ */
