/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Key context wrapper structure definition.
 * Unified context structure for EC, RSA, PQC (ML-DSA, SLH-DSA), EdDSA, DH, and ML-KEM keys.
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

#endif /* __KEY_CONTEXT_H__ */
