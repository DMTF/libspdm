/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Diffie-Hellman Wrapper Implementation over.
 *
 * RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
 **/

#ifndef __INTERNAL_PQCCRYPT_LIB_H__
#define __INTERNAL_PQCCRYPT_LIB_H__

#include <base.h>
#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "library/spdm_crypt_lib.h"
#include "hal/library/cryptlib.h"

#include "oqs/oqs.h"

typedef struct {
    OQS_KEM  *kem;
    size_t   decap_key_size;
    uint8_t  decap_key[LIBSPDM_MAX_KEM_DECAP_KEY_SIZE];
} OQS_KEM_WRAP;

typedef struct {
    OQS_SIG  *sig;
    size_t   pub_key_size;
    size_t   priv_key_size;
    uint8_t  pub_key[LIBSPDM_MAX_PQC_ASYM_PUB_KEY_SIZE];
    uint8_t  priv_key[LIBSPDM_MAX_PQC_ASYM_PRIV_KEY_SIZE];
} OQS_SIG_WRAP;

uint8_t m_mldsa44_oid[];
uint8_t m_mldsa44_oid_size;

uint8_t m_mldsa65_oid[];
uint8_t m_mldsa65_oid_size;

uint8_t m_mldsa87_oid[];
uint8_t m_mldsa87_oid_size;

#endif /* __INTERNAL_PQCCRYPT_LIB_H__ */
