/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Internal include file for cryptlib.
 **/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#include <base.h>
#include "library/memlib.h"
#include "library/malloclib.h"
#include "library/debuglib.h"
#include "library/cryptlib.h"
#include "library/spdm_crypt_lib.h"

#include <limits.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x30200000L

#ifndef EVP_PKEY_PRIVATE_KEY
#define EVP_PKEY_PRIVATE_KEY EVP_PKEY_KEYPAIR
#endif

#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

#endif

#if LIBSPDM_FIPS_MODE
/* Hash the message of a FIPS signature API, which signs and verifies a message and not a hash.
 * digest shall hold LIBSPDM_SHA512_DIGEST_SIZE bytes. */
bool libspdm_fips_hash_message(size_t hash_nid, const uint8_t *message,
                               size_t message_size, uint8_t *digest,
                               size_t *digest_size);
#endif /* LIBSPDM_FIPS_MODE */

#endif
