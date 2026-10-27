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
#include "hal/library/cryptlib_ext.h"

/* We should always add mbedtls/build_info.h here
 * to ensure the config override takes effect.
 *
 * Do not directly include custom libspdm_mbedtls_config.h. build_info.h
 * includes custom config file and other dependency header files.
 */

#include <mbedtls/build_info.h>

int libspdm_myrand(void *rng_state, unsigned char *output, size_t len);

#if LIBSPDM_FIPS_MODE
/* Hash the message of a FIPS signature API, which signs and verifies a message and not a hash.
 * digest shall hold LIBSPDM_SHA512_DIGEST_SIZE bytes. */
bool libspdm_fips_hash_message(size_t hash_nid, const uint8_t *message,
                               size_t message_size, uint8_t *digest,
                               size_t *digest_size);
#endif /* LIBSPDM_FIPS_MODE */

#endif
