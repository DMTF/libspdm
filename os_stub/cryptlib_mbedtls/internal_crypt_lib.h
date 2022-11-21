/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
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
#include "spdm_crypt_ext_lib/cryptlib_ext.h"

/* We should alwasy add mbedtls/config.h here
 * to ensure the config override takes effect.*/

#include <mbedtls/config.h>

int libspdm_myrand(void *rng_state, unsigned char *output, size_t len);

#if LIBSPDM_UNIT_TEST
#define libspdm_sha256_new libspdm_sha256_new_internal
#define libspdm_sha256_init libspdm_sha256_init_internal
#define libspdm_sha256_update libspdm_sha256_update_internal
#define libspdm_sha256_final libspdm_sha256_final_internal
#define libspdm_sha256_hash_all libspdm_sha256_hash_all_internal

#define libspdm_sha384_new libspdm_sha384_new_internal
#define libspdm_sha384_init libspdm_sha384_init_internal
#define libspdm_sha384_update libspdm_sha384_update_internal
#define libspdm_sha384_final libspdm_sha384_final_internal
#define libspdm_sha384_hash_all libspdm_sha384_hash_all_internal

#define libspdm_sha512_new libspdm_sha512_new_internal
#define libspdm_sha512_init libspdm_sha512_init_internal
#define libspdm_sha512_update libspdm_sha512_update_internal
#define libspdm_sha512_final libspdm_sha512_final_internal
#define libspdm_sha512_hash_all libspdm_sha512_hash_all_internal
#endif /* LIBSPDM_UNIT_TEST */

#endif /* __INTERNAL_CRYPT_LIB_H__ */
