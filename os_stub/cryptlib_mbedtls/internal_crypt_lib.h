/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
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

/* We should always add mbedtls/build_info.h here
 * to ensure the config override takes effect.
 *
 * Do not directly include custom libspdm_mbedtls_config.h. build_info.h
 * includes custom config file and other dependency header files.
 */

#include <mbedtls/build_info.h>

int libspdm_myrand(void *rng_state, unsigned char *output, size_t len);

#endif
