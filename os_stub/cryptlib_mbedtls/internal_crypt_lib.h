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

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "hal/library/debuglib.h"
#include "hal/library/cryptlib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"
#include <stdio.h>

/* We should alwasy add mbedtls/config.h here
 * to ensure the config override takes effect.*/

#include <mbedtls/config.h>

int libspdm_myrand(void *rng_state, unsigned char *output, size_t len);

#endif
