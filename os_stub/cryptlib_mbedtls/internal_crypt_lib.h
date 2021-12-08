/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Internal include file for cryptlib.
**/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#include <base.h>
#include "library/memlib.h"
#include "library/malloclib.h"
#include "library/debuglib.h"
#include "library/cryptlib.h"
#include <stdio.h>

//
// We should alwasy add mbedtls/config.h here
// to ensure the config override takes effect.
//
#include <mbedtls/config.h>

int myrand(void *rng_state, unsigned char *output, size_t len);

#endif
