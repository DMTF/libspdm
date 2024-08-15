/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
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

#include "crt_support.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OBJ_get0_data(o) ((o)->data)
#define OBJ_length(o) ((o)->length)
#endif

#endif
