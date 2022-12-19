/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CRYPTEST_H__
#define __CRYPTEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "hal/base.h"
#include "library/spdm_lib_config.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "hal/library/cryptlib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"

#if LIBSPDM_RSA_SSA_SUPPORT == 0
#undef LIBSPDM_RSA_SSA_SUPPORT_TEST
#define LIBSPDM_RSA_SSA_SUPPORT_TEST 0
#endif

#if LIBSPDM_RSA_PSS_SUPPORT == 0
#undef LIBSPDM_RSA_PSS_SUPPORT_TEST
#define LIBSPDM_RSA_PSS_SUPPORT_TEST 0
#endif

#if LIBSPDM_ECDSA_SUPPORT == 0
#undef LIBSPDM_ECDSA_SUPPORT_TEST
#define LIBSPDM_ECDSA_SUPPORT_TEST 0
#endif

#if LIBSPDM_SM2_DSA_SUPPORT == 0
#undef LIBSPDM_SM2_DSA_SUPPORT_TEST
#define LIBSPDM_SM2_DSA_SUPPORT_TEST 0
#endif

#if LIBSPDM_EDDSA_ED25519_SUPPORT == 0
#undef LIBSPDM_EDDSA_ED25519_SUPPORT_TEST
#define LIBSPDM_EDDSA_ED25519_SUPPORT_TEST 0
#endif

#if LIBSPDM_EDDSA_ED448_SUPPORT == 0
#undef LIBSPDM_EDDSA_ED448_SUPPORT_TEST
#define LIBSPDM_EDDSA_ED448_SUPPORT_TEST 0
#endif

#if LIBSPDM_FFDHE_SUPPORT == 0
#undef LIBSPDM_FFDHE_SUPPORT_TEST
#define LIBSPDM_FFDHE_SUPPORT_TEST 0
#endif

#if LIBSPDM_ECDHE_SUPPORT == 0
#undef LIBSPDM_ECDHE_SUPPORT_TEST
#define LIBSPDM_ECDHE_SUPPORT_TEST 0
#endif

#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 0
#undef LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT_TEST
#define LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT_TEST 0
#endif

#if LIBSPDM_AEAD_GCM_SUPPORT == 0
#undef LIBSPDM_AEAD_GCM_SUPPORT_TEST
#define LIBSPDM_AEAD_GCM_SUPPORT_TEST 0
#endif

#if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 0
#undef LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT_TEST
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT_TEST 0
#endif

#if LIBSPDM_AEAD_SM4_SUPPORT == 0
#undef LIBSPDM_AEAD_SM4_SUPPORT_TEST
#define LIBSPDM_AEAD_SM4_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA256_SUPPORT == 0
#undef LIBSPDM_SHA256_SUPPORT_TEST
#define LIBSPDM_SHA256_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA384_SUPPORT == 0
#undef LIBSPDM_SHA384_SUPPORT_TEST
#define LIBSPDM_SHA384_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA512_SUPPORT == 0
#undef LIBSPDM_SHA512_SUPPORT_TEST
#define LIBSPDM_SHA512_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA3_256_SUPPORT == 0
#undef LIBSPDM_SHA3_256_SUPPORT_TEST
#define LIBSPDM_SHA3_256_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA3_384_SUPPORT == 0
#undef LIBSPDM_SHA3_384_SUPPORT_TEST
#define LIBSPDM_SHA3_384_SUPPORT_TEST 0
#endif

#if LIBSPDM_SHA3_512_SUPPORT == 0
#undef LIBSPDM_SHA3_512_SUPPORT_TEST
#define LIBSPDM_SHA3_512_SUPPORT_TEST 0
#endif

#if LIBSPDM_SM3_256_SUPPORT == 0
#undef LIBSPDM_SM3_256_SUPPORT_TEST
#define LIBSPDM_SM3_256_SUPPORT_TEST 0
#endif

bool libspdm_read_input_file(const char *file_name, void **file_data, size_t *file_size);

size_t libspdm_ascii_str_len(const char *string);

void libspdm_my_print(const char *message);

/**
 * Validate Crypto digest Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_digest(void);

/**
 * Validate Crypto message Authentication Codes Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_hmac(void);

/**
 * Validate Crypto HMAC Key Derivation Function Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_hkdf(void);

/**
 * Validate Crypto AEAD Ciphers Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_aead_cipher(void);

/**
 * Validate Crypto RSA Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_rsa(void);

/**
 * Validate Crypto RSA key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_rsa_2(void);

/**
 * Validate Crypto X509 certificate Verify
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_x509(char *Path, size_t len);

/**
 * Gen and verify RSA CSR.
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen and verify RSA CSR.
 **/
bool libspdm_validate_crypt_x509_csr(void);

/**
 * Validate Crypto DH Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_dh(void);

/**
 * Validate Crypto EC Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ec(void);

/**
 * Validate Crypto EC key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ec_2(void);

/**
 * Validate Crypto Ed Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ecd(void);

/**
 * Validate Crypto Ed key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ecd_2(void);

/**
 * Validate Crypto sm2 Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_sm2(void);

/**
 * Validate Crypto sm2 key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_sm2_2(void);

/**
 * Validate Crypto pseudorandom number generator interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_prng(void);

#endif
