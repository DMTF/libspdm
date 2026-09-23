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
#include <string.h>

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "hal/library/cryptlib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"

/* mbedtls does not evaluate X.509 nameConstraints (see Mbed-TLS/mbedtls#8759),
 * so its regression test is skipped for CRYPTO=mbedtls builds. */
#ifndef LIBSPDM_SKIP_NAME_CONSTRAINTS_CHECK
#define LIBSPDM_SKIP_NAME_CONSTRAINTS_CHECK 0
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
 * Validate that libspdm_x509_verify_cert_chain() rejects a chain that violates
 * the root's pathLenConstraint.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_x509_verify_cert_chain_pathlen_constraints(void);

/**
 * Validate that libspdm_x509_verify_cert_chain() rejects a chain that violates
 * the root's dNSName nameConstraints.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_x509_verify_cert_chain_name_constraints(void);

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
