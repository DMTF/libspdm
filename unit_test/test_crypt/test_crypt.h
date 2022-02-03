/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
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
#undef NULL

#include "hal/base.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "hal/library/cryptlib.h"

bool read_input_file(IN char *file_name, OUT void **file_data,
                        OUT uintn *file_size);

uintn ascii_str_len(IN const char *string);

void my_print(IN char *message);

/**
 * Validate Crypto digest Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_digest(void);

/**
 * Validate Crypto message Authentication Codes Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_hmac(void);

/**
 * Validate Crypto HMAC Key Derivation Function Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_hkdf(void);

/**
 * Validate Crypto AEAD Ciphers Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_aead_cipher(void);

/**
 * Validate Crypto RSA Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_rsa(void);

/**
 * Validate Crypto RSA key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_rsa_2(void);

/**
 * Validate Crypto X509 certificate Verify
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_x509(char *Path, uintn len);

/**
 * Validate Crypto DH Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_dh(void);

/**
 * Validate Crypto EC Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_ec(void);

/**
 * Validate Crypto EC key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_ec_2(void);

/**
 * Validate Crypto Ed Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_ecd(void);

/**
 * Validate Crypto Ed key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_ecd_2(void);

/**
 * Validate Crypto MontgomeryCurve Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_ecx(void);

/**
 * Validate Crypto sm2 Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_sm2(void);

/**
 * Validate Crypto sm2 key Retrieving (from PEM & X509) & signature Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_sm2_2(void);

/**
 * Validate Crypto pseudorandom number generator interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_prng(void);

#endif
