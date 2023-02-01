/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

/**
 * SHA256 KAT: HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_sha256(void)
{
    return libspdm_fips_selftest_hmac_sha256();
}

/**
 * SHA384 KAT: HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_sha384(void)
{
    return libspdm_fips_selftest_hmac_sha384();
}

/**
 * SHA512 KAT: HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_sha512(void)
{
    return libspdm_fips_selftest_hmac_sha512();
}

#endif/*LIBSPDM_FIPS_MODE*/
