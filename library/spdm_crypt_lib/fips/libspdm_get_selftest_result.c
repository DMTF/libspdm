/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE
bool last_result = false;

/*get the last fips self_test result*/
bool libspdm_fips_get_selftest_result(void)
{
    return last_result;
}

/*run of all selftests and returns the results.*/
bool libspdm_fips_run_selftest(void)
{
    bool result;
    last_result = true;
    result = true;

    result = libspdm_fips_selftest_hmac_sha256();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HMAC-SHA256 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_hmac_sha384();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HMAC-SHA384 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_hmac_sha512();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HMAC-SHA512 self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_aes_gcm();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "AES_GCM self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_rsa_ssa();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "RSA_SSA self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_hkdf();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_ecdh();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_sha256();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA256 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_sha384();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA384 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_sha512();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA512 self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_sha3_256();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA3_256 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_sha3_384();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA3_384 self_test failed\n"));
        last_result = false;
    }
    result = libspdm_fips_selftest_sha3_512();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SHA3_512 self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_ffdh();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_ecdsa();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDSA self_test failed\n"));
        last_result = false;
    }

    result = libspdm_fips_selftest_eddsa();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA self_test failed\n"));
        last_result = false;
    }

    return last_result;
}

#endif/*LIBSPDM_FIPS_MODE*/
