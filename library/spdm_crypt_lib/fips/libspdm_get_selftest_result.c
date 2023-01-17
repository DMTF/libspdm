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
    }

    last_result = last_result && result;

    result = libspdm_fips_selftest_hmac_sha384();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HMAC-SHA384 self_test failed\n"));
    }

    last_result = last_result && result;

    result = libspdm_fips_selftest_hmac_sha512();
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HMAC-SHA512 self_test failed\n"));
    }

    last_result = last_result && result;


    return last_result;
}

#endif
