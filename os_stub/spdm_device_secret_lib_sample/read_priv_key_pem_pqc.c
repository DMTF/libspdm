/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_pqc_private_key(uint32_t pqc_asym_algo,
                                            void **data, size_t *size)
{
    bool res;
    char *file;

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/end_responder.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/end_responder.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_read_requester_pqc_private_key(uint32_t req_pqc_asym_alg,
                                            void **data, size_t *size)
{
    bool res;
    char *file;

    switch (req_pqc_asym_alg) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/end_requester.key";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/end_requester.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP || (...) */
