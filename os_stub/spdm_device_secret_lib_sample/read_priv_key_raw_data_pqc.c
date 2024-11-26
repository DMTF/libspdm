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
#include "raw_data_key.h"
#include "internal/libspdm_common_lib.h"

bool libspdm_get_responder_pqc_private_key_from_raw_data(uint32_t pqc_asym_algo, void **context)
{
#if (LIBSPDM_ML_DSA_SUPPORT) || (LIBSPDM_SLH_DSA_SUPPORT)
    bool res;
    void *data;
    size_t size;
    char *file;
    size_t nid;
    void *dsa_context;

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/end_responder.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/end_responder.key.priv.raw";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    res = libspdm_read_input_file(file, &data, &size);

    nid = libspdm_get_pqc_aysm_nid(pqc_asym_algo);

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        dsa_context = libspdm_mldsa_new(nid);
        if (dsa_context == NULL) {
            return false;
        }
        res = libspdm_mldsa_set_privkey(dsa_context, data, size);
        if (!res) {
            libspdm_mldsa_free(dsa_context);
            return false;
        }
        *context = dsa_context;
        return true;
#else
        return false;
#endif
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        dsa_context = libspdm_slhdsa_new(nid);
        if (dsa_context == NULL) {
            return false;
        }
        res = libspdm_slhdsa_set_privkey(dsa_context, data, size);
        if (!res) {
            libspdm_slhdsa_free(dsa_context);
            return false;
        }
        *context = dsa_context;
        return true;
#else
        return false;
#endif
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
#else
    return false;
#endif /* (LIBSPDM_ML_DSA_SUPPORT) || (LIBSPDM_SLH_DSA_SUPPORT) */
}

bool libspdm_get_requester_pqc_private_key_from_raw_data(uint32_t req_pqc_asym_algo, void **context)
{
#if (LIBSPDM_ML_DSA_SUPPORT) || (LIBSPDM_SLH_DSA_SUPPORT)
    bool res;
    void *data;
    size_t size;
    char *file;
    size_t nid;
    void *dsa_context;

    switch (req_pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/end_requester.key.priv.raw";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/end_requester.key.priv.raw";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    res = libspdm_read_input_file(file, &data, &size);

    nid = libspdm_get_pqc_aysm_nid(req_pqc_asym_algo);

    switch (req_pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
#if LIBSPDM_ML_DSA_SUPPORT
        dsa_context = libspdm_mldsa_new(nid);
        if (dsa_context == NULL) {
            return false;
        }
        res = libspdm_mldsa_set_privkey(dsa_context, data, size);
        if (!res) {
            libspdm_mldsa_free(dsa_context);
            return false;
        }
        *context = dsa_context;
        return true;
#else
        return false;
#endif
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
#if LIBSPDM_SLH_DSA_SUPPORT
        dsa_context = libspdm_slhdsa_new(nid);
        if (dsa_context == NULL) {
            return false;
        }
        res = libspdm_slhdsa_set_privkey(dsa_context, data, size);
        if (!res) {
            libspdm_slhdsa_free(dsa_context);
            return false;
        }
        *context = dsa_context;
        return true;
#else
        return false;
#endif
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
#else
    return false;
#endif /* (LIBSPDM_ML_DSA_SUPPORT) || (LIBSPDM_SLH_DSA_SUPPORT) */
}
