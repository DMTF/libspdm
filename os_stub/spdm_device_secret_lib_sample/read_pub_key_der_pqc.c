/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
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

bool libspdm_read_responder_pqc_public_key(
    uint32_t pqc_asym_algo, void **data, size_t *size)
{
    bool res;
    char *file;

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_responder.key.pub.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_responder.key.pub.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}

bool libspdm_read_requester_pqc_public_key(
    uint32_t req_pqc_asym_alg, void **data, size_t *size)
{
    bool res;
    char *file;

    switch (req_pqc_asym_alg) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_requester.key.pub.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_requester.key.pub.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
