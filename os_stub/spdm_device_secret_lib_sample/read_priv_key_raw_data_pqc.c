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
#include "raw_data_key.h"
#include "internal/libspdm_common_lib.h"

bool libspdm_get_responder_pqc_private_key_from_raw_data(uint32_t pqc_asym_algo, void **context)
{
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
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    res = libspdm_read_input_file(file, &data, &size);

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_44;
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_65;
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_87;
        break;
    }

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
}

bool libspdm_get_requester_pqc_private_key_from_raw_data(uint32_t req_pqc_asym_algo, void **context)
{
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
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    res = libspdm_read_input_file(file, &data, &size);

    switch (req_pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_44;
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_65;
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_87;
        break;
    }

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
}
