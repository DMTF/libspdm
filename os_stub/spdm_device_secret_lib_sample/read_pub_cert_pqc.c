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

bool libspdm_read_pqc_responder_root_public_certificate(uint32_t base_hash_algo,
                                                        uint32_t pqc_asym_algo,
                                                        void **data, size_t *size,
                                                        void **hash,
                                                        size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/ca.cert.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    res = libspdm_hash_all(base_hash_algo, file_data, file_size,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

bool libspdm_read_pqc_responder_root_public_certificate_slot(uint8_t slot_id,
                                                             uint32_t base_hash_algo,
                                                             uint32_t pqc_asym_algo,
                                                             void **data, size_t *size,
                                                             void **hash,
                                                             size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    if (slot_id == 0) {
        switch (pqc_asym_algo) {
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
            file = "mldsa44/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
            file = "mldsa65/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
            file = "mldsa87/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
            file = "slh-dsa-sha2-128s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
            file = "slh-dsa-shake-128s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
            file = "slh-dsa-sha2-128f/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
            file = "slh-dsa-shake-128f/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
            file = "slh-dsa-sha2-192s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
            file = "slh-dsa-shake-192s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
            file = "slh-dsa-sha2-192f/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
            file = "slh-dsa-shake-192f/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
            file = "slh-dsa-sha2-256s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
            file = "slh-dsa-shake-256s/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
            file = "slh-dsa-sha2-256f/ca.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
            file = "slh-dsa-shake-256f/ca.cert.der";
            break;
        default:
            LIBSPDM_ASSERT(false);
            return false;
        }
    } else {
        switch (pqc_asym_algo) {
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
            file = "mldsa44/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
            file = "mldsa65/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
            file = "mldsa87/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
            file = "slh-dsa-sha2-128s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
            file = "slh-dsa-shake-128s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
            file = "slh-dsa-sha2-128f/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
            file = "slh-dsa-shake-128f/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
            file = "slh-dsa-sha2-192s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
            file = "slh-dsa-shake-192s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
            file = "slh-dsa-sha2-192f/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
            file = "slh-dsa-shake-192f/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
            file = "slh-dsa-sha2-256s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
            file = "slh-dsa-shake-256s/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
            file = "slh-dsa-sha2-256f/ca1.cert.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
            file = "slh-dsa-shake-256f/ca1.cert.der";
            break;
        default:
            LIBSPDM_ASSERT(false);
            return false;
        }
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    res = libspdm_hash_all(base_hash_algo, file_data, file_size,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

bool libspdm_read_pqc_requester_root_public_certificate(uint32_t base_hash_algo,
                                                        uint32_t req_pqc_asym_alg,
                                                        void **data, size_t *size,
                                                        void **hash,
                                                        size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (req_pqc_asym_alg == 0) {
        return false;
    }

    switch (req_pqc_asym_alg) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/ca.cert.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;
    res = libspdm_hash_all(base_hash_algo, file_data, file_size,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

bool libspdm_read_pqc_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;
    bool is_requester_cert;
    bool is_device_cert_model;

    is_requester_cert = false;

    /*default is true*/
    is_device_cert_model = true;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/bundle_responder.certchain.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    res = libspdm_verify_cert_chain_data_with_pqc(file_data, file_size,
                                                  0, pqc_asym_algo, base_hash_algo,
                                                  is_requester_cert, is_device_cert_model);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }


    /* Get Root Certificate and calculate hash value*/

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    size_t digest_size;
    bool is_requester_cert;
    bool is_device_cert_model;

    is_requester_cert = false;

    /*default is false*/
    is_device_cert_model = false;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/bundle_responder.certchain_alias_cert_partial_set.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    /* Get leaf Certificate*/
    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, -1, &leaf_cert,
                                                &leaf_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = libspdm_x509_set_cert_certificate_check_with_pqc(leaf_cert, leaf_cert_len,
                                                           0, pqc_asym_algo, base_hash_algo,
                                                           is_requester_cert, is_device_cert_model);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /* Get Root Certificate*/
    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /*verify cert_chain*/
    res = libspdm_x509_verify_cert_chain(root_cert, root_cert_len, file_data, file_size);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /*calculate hash value*/
    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    size_t digest_size;
    bool is_requester_cert;
    bool is_device_cert_model;

    is_requester_cert = false;

    /*default is false*/
    is_device_cert_model = false;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/bundle_responder.certchain_alias.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/bundle_responder.certchain_alias.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    /* Get leaf Certificate*/
    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, -1, &leaf_cert,
                                                &leaf_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = libspdm_x509_certificate_check_with_pqc(leaf_cert, leaf_cert_len,
                                                  0, pqc_asym_algo, base_hash_algo,
                                                  is_requester_cert, is_device_cert_model);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /* Get Root Certificate*/
    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /*verify cert_chain*/
    res = libspdm_x509_verify_cert_chain(root_cert, root_cert_len, file_data, file_size);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    /*calculate hash value*/
    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

bool libspdm_read_pqc_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;
    bool is_requester_cert;
    bool is_device_cert_model;

    is_requester_cert = false;

    /*default is true*/
    is_device_cert_model = true;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (pqc_asym_algo == 0) {
        return false;
    }

    if (slot_id == 0) {
        switch (pqc_asym_algo) {
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
            file = "mldsa44/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
            file = "mldsa65/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
            file = "mldsa87/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
            file = "slh-dsa-sha2-128s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
            file = "slh-dsa-shake-128s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
            file = "slh-dsa-sha2-128f/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
            file = "slh-dsa-shake-128f/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
            file = "slh-dsa-sha2-192s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
            file = "slh-dsa-shake-192s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
            file = "slh-dsa-sha2-192f/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
            file = "slh-dsa-shake-192f/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
            file = "slh-dsa-sha2-256s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
            file = "slh-dsa-shake-256s/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
            file = "slh-dsa-sha2-256f/bundle_responder.certchain.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
            file = "slh-dsa-shake-256f/bundle_responder.certchain.der";
            break;
        default:
            LIBSPDM_ASSERT(false);
            return false;
        }
    } else {
        switch (pqc_asym_algo) {
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
            file = "mldsa44/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
            file = "mldsa65/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
            file = "mldsa87/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
            file = "slh-dsa-sha2-128s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
            file = "slh-dsa-shake-128s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
            file = "slh-dsa-sha2-128f/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
            file = "slh-dsa-shake-128f/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
            file = "slh-dsa-sha2-192s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
            file = "slh-dsa-shake-192s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
            file = "slh-dsa-sha2-192f/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
            file = "slh-dsa-shake-192f/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
            file = "slh-dsa-sha2-256s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
            file = "slh-dsa-shake-256s/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
            file = "slh-dsa-sha2-256f/bundle_responder.certchain1.der";
            break;
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
            file = "slh-dsa-shake-256f/bundle_responder.certchain1.der";
            break;
        default:
            LIBSPDM_ASSERT(false);
            return false;
        }
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    res = libspdm_verify_cert_chain_data_with_pqc(file_data, file_size,
                                                  0, pqc_asym_algo, base_hash_algo,
                                                  is_requester_cert, is_device_cert_model);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }


    /* Get Root Certificate and calculate hash value*/

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}


bool libspdm_read_pqc_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t req_pqc_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;
    bool is_requester_cert;
    bool is_device_cert_model;

    is_requester_cert = false;

    /*default is true*/
    is_device_cert_model = true;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (req_pqc_asym_alg == 0) {
        return false;
    }

    switch (req_pqc_asym_alg) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/bundle_requester.certchain.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    res = libspdm_verify_cert_chain_data_with_pqc(file_data, file_size,
                                                  0, req_pqc_asym_alg, base_hash_algo,
                                                  is_requester_cert, is_device_cert_model);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }


    /* Get Root Certificate and calculate hash value*/

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

bool libspdm_read_responder_pqc_certificate(uint32_t pqc_asym_algo,
                                            void **data, size_t *size)
{
    bool res;
    char *file;

    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        file = "mldsa44/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        file = "mldsa65/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        file = "mldsa87/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        file = "slh-dsa-sha2-128s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        file = "slh-dsa-shake-128s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        file = "slh-dsa-sha2-128f/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        file = "slh-dsa-shake-128f/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        file = "slh-dsa-sha2-192s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        file = "slh-dsa-shake-192s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        file = "slh-dsa-sha2-192f/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        file = "slh-dsa-shake-192f/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        file = "slh-dsa-sha2-256s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        file = "slh-dsa-shake-256s/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        file = "slh-dsa-sha2-256f/end_responder.cert.der";
        break;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        file = "slh-dsa-shake-256f/end_responder.cert.der";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
