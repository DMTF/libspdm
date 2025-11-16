/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
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
#include "hal/library/cryptlib/cryptlib_tpm.h"
#include "keys.h"

static bool get_certificate(uint32_t index, uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
                            size_t *size, void **hash, size_t *hash_size)
{
    bool result;
    void *cert;
    size_t cert_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    size_t digest_size;

    if (base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported asym algo %d\n", base_asym_algo));
        return false;
    }

    if (!libspdm_tpm_device_init())
        return false;

    result = libspdm_tpm_read_nv(index, &cert, &cert_size);
    if (!result)
        return false;

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL){
        result = false;
        goto cleanup_cert;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    result = libspdm_hash_all(base_hash_algo, cert, cert_size,
                              (uint8_t *)(cert_chain + 1));
    if (!result){
        result = false;
        free(cert_chain);
        goto cleanup_cert;
    }

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     cert, cert_size);

    *data = cert_chain;
    *size = cert_chain_size;

    if (hash != NULL)
        *hash = (cert_chain + 1);

    if (hash_size != NULL)
        *hash_size = digest_size;

cleanup_cert:
    free(cert);

    return result;
}

static bool get_certificate_chain(uint32_t index, uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
                                  size_t *size, void **hash, size_t *hash_size,
                                  bool is_requester_cert, bool is_device_cert_model)
{
    bool result;
    void *cert;
    size_t cert_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    size_t digest_size;

    if (base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256){
        fprintf(stderr, "ERROR: unsupported asym algo %d\n", base_asym_algo);
        return false;
    }

    if (!libspdm_tpm_read_nv(index, &cert, &cert_size)){
        fprintf(stderr, "ERROR: failed to read nv index %d\n", index);
        return false;
    }
    fprintf(stdout, "NV read success %p %ld\n", cert, cert_size);

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL){
        result = false;
        goto cleanup_cert;
    }
    cert_chain->length = (uint32_t)cert_chain_size;
    result = libspdm_verify_cert_chain_data(SPDM_MESSAGE_VERSION_12,
                                            cert, cert_size,
                                            base_asym_algo, 0, base_hash_algo,
                                            is_requester_cert, is_device_cert_model);
    if (!result)
        goto cleanup_cert_chain;

    result = libspdm_x509_get_cert_from_cert_chain(cert, cert_size, 0, &root_cert,
                                                   &root_cert_len);
    if (!result)
        goto cleanup_cert_chain;

    result = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                              (uint8_t *)(cert_chain + 1));
    if (!result)
        goto cleanup_cert_chain;

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     cert, cert_size);

    *data = cert_chain;
    *size = cert_chain_size;

    if (hash != NULL)
        *hash = (cert_chain + 1);

    if (hash_size != NULL)
        *hash_size = digest_size;

    if (result)
        goto cleanup_cert;

cleanup_cert_chain:
    free(cert_chain);

cleanup_cert:
    free(cert);

    return result;
}

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
                                                    uint16_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size)
{
    return get_certificate(TPM_ROOT_CERT, base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(TPM_REQU_CERT_CHAIN, base_hash_algo, req_base_asym_alg, data, size, hash,
                                 hash_size, false, true);
}

bool libspdm_read_responder_certificate(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    bool result;
    void *cert;
    size_t cert_size;

    if (base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256){
        fprintf(stderr, "ERROR: unsupported asym algo %d\n", base_asym_algo);
        return false;
    }

    if (!libspdm_tpm_device_init())
        return false;

    result = libspdm_tpm_read_nv(TPM_RESP_CERT, &cert, &cert_size);
    if (!result)
        return false;

    return true;
}

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
                                                    uint32_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size)
{
    return get_certificate(TPM_ROOT_CERT, base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(TPM_RESP_CERT_CHAIN, base_hash_algo, base_asym_algo, data, size, hash, hash_size,
                                 false, true);
}

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
                                                         uint32_t base_hash_algo,
                                                         uint32_t base_asym_algo,
                                                         void **data, size_t *size,
                                                         void **hash,
                                                         size_t *hash_size)
{
    return get_certificate(TPM_ROOT_CERT, base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(TPM_RESP_CERT_CHAIN, base_hash_algo, base_asym_algo, data, size, hash, hash_size,
                                 false, true);
}

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    libspdm_debug_print(LIBSPDM_DEBUG_ERROR,
                        "libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca not yet implemented\n");
    return false;
}

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    libspdm_debug_print(LIBSPDM_DEBUG_ERROR,
                        "libspdm_read_responder_public_certificate_chain_alias_cert not yet implemented\n");
    return false;
}
