/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link:
 * https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "library/debuglib.h"
#include "library/memlib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "keys.h"
#include <base.h>

static bool get_responder_certchain_index_by_slot(uint8_t slot_id, uint32_t *chain_index)
{
    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0
    case 0:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1
    case 1:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2
    case 2:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3
    case 3:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4
    case 4:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5
    case 5:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6
    case 6:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7
    case 7:
        *chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7;
        return true;
#endif
    default:
        return false;
    }
}

static bool get_pqc_certificate_chain(uint32_t index, uint32_t base_hash_algo,
                                      uint32_t pqc_asym_algo, void **data,
                                      size_t *size, void **hash,
                                      size_t *hash_size)
{
    bool result;
    void *cert;
    size_t cert_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    size_t digest_size;

    if ((pqc_asym_algo == 0) || (data == NULL) || (size == NULL)) {
        return false;
    }

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    cert = NULL;
    cert_chain = NULL;
    result = false;

    if (!libspdm_tpm_read_nv(index, &cert, &cert_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to read nv index %d\n", index));
        goto cleanup;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);
    if (digest_size == 0) {
        goto cleanup;
    }

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        goto cleanup;
    }
    cert_chain->length = (uint32_t)cert_chain_size;

    result = libspdm_verify_cert_chain_data(SPDM_MESSAGE_VERSION_14,
                                            cert, cert_size,
                                            0, pqc_asym_algo, base_hash_algo,
                                            false,
                                            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
    if (!result) {
        goto cleanup;
    }

    result = libspdm_x509_get_cert_from_cert_chain(cert, cert_size, 0,
                                                   &root_cert, &root_cert_len);
    if (!result) {
        goto cleanup;
    }

    result = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                              (uint8_t *)(cert_chain + 1));
    if (!result) {
        goto cleanup;
    }

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     cert, cert_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    cert_chain = NULL;
    result = true;

cleanup:
    if (cert_chain != NULL) {
        free(cert_chain);
    }
    if (cert != NULL) {
        free(cert);
    }
    return result;
}

static bool get_leaf_certificate_from_chain(uint32_t chain_index, void **data, size_t *size)
{
    bool result;
    void *cert_chain_data;
    size_t cert_chain_size;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    int32_t cert_count;

    if ((data == NULL) || (size == NULL)) {
        return false;
    }

    *data = NULL;
    *size = 0;

    result = libspdm_tpm_read_nv(chain_index, &cert_chain_data, &cert_chain_size);
    if (!result) {
        return false;
    }

    cert_count = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size, -1,
                                                       NULL, NULL);
    if (cert_count <= 0) {
        free(cert_chain_data);
        return false;
    }

    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size,
                                                   cert_count - 1, &leaf_cert, &leaf_cert_len);
    if (!result) {
        free(cert_chain_data);
        return false;
    }

    *data = malloc(leaf_cert_len);
    if (*data == NULL) {
        free(cert_chain_data);
        return false;
    }

    libspdm_copy_mem(*data, leaf_cert_len, leaf_cert, leaf_cert_len);
    *size = leaf_cert_len;

    free(cert_chain_data);
    return true;
}

bool libspdm_read_pqc_responder_root_public_certificate(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data, size_t *size,
    void **hash, size_t *hash_size) {
    /* TPM API need no changes for pqc support */
    return libspdm_read_responder_root_public_certificate(
        base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_pqc_responder_root_public_certificate_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size) {
    return libspdm_read_responder_root_public_certificate_slot(
        slot_id, base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_pqc_requester_root_public_certificate(
    uint32_t base_hash_algo, uint32_t req_pqc_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size) {
    return libspdm_read_requester_root_public_certificate(
        base_hash_algo, req_pqc_asym_alg, data, size, hash, hash_size);
}

bool libspdm_read_pqc_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data, size_t *size,
    void **hash, size_t *hash_size) {
    return get_pqc_certificate_chain(
        LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
        base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data, size_t *size,
    void **hash, size_t *hash_size) {
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "not supported"));
    return false;
}

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data, size_t *size,
    void **hash, size_t *hash_size) {
    return libspdm_read_responder_public_certificate_chain_alias_cert(
        base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_pqc_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size) {
    uint32_t chain_index;

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) ||
        ((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) == 0) ||
        !get_responder_certchain_index_by_slot(slot_id, &chain_index)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d (supported mask: 0x%x)\n",
                       slot_id, LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK));
        return false;
    }

    return get_pqc_certificate_chain(chain_index, base_hash_algo, pqc_asym_algo,
                                     data, size, hash, hash_size);
}

bool libspdm_read_pqc_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t req_pqc_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size) {
    return get_pqc_certificate_chain(
        LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_0,
        base_hash_algo, req_pqc_asym_alg, data, size, hash, hash_size);
}

bool libspdm_read_responder_pqc_certificate(uint32_t pqc_asym_algo, void **data,
                                            size_t *size) {
    if (pqc_asym_algo == 0) {
        return false;
    }
    return get_leaf_certificate_from_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
                                           data, size);
}
