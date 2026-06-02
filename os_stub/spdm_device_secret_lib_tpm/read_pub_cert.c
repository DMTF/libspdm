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
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "keys.h"

static bool get_root_certificate_from_chain(uint32_t chain_index, uint32_t base_hash_algo,
                                            uint32_t base_asym_algo, void **data,
                                            size_t *size, void **hash, size_t *hash_size)
{
    bool result;
    void *cert_chain_data;
    size_t cert_chain_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    spdm_cert_chain_t *cert_chain;
    size_t output_cert_chain_size;
    size_t digest_size;

    if (!libspdm_tpm_device_init())
        return false;

    result = libspdm_tpm_read_nv(chain_index, &cert_chain_data, &cert_chain_size);
    if (!result)
        return false;

    /* Extract root certificate from chain */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size, 0,
                                                   &root_cert, &root_cert_len);
    if (!result) {
        free(cert_chain_data);
        return false;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    /* Create cert chain with just root cert */
    output_cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + root_cert_len;
    cert_chain = (void *)malloc(output_cert_chain_size);
    if (cert_chain == NULL){
        free(cert_chain_data);
        return false;
    }
    cert_chain->length = (uint32_t)output_cert_chain_size;

    result = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                              (uint8_t *)(cert_chain + 1));
    if (!result){
        free(cert_chain);
        free(cert_chain_data);
        return false;
    }

    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     output_cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     root_cert, root_cert_len);

    *data = cert_chain;
    *size = output_cert_chain_size;

    if (hash != NULL)
        *hash = (cert_chain + 1);

    if (hash_size != NULL)
        *hash_size = digest_size;

    free(cert_chain_data);
    return true;
}

static bool get_leaf_certificate_from_chain(uint32_t chain_index, uint32_t base_asym_algo,
                                            void **data, size_t *size)
{
    bool result;
    void *cert_chain_data;
    size_t cert_chain_size;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    int32_t cert_count;

    if (!libspdm_tpm_device_init())
        return false;

    result = libspdm_tpm_read_nv(chain_index, &cert_chain_data, &cert_chain_size);
    if (!result)
        return false;

    /* Get certificate count */
    cert_count = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size, -1,
                                                       NULL, NULL);
    if (cert_count <= 0) {
        free(cert_chain_data);
        return false;
    }

    /* Extract leaf certificate (last in chain) */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data, cert_chain_size,
                                                   cert_count - 1, &leaf_cert, &leaf_cert_len);
    if (!result) {
        free(cert_chain_data);
        return false;
    }

    /* Allocate and copy leaf cert */
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

    if (!libspdm_tpm_read_nv(index, &cert, &cert_size)){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to read nv index %d\n", index));
        return false;
    }

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
    return get_root_certificate_from_chain(LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_0,
                                           base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_0, base_hash_algo, req_base_asym_alg, data,
                                 size, hash,
                                 hash_size, false, true);
}

bool libspdm_read_responder_certificate(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    if (base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported asym algo %d\n", base_asym_algo));
        return false;
    }

    return get_leaf_certificate_from_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
                                           base_asym_algo, data, size);
}

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
                                                    uint32_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size)
{
    return get_root_certificate_from_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0,
                                           base_hash_algo, base_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    return get_certificate_chain(LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0, base_hash_algo, base_asym_algo, data,
                                 size, hash, hash_size,
                                 false, true);
}

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
                                                         uint32_t base_hash_algo,
                                                         uint32_t base_asym_algo,
                                                         void **data, size_t *size,
                                                         void **hash,
                                                         size_t *hash_size)
{
    uint32_t chain_index;

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) ||
        ((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) == 0)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d (supported mask: 0x%x)\n",
                       slot_id, LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK));
        return false;
    }

    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0
    case 0:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1
    case 1:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2
    case 2:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3
    case 3:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4
    case 4:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5
    case 5:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6
    case 6:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7
    case 7:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7;
        break;
#endif
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d\n", slot_id));
        return false;
    }

    return get_root_certificate_from_chain(chain_index, base_hash_algo, base_asym_algo,
                                           data, size, hash, hash_size);
}

bool libspdm_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    uint32_t chain_index;

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) ||
        ((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) == 0)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d (supported mask: 0x%x)\n",
                       slot_id, LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK));
        return false;
    }

    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0
    case 0:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1
    case 1:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_1;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2
    case 2:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_2;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3
    case 3:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_3;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4
    case 4:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_4;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5
    case 5:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_5;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6
    case 6:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_6;
        break;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7
    case 7:
        chain_index = LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_7;
        break;
#endif
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "unsupported slot_id %d\n", slot_id));
        return false;
    }

    return get_certificate_chain(chain_index, base_hash_algo, base_asym_algo, data, size, hash, hash_size,
                                 false, true);
}

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                   "libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca not yet implemented\n"));
    return false;
}

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                   "libspdm_read_responder_public_certificate_chain_alias_cert not yet implemented\n"));
    return false;
}
