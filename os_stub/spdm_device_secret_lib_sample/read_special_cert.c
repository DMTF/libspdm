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

bool libspdm_read_responder_root_public_certificate_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t chain_id,
    void **data, size_t *size, void **hash, size_t *hash_size)
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

    switch (chain_id) {
    case LIBSPDM_TEST_CERT_SMALL:
        file = "long_chains/Shorter1024B_ca.cert.der";
        break;
    case LIBSPDM_TEST_CERT_MAXINT16: /* data_size slightly smaller than 0x7FFF*/
        file = "long_chains/ShorterMAXINT16_ca.cert.der";
        break;
    case LIBSPDM_TEST_CERT_MAXUINT16: /* data_size slightly smaller than 0xFFFF*/
        file = "long_chains/ShorterMAXUINT16_ca.cert.der";
        break;
    case LIBSPDM_LIBSPDM_TEST_CERT_MAXUINT16_LARGER: /* data_size larger than 0xFFFF*/
        file = "long_chains/LongerMAXUINT16_ca.cert.der";
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
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

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

bool libspdm_read_responder_public_certificate_chain_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t chain_id,
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

    switch (chain_id) {
    case LIBSPDM_TEST_CERT_SMALL: /* data_size smaller than 1024 Bytes*/
        file = "long_chains/Shorter1024B_bundle_responder.certchain.der";
        break;
    case LIBSPDM_TEST_CERT_MAXINT16: /* data_size slightly smaller than 0x7FFF*/
        file = "long_chains/ShorterMAXINT16_bundle_responder.certchain.der";
        break;
    case LIBSPDM_TEST_CERT_MAXUINT16: /* data_size slightly smaller than 0xFFFF*/
        file = "long_chains/ShorterMAXUINT16_bundle_responder.certchain.der";
        break;
    case LIBSPDM_LIBSPDM_TEST_CERT_MAXUINT16_LARGER: /* data_size larger than 0xFFFF*/
        file = "long_chains/LongerMAXUINT16_bundle_responder.certchain.der";
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
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = libspdm_verify_cert_chain_data(file_data, file_size,
                                         base_asym_algo, base_hash_algo,
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
