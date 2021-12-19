/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  SPDM common library.
  It follows the SPDM Specification.
**/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#undef NULL
#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"

boolean read_responder_root_public_certificate(IN uint32_t base_hash_algo,
                           IN uint32_t base_asym_algo,
                           OUT void **data, OUT uintn *size,
                           OUT void **hash,
                           OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (base_asym_algo == 0) {
        return FALSE;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/ca.cert.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }
    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = spdm_hash_all(base_hash_algo, file_data, file_size,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}

boolean read_requester_root_public_certificate(IN uint32_t base_hash_algo,
                           IN uint16_t req_base_asym_alg,
                           OUT void **data, OUT uintn *size,
                           OUT void **hash,
                           OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (req_base_asym_alg == 0) {
        return FALSE;
    }

    switch (req_base_asym_alg) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/ca.cert.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/ca.cert.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;
    res = spdm_hash_all(base_hash_algo, file_data, file_size,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}

boolean read_responder_public_certificate_chain(
    IN uint32_t base_hash_algo, IN uint32_t base_asym_algo, OUT void **data,
    OUT uintn *size, OUT void **hash, OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uint8_t *root_cert;
    uintn root_cert_len;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (base_asym_algo == 0) {
        return FALSE;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/bundle_responder.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/bundle_responder.certchain.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }
    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = spdm_verify_cert_chain_data(file_data, file_size);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    
    /* Get Root Certificate and calculate hash value*/
    
    res = x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                        &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = spdm_hash_all(base_hash_algo, root_cert, root_cert_len,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}

boolean read_requester_public_certificate_chain(
    IN uint32_t base_hash_algo, IN uint16_t req_base_asym_alg, OUT void **data,
    OUT uintn *size, OUT void **hash, OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uint8_t *root_cert;
    uintn root_cert_len;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (req_base_asym_alg == 0) {
        return FALSE;
    }

    switch (req_base_asym_alg) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/bundle_requester.certchain.der";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/bundle_requester.certchain.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }
    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = spdm_verify_cert_chain_data(file_data, file_size);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    
    /* Get Root Certificate and calculate hash value*/
    
    res = x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                        &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = spdm_hash_all(base_hash_algo, root_cert, root_cert_len,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}

boolean read_responder_root_public_certificate_by_size(
    IN uint32_t base_hash_algo, IN uint32_t base_asym_algo, IN uint16_t chain_id,
    OUT void **data, OUT uintn *size, OUT void **hash, OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    switch (chain_id) {
    case TEST_CERT_SMALL:
        file = "long_chains/Shorter1024B_ca.cert.der";
        break;
    case TEST_CERT_MAXINT16: /* data_size slightly smaller than MAX_INT16*/
        file = "long_chains/ShorterMAXINT16_ca.cert.der";
        break;
    case TEST_CERT_MAXUINT16: /* data_size slightly smaller than MAX_UINT16*/
        file = "long_chains/ShorterMAXUINT16_ca.cert.der";
        break;
    case TEST_CERT_MAXUINT16_LARGER: /* data_size larger than MAX_UINT16*/
        file = "long_chains/LongerMAXUINT16_ca.cert.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }
    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = spdm_hash_all(base_hash_algo, file_data, file_size,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}

boolean read_responder_public_certificate_chain_by_size(
    IN uint32_t base_hash_algo, IN uint32_t base_asym_algo, IN uint16_t chain_id,
    OUT void **data, OUT uintn *size, OUT void **hash, OUT uintn *hash_size)
{
    boolean res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char8 *file;
    uint8_t *root_cert;
    uintn root_cert_len;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    switch (chain_id) {
    case TEST_CERT_SMALL: /* data_size smaller than 1024 Bytes*/
        file = "long_chains/Shorter1024B_bundle_responder.certchain.der";
        break;
    case TEST_CERT_MAXINT16: /* data_size slightly smaller than MAX_INT16*/
        file = "long_chains/ShorterMAXINT16_bundle_responder.certchain.der";
        break;
    case TEST_CERT_MAXUINT16: /* data_size slightly smaller than MAX_UINT16*/
        file = "long_chains/ShorterMAXUINT16_bundle_responder.certchain.der";
        break;
    case TEST_CERT_MAXUINT16_LARGER: /* data_size larger than MAX_UINT16*/
        file = "long_chains/LongerMAXUINT16_bundle_responder.certchain.der";
        break;
    default:
        ASSERT(FALSE);
        return FALSE;
    }
    res = read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = spdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return FALSE;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    res = spdm_verify_cert_chain_data(file_data, file_size);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    
    /* Get Root Certificate and calculate hash value*/
    
    res = x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                        &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    res = spdm_hash_all(base_hash_algo, root_cert, root_cert_len,
              (uint8_t *)(cert_chain + 1));
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }
    copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
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
    return TRUE;
}
