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
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include <base.h>

bool libspdm_read_pqc_responder_root_public_certificate(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data, size_t *size,
    void **hash, size_t *hash_size) {
    /* TPM API need no changes for pqc support */
    return libspdm_read_requester_root_public_certificate(
        base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_pqc_responder_root_public_certificate_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size) {
    return libspdm_read_responder_root_public_certificate_slot(
        slot_id, base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
    ;
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
    return libspdm_read_responder_public_certificate_chain(
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
    return libspdm_read_responder_public_certificate_chain_per_slot(
        slot_id, base_hash_algo, pqc_asym_algo, data, size, hash, hash_size);
}

bool libspdm_read_pqc_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t req_pqc_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size) {
    return libspdm_read_requester_public_certificate_chain(
        base_hash_algo, req_pqc_asym_alg, data, size, hash, hash_size);
}

bool libspdm_read_responder_pqc_certificate(uint32_t pqc_asym_algo, void **data,
                                            size_t *size) {
    return libspdm_read_responder_certificate(pqc_asym_algo, data, size);
}
