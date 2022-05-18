/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#ifndef __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__
#define __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__

#include "library/spdm_device_secret_lib.h"

#define LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER 4
#define LIBSPDM_MEASUREMENT_BLOCK_NUMBER (LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER /*Index - 1~4*/ + \
                                          1 /*SVN - 0x10*/ + \
                                          1 /*Manifest - 0xFD*/ + 1 /*DEVICE_MODE - 0xFE*/)
#define LIBSPDM_MEASUREMENT_RAW_DATA_SIZE 72
#define LIBSPDM_MEASUREMENT_MANIFEST_SIZE 128
#define LIBSPDM_MEASUREMENT_INDEX_SVN 0x10

#define LIBSPDM_TEST_PSK_DATA_STRING "TestPskData"
#define LIBSPDM_TEST_PSK_HINT_STRING "TestPskHint"

#define LIBSPDM_TEST_CERT_MAXINT16 1
#define LIBSPDM_TEST_CERT_MAXUINT16 2
#define LIBSPDM_LIBSPDM_TEST_CERT_MAXUINT16_LARGER 3
#define LIBSPDM_TEST_CERT_SMALL 4


/* public cert*/

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
                                                    uint32_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
                                                         uint32_t base_hash_algo,
                                                         uint32_t base_asym_algo,
                                                         void **data, size_t *size,
                                                         void **hash,
                                                         size_t *hash_size);

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
                                                    uint16_t req_base_asym_alg,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
    void **data, size_t *size, void **hash,
    size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
    void **data, size_t *size, void **hash,
    size_t *hash_size);


/* External*/

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

#endif
